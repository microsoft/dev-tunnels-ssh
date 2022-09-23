//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, skip, params, pending, slow, timeout } from '@testdeck/mocha';
import {
	Stream,
	WebSocketStream,
	SshClientSession,
	SshAlgorithms,
	SshDisconnectReason,
	PromiseCompletionSource,
} from '@microsoft/dev-tunnels-ssh';
import { importKey } from '@microsoft/dev-tunnels-ssh-keys';
import { createConfig } from './config';
import { PortForwardingService } from '@microsoft/dev-tunnels-ssh-tcp';
import { withTimeout } from './promiseUtils';

@suite
export class BrowserTests {
	@test
	@test(slow(8000), timeout(20000))
	@skip(typeof window === 'undefined')
	@params({
		kexAlg: 'diffie-hellman-group16-sha512',
		pkAlg: 'rsa-sha2-512',
		hmacAlg: 'hmac-sha2-512-etm@openssh.com',
	})
	@params({
		kexAlg: 'diffie-hellman-group14-sha256',
		pkAlg: 'ecdsa-sha2-nistp384',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'ecdh-sha2-nistp384',
		pkAlg: 'ecdsa-sha2-nistp384',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'ecdh-sha2-nistp521',
		pkAlg: 'ecdsa-sha2-nistp521',
		hmacAlg: 'hmac-sha2-512-etm@openssh.com',
	})
	@params.naming((p) => `interopWithNodeWebsocketServer(${p.kexAlg},${p.pkAlg},${p.hmacAlg})`)
	public async interopWithNodeWebsocketServer({
		kexAlg,
		pkAlg,
		hmacAlg,
	}: {
		kexAlg: string;
		pkAlg: string;
		hmacAlg: string;
	}) {
		const serverUri = 'ws://localhost:9880';
		const socket = new WebSocket(serverUri, 'ssh');
		socket.binaryType = 'arraybuffer';
		const stream = await new Promise<Stream>((resolve, reject) => {
			socket.onopen = () => {
				resolve(new WebSocketStream(socket));
			};
			socket.onerror = (e) => {
				reject(
					new Error(
						`Failed to connect to server at ${serverUri}\n` +
							'Ensure local server is running: npm run test-server',
					),
				);
			};
		});

		const config = createConfig(kexAlg, pkAlg, hmacAlg);
		config.encryptionAlgorithms.splice(0, 0, SshAlgorithms.encryption.aes256Gcm);
		config.addService(PortForwardingService);

		const testKeys = await import('./testKeys');
		const keyMap: { [pkAlg: string]: keyof typeof testKeys } = {
			'rsa-sha2-512': 'private-rsa2048-pkcs8',
			'ecdsa-sha2-nistp384': 'private-ecdsa384-pkcs8',
			'ecdsa-sha2-nistp521': 'private-ecdsa521-pkcs8',
		};
		const privateKey = await importKey(testKeys[keyMap[pkAlg]]);

		const session = new SshClientSession(config);
		await session.connect(stream);
		session.onAuthenticating((e) => {
			e.authenticationPromise = (async () => {
				const serverKeyBytes = (await e.publicKey!.getPublicKeyBytes())!;
				const hostKeyBytes = (await privateKey.getPublicKeyBytes())!;
				if (serverKeyBytes.equals(hostKeyBytes)) {
					return {};
				} else {
					return null;
				}
			})();
		});
		const serverAuthenticated = await session.authenticateServer();
		assert(serverAuthenticated);
		const clientAuthenticated = await session.authenticateClient({
			username: 'test',
			publicKeys: [privateKey],
		});
		assert(clientAuthenticated);

		const channel = await session.openChannel();
		channel.close();

		const pfs = session.activateService(PortForwardingService);

		// Use streamed port-forwarding in both directions to send messages on a round trip!
		const remoteForwarder = await pfs.streamFromRemotePort('::', 9881);
		assert(remoteForwarder);
		try {
			const connectCompletion = new PromiseCompletionSource<void>();
			const dataCompletion1 = new PromiseCompletionSource<Buffer>();
			const dataCompletion2 = new PromiseCompletionSource<Buffer>();
			remoteForwarder!.onStreamOpened((s) => {
				s.write('one', 'utf8');
				connectCompletion.resolve();

				s.on('data', (data) => {
					dataCompletion2.resolve(data);
				});
			});

			const forwardedStream = await pfs.streamToRemotePort('::', 9881);
			assert(forwardedStream);

			await withTimeout(connectCompletion.promise, 5000);

			forwardedStream.write('two', 'utf8');
			forwardedStream.on('data', (data) => {
				dataCompletion1.resolve(data);
			});

			const readResult1 = await withTimeout(dataCompletion1.promise, 5000);
			assert.equal(readResult1.toString('utf8'), 'one');
			const readResult2 = await withTimeout(dataCompletion2.promise, 5000);
			assert.equal(readResult2.toString('utf8'), 'two');

			forwardedStream.destroy();
		} finally {
			remoteForwarder!.dispose();
		}

		session.close(SshDisconnectReason.byApplication);
	}
}
