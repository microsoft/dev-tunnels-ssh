//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, params, slow, timeout, pending } from '@testdeck/mocha';
import { DuplexStream } from './duplexStream';

import {
	KeyPair,
	PromiseCompletionSource,
	SecureStream,
	SshAlgorithms,
	SshAuthenticatingEventArgs,
	SshClientCredentials,
	SshConnectionError,
	SshDisconnectReason,
	SshServerCredentials,
	SshServerSession,
	SshSessionClosedEventArgs,
	Stream,
} from '@microsoft/dev-tunnels-ssh';
import { MockNetworkStream } from './mockNetworkStream';

@suite
@slow(3000)
@timeout(20000)
export class SecureStreamTests {
	private static clientKey: KeyPair;
	private static serverKey: KeyPair;
	private static clientCredentials: SshClientCredentials;
	private static serverCredentials: SshServerCredentials;

	@slow(10000)
	@timeout(20000)
	public static async before() {
		SecureStreamTests.clientKey = await SshAlgorithms.publicKey.rsaWithSha512!.generateKeyPair();
		SecureStreamTests.serverKey = await SshAlgorithms.publicKey.rsaWithSha512!.generateKeyPair();

		SecureStreamTests.clientCredentials = {
			username: 'test',
			publicKeys: [SecureStreamTests.clientKey],
		};
		SecureStreamTests.serverCredentials = { publicKeys: [SecureStreamTests.serverKey] };
	}

	@test
	@params({ authenticateSuccess: true })
	@params({ authenticateSuccess: false })
	@params.naming((p) => `authenticateServer(authenticateSuccess:${p.authenticateSuccess})`)
	public async authenticateServer({ authenticateSuccess }: { authenticateSuccess: boolean }) {
		const [serverStream, clientStream] = await DuplexStream.createStreams();

		const server = new SecureStream(serverStream, SecureStreamTests.serverCredentials);
		server.onAuthenticating((e) => (e.authenticationPromise = Promise.resolve({})));

		let serverAuthenticatingEvent: SshAuthenticatingEventArgs = null!;
		const client = new SecureStream(clientStream, SecureStreamTests.clientCredentials);
		client.onAuthenticating((e) => {
			serverAuthenticatingEvent = e;
			e.authenticationPromise = Promise.resolve(authenticateSuccess ? {} : null);
		});

		const serverConnectPromise = server.connect();
		const clientConnectPromise = client.connect();

		try {
			await Promise.all([serverConnectPromise, clientConnectPromise]);
		} catch {
			assert(!authenticateSuccess);
		}

		if (!authenticateSuccess) {
			let serverError: Error | null = null;
			try {
				await serverConnectPromise;
			} catch (e) {
				serverError = e instanceof Error ? e : null;
			}
			assert(serverError instanceof SshConnectionError);
			assert.equal(
				(<SshConnectionError>serverError).reason,
				SshDisconnectReason.hostKeyNotVerifiable,
			);

			let clientError: Error | null = null;
			try {
				await clientConnectPromise;
			} catch (e) {
				clientError = e instanceof Error ? e : null;
			}
			assert(clientError instanceof SshConnectionError);
			assert.equal(
				(<SshConnectionError>clientError).reason,
				SshDisconnectReason.hostKeyNotVerifiable,
			);
		}

		assert(serverAuthenticatingEvent);
		assert.strictEqual(serverAuthenticatingEvent!.username, null);
		assert(serverAuthenticatingEvent!.publicKey);
		assert(
			(await serverAuthenticatingEvent!.publicKey!.getPublicKeyBytes())!.equals(
				(await SecureStreamTests.serverKey.getPublicKeyBytes())!,
			),
		);
	}

	@test
	@params({ authenticateSuccess: true })
	@params({ authenticateSuccess: false })
	@params.naming((p) => `authenticateClient(authenticateSuccess:${p.authenticateSuccess})`)
	public async authenticateClient({ authenticateSuccess }: { authenticateSuccess: boolean }) {
		const [serverStream, clientStream] = await DuplexStream.createStreams();

		let clientAuthenticatingEvent: SshAuthenticatingEventArgs = null!;
		const server = new SecureStream(serverStream, SecureStreamTests.serverCredentials);
		server.onAuthenticating((e) => {
			clientAuthenticatingEvent = e;
			e.authenticationPromise = Promise.resolve(authenticateSuccess ? {} : null);
		});

		const client = new SecureStream(clientStream, SecureStreamTests.clientCredentials);
		client.onAuthenticating((e) => (e.authenticationPromise = Promise.resolve({})));

		const serverConnectPromise = server.connect();
		const clientConnectPromise = client.connect();

		try {
			await Promise.all([serverConnectPromise, clientConnectPromise]);
		} catch {
			assert(!authenticateSuccess);
		}

		if (!authenticateSuccess) {
			let serverError: Error | null = null;
			try {
				await serverConnectPromise;
			} catch (e) {
				serverError = e instanceof Error ? e : null;
			}
			assert(serverError instanceof SshConnectionError);
			assert.equal(
				(<SshConnectionError>serverError).reason,
				SshDisconnectReason.noMoreAuthMethodsAvailable,
			);

			let clientError: Error | null = null;
			try {
				await clientConnectPromise;
			} catch (e) {
				clientError = e instanceof Error ? e : null;
			}
			assert(clientError instanceof SshConnectionError);
			assert.equal(
				(<SshConnectionError>clientError).reason,
				SshDisconnectReason.noMoreAuthMethodsAvailable,
			);
		}

		assert(clientAuthenticatingEvent);
		assert.equal(
			clientAuthenticatingEvent!.username,
			SecureStreamTests.clientCredentials.username,
		);
		assert(clientAuthenticatingEvent!.publicKey);
		assert(
			(await clientAuthenticatingEvent!.publicKey!.getPublicKeyBytes())!.equals(
				(await SecureStreamTests.clientKey.getPublicKeyBytes())!,
			),
		);
	}

	@test
	@params({ disposeAsync: true })
	@params({ disposeAsync: false })
	@params.naming((p) => `disposeClosesTransportStream(disposeAsync:${p.disposeAsync})`)
	public async disposeClosesTransportStream({ disposeAsync }: { disposeAsync: boolean }) {
		const [_, serverStream] = await DuplexStream.createStreams();
		const server = new SecureStream(serverStream, SecureStreamTests.serverCredentials);
		assert(!server.isClosed);

		let closedEventRaised = false;
		server.onClosed((e) => (closedEventRaised = true));

		await SecureStreamTests.disposeSecureStream(server, disposeAsync);

		assert(server.isClosed);
		assert(closedEventRaised);
		assert(serverStream.isDisposed);
	}

	@test
	@params({ isConnected: true, disposeAsync: true })
	@params({ isConnected: true, disposeAsync: false })
	@params({ isConnected: false, disposeAsync: true })
	@params({ isConnected: false, disposeAsync: false })
	@params.naming(
		(p) =>
			`disposeClosesTransportStream(isConnected:${p.isConnected},disposeAsync:${p.disposeAsync})`,
	)
	public async disposeRaisesCloseEvent({
		isConnected,
		disposeAsync,
	}: {
		isConnected: boolean;
		disposeAsync: boolean;
	}) {
		const [server, client] = await this.connect();

		let closedEvent: SshSessionClosedEventArgs = undefined!;
		server.onClosed((e) => {
			closedEvent = e;
		});

		if (isConnected) {
			await Promise.all([client.connect(), server.connect()]);
		}

		await SecureStreamTests.disposeSecureStream(server, disposeAsync);

		assert(server.isClosed);
		assert(closedEvent);
		assert.equal(closedEvent.reason, SshDisconnectReason.none);
		assert.equal(closedEvent.message, 'SshServerSession disposed.');
	}

	private static async disposeSecureStream(stream: SecureStream, disposeAsync: boolean) {
		if (disposeAsync) {
			await stream.close();
		} else {
			stream.dispose();
		}
	}

	@test
	public async readWrite() {
		const [server, client] = await this.connect();

		await this.exchangeData(server, client);

		await server.close();
		await client.close();
	}

	private async connect(
		reconnectableSessions?: SshServerSession[],
		streams?: [Stream, Stream],
	): Promise<[SecureStream, SecureStream]> {
		streams ??= await DuplexStream.createStreams();
		const [serverStream, clientStream] = streams;

		const server = new SecureStream(
			serverStream,
			SecureStreamTests.serverCredentials,
			reconnectableSessions,
		);
		server.onAuthenticating((e) => (e.authenticationPromise = Promise.resolve({})));
		const client = new SecureStream(
			clientStream,
			SecureStreamTests.clientCredentials,
			!!reconnectableSessions,
		);
		client.onAuthenticating((e) => (e.authenticationPromise = Promise.resolve({})));

		await Promise.all([server.connect(), client.connect()]);

		return [server, client];
	}

	private async exchangeData(server: SecureStream, client: SecureStream) {
		const payloadString = 'Hello!';
		const payload = Buffer.from(payloadString, 'utf8');

		// Write from client, read from server.
		const readPromise = readAsync(server);
		await writeAsync(client, payload);
		const result1 = await readPromise;
		assert.equal(result1.toString('utf8'), payloadString);

		// Write from server, read from client.
		await writeAsync(server, payload);
		const result2 = await readAsync(client);
		assert.equal(result2.toString('utf8'), payloadString);
	}

	@test
	public async reconnectSecureStream() {
		let [serverStream, clientStream] = await DuplexStream.createStreams();
		serverStream = new MockNetworkStream(serverStream);
		clientStream = new MockNetworkStream(clientStream);

		const reconnectableSessions: SshServerSession[] = [];
		const streams: [Stream, Stream] = [serverStream, clientStream];
		const [server, client] = await this.connect(reconnectableSessions, streams);

		const serverDisconnected = new PromiseCompletionSource<void>();
		server.onDisconnected(() => serverDisconnected.resolve());
		const clientDisconnected = new PromiseCompletionSource<void>();
		client.onDisconnected(() => clientDisconnected.resolve());

		await this.exchangeData(server, client);

		(<MockNetworkStream>serverStream).mockDisconnect(new Error('Mock disconnect.'));
		(<MockNetworkStream>clientStream).mockDisconnect(new Error('Mock disconnect.'));

		await serverDisconnected.promise;
		await clientDisconnected.promise;

		let [serverStream2, clientStream2] = await DuplexStream.createStreams();
		serverStream2 = new MockNetworkStream(serverStream2);
		clientStream2 = new MockNetworkStream(clientStream2);

		const server2 = new SecureStream(
			serverStream2,
			SecureStreamTests.serverCredentials,
			reconnectableSessions,
		);
		server2.onAuthenticating((e) => (e.authenticationPromise = Promise.resolve({})));

		await Promise.all([server2.connect(), client.reconnect(clientStream2)]);

		await this.exchangeData(server, client);
	}
}

async function writeAsync(writable: NodeJS.WritableStream, chunk: Buffer): Promise<void> {
	return new Promise<void>((resolve, reject) => {
		writable.write(chunk, (err) => {
			if (err) {
				reject(err);
			} else {
				resolve();
			}
		});
	});
}

async function readAsync(readable: NodeJS.ReadableStream): Promise<Buffer> {
	return new Promise<Buffer>((resolve, reject) => {
		readable.once('data', (data) => {
			resolve(data);
		});
		readable.once('error', (e) => {
			reject(e);
		});
	});
}
