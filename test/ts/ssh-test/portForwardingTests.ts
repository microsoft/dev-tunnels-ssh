//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import * as net from 'net';
import { suite, test, params, pending, slow, timeout } from '@testdeck/mocha';

import {
	PromiseCompletionSource,
	SessionRequestMessage,
	SshAlgorithms,
	SshChannel,
	SshChannelError,
	SshChannelOpenFailureReason,
	SshClientSession,
	SshServerSession,
	SshStream,
} from '@microsoft/dev-tunnels-ssh';
import {
	ForwardedPort,
	ForwardedPortChannelEventArgs,
	ForwardedPortEventArgs,
	PortForwardChannelOpenMessage,
	PortForwardingService,
	PortForwardRequestMessage,
	PortForwardSuccessMessage,
	RemotePortForwarder,
	TcpListenerFactory,
} from '@microsoft/dev-tunnels-ssh-tcp';
import { connectSessionPair, createSessionConfig, createSessionPair } from './sessionPair';
import {
	acceptSocketConnection,
	getAvailablePort,
	listenOnLocalPort,
	connectSocket,
	writeSocket,
	readSocket,
	endSocket,
} from './tcpUtils';
import { expectError, until, withTimeout } from './promiseUtils';

const timeoutMs = 5000;
const loopbackV4 = '127.0.0.1';
const loopbackV6 = '::1';
const anyV4 = '0.0.0.0';
const anyV6 = '::';

// Node.js >v16 resolves "localhost" to a v6 address instead of v4.
const nodeMajorVersion = parseInt(process.versions.node.split('.')[0]);
const loopback = nodeMajorVersion > 16 ? loopbackV6 : loopbackV4;

class TestTcpListenerFactory implements TcpListenerFactory {
	public constructor(public readonly localPortOverride: number) { }

	public async createTcpListener(
		localIPAddress: string,
		localPort: number,
		canChangePort: boolean,
	): Promise<net.Server> {
		const listener = net.createServer();
		await new Promise((resolve, reject) => {
			listener.listen({
				host: localIPAddress,
				port: this.localPortOverride,
			});
			listener.on('listening', resolve);
			listener.on('error', reject);
		});
		return listener;
	}
}

@suite
@slow(2000)
@timeout(2 * timeoutMs)
export class PortForwardingTests {
	private clientSession!: SshClientSession;
	private serverSession!: SshServerSession;

	public after(): void {
		this.clientSession?.dispose();
		this.serverSession?.dispose();
	}

	private async createSessions(): Promise<[SshClientSession, SshServerSession]> {
		const serverConfig = createSessionConfig();
		const clientConfig = createSessionConfig();

		serverConfig.addService(PortForwardingService);
		clientConfig.addService(PortForwardingService);
		[this.clientSession, this.serverSession] = await createSessionPair(
			true,
			true,
			serverConfig,
			clientConfig,
		);

		const serverKey = await SshAlgorithms.publicKey.ecdsaSha2Nistp384!.generateKeyPair();
		this.serverSession.credentials.publicKeys = [serverKey];

		return [this.clientSession, this.serverSession];
	}

	@test
	@params({ isRegistered: true, isAuthorized: true })
	@params({ isRegistered: true, isAuthorized: false })
	@params({ isRegistered: false, isAuthorized: false })
	@params.naming(
		(p) => `forwardFromRemotePortRequest(reg=${p.isRegistered},auth=${p.isAuthorized})`,
	)
	public async forwardFromRemotePortRequest({
		isRegistered,
		isAuthorized,
	}: {
		isRegistered: boolean;
		isAuthorized: boolean;
	}) {
		const testPort = await getAvailablePort();
		const [clientSession, serverSession] = await this.createSessions();

		if (!isRegistered) {
			serverSession.config.services.delete(PortForwardingService);
		}

		await connectSessionPair(clientSession, serverSession);

		let requestMessage: SessionRequestMessage | undefined;
		serverSession.onRequest((e) => {
			requestMessage = e.request;
			e.isAuthorized = isAuthorized;
		});

		const pfs = clientSession.activateService(PortForwardingService);
		const forwarder = await pfs.forwardFromRemotePort(loopbackV4, testPort);

		assert.equal(requestMessage?.requestType, 'tcpip-forward');
		assert(
			requestMessage instanceof
			(isRegistered ? PortForwardRequestMessage : SessionRequestMessage),
		);
		if (isRegistered) {
			assert.equal((<PortForwardRequestMessage>requestMessage).port, testPort);
		}

		assert.equal(!!forwarder, isRegistered && isAuthorized);
		if (isRegistered && isAuthorized) {
			assert.equal(forwarder!.remoteIPAddress, loopbackV4);
			assert.equal(forwarder!.remotePort, testPort);
			assert.equal(forwarder!.localHost, loopbackV4);
			assert.equal(forwarder!.localPort, testPort);
		}
	}

	@test
	public async forwardFromRemotePortWithListenerFactory() {
		const testPort = await getAvailablePort();
		const testPort2 = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();

		await connectSessionPair(clientSession, serverSession);
		serverSession.onRequest((e) => (e.isAuthorized = true));

		const serverPfs = serverSession.activateService(PortForwardingService);
		serverPfs.tcpListenerFactory = new TestTcpListenerFactory(testPort2);

		const clientPfs = clientSession.activateService(PortForwardingService);
		const forwarder = await clientPfs.forwardFromRemotePort(loopbackV4, testPort);

		assert(forwarder);
		assert.equal(forwarder!.remoteIPAddress, loopbackV4);

		// The client does not know (or need to know) that the remote side chose a different port.
		assert.equal(testPort, forwarder!.remotePort);

		assert.equal(forwarder!.localHost, loopbackV4);
		assert.equal(forwarder!.localPort, testPort);

		const localServer = await listenOnLocalPort(testPort);
		try {
			const acceptPromise = acceptSocketConnection(localServer);
			await connectSocket(loopbackV4, testPort2);
			await withTimeout(acceptPromise, timeoutMs);
		} finally {
			localServer.close();
		}
	}

	@test
	public async forwardFromRemotePortAutoChoose() {
		const testPort = await getAvailablePort();
		const [clientSession, serverSession] = await this.createSessions();

		await connectSessionPair(clientSession, serverSession);
		serverSession.onRequest((e) => (e.isAuthorized = true));

		const pfs = clientSession.activateService(PortForwardingService);
		const forwarder = await pfs.forwardFromRemotePort(loopbackV4, 0, loopbackV4, testPort);

		assert(forwarder);
		assert.equal(forwarder!.remoteIPAddress, loopbackV4);
		assert(Number.isInteger(forwarder!.remotePort));
		assert(forwarder!.remotePort > 0);
		assert.equal(forwarder!.localHost, loopbackV4);
		assert.equal(forwarder!.localPort, testPort);
	}

	@test
	public async forwardFromRemotePortInUse() {
		const listener = await listenOnLocalPort(0);
		try {
			const testPort = (<net.AddressInfo>listener.address()).port;

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);
			serverSession.onRequest((e) => (e.isAuthorized = true));

			const pfs = clientSession.activateService(PortForwardingService);
			const forwarder = await pfs.forwardFromRemotePort(loopbackV4, testPort);
			assert(!forwarder);
		} finally {
			listener.close();
		}
	}

	@test
	@params({
		remoteServerIPAddress: anyV4,
		remoteClientIPAddress: loopbackV4,
		localForwardHost: 'localhost',
		localServerIPAddress: loopback,
	})
	@params({
		remoteServerIPAddress: loopbackV4,
		remoteClientIPAddress: loopbackV4,
		localForwardHost: loopbackV4,
		localServerIPAddress: loopbackV4,
	})
	@params({
		remoteServerIPAddress: loopbackV4,
		remoteClientIPAddress: loopbackV4,
		localForwardHost: 'localhost',
		localServerIPAddress: loopback,
	})
	@params({
		remoteServerIPAddress: anyV4,
		remoteClientIPAddress: loopbackV6,
		localForwardHost: loopbackV6,
		localServerIPAddress: loopbackV6,
	})
	@params({
		remoteServerIPAddress: loopbackV4,
		remoteClientIPAddress: loopbackV6,
		localForwardHost: loopbackV6,
		localServerIPAddress: loopbackV6,
	})
	@params({
		remoteServerIPAddress: anyV6,
		remoteClientIPAddress: loopbackV6,
		localForwardHost: loopbackV6,
		localServerIPAddress: loopbackV6,
	})
	@params({
		remoteServerIPAddress: loopbackV6,
		remoteClientIPAddress: loopbackV6,
		localForwardHost: loopbackV6,
		localServerIPAddress: loopbackV6,
	})
	@params.naming(
		(p) =>
			`forwardFromRemotePortReadWrite(${p.remoteServerIPAddress}, ${p.remoteClientIPAddress}, ${p.localForwardHost}, ${p.localServerIPAddress})`,
	)
	public async forwardFromRemotePortReadWrite({
		remoteServerIPAddress,
		remoteClientIPAddress,
		localForwardHost,
		localServerIPAddress,
	}: {
		remoteServerIPAddress: string;
		remoteClientIPAddress: string;
		localForwardHost: string;
		localServerIPAddress: string;
	}) {
		const localServer = await listenOnLocalPort(0, localServerIPAddress);
		try {
			const localPort = (<net.AddressInfo>localServer.address()).port;
			const remotePort = await getAvailablePort();

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);
			serverSession.onRequest((e) => (e.isAuthorized = true));

			const pfs = clientSession.activateService(PortForwardingService);
			const forwarder = await pfs.forwardFromRemotePort(
				remoteServerIPAddress,
				remotePort,
				localForwardHost,
				localPort,
			);
			assert(forwarder);

			const acceptPromise = acceptSocketConnection(localServer);
			const remoteClient = await withTimeout(
				connectSocket(remoteClientIPAddress, remotePort),
				timeoutMs,
			);
			const localClient = await withTimeout(acceptPromise, timeoutMs);

			const writeBuffer = Buffer.from('hello', 'utf8');
			await writeSocket(remoteClient, writeBuffer);
			await writeSocket(localClient, writeBuffer);

			const readBuffer1 = await readSocket(localClient);
			const readBuffer2 = await readSocket(remoteClient);
			assert(readBuffer1.equals(writeBuffer));
			assert(readBuffer2.equals(writeBuffer));
		} catch (e) {
			throw e;
		} finally {
			localServer.close();
		}
	}

	@test
	@params({ remoteClose: true })
	@params({ remoteClose: false })
	@params.naming((p) => `forwardFromRemotePortClose(remoteClose=${p.remoteClose})`)
	public async forwardFromRemotePortClose({ remoteClose }: { remoteClose: boolean }) {
		const localServer = await listenOnLocalPort(0);
		try {
			const localPort = (<net.AddressInfo>localServer.address()).port;

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);
			serverSession.onRequest((e) => {
				e.isAuthorized = e.request instanceof PortForwardRequestMessage;
			});

			let forwardingChannel: SshChannel | null = null;
			clientSession.onChannelOpening((e) => {
				if (e.request instanceof PortForwardChannelOpenMessage) {
					forwardingChannel = e.channel;
				}
			});

			const pfs = clientSession.activateService(PortForwardingService);
			const forwarder = await pfs.forwardFromRemotePort(loopbackV4, 0, loopbackV4, localPort);
			assert(forwarder);
			assert(!forwardingChannel);

			const acceptPromise = acceptSocketConnection(localServer);

			const remoteClient = await connectSocket(loopbackV4, forwarder!.remotePort);
			const localClient = await withTimeout(acceptPromise, timeoutMs);
			assert(forwardingChannel);

			await endSocket(remoteClose ? remoteClient : localClient);

			const readBuffer = await readSocket(remoteClose ? localClient : remoteClient);
			assert.equal(readBuffer.length, 0);

			await until(() => forwardingChannel!.isClosed, timeoutMs);
		} finally {
			localServer.close();
		}
	}

	@test
	@params({ remoteError: true })
	@params({ remoteError: false })
	@params.naming((p) => `forwardFromRemotePortError(remoteError=${p.remoteError})`)
	public async forwardFromRemotePortError({ remoteError }: { remoteError: boolean }) {
		const localServer = await listenOnLocalPort(0);
		try {
			const localPort = (<net.AddressInfo>localServer.address()).port;

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);
			serverSession.onRequest((e) => {
				e.isAuthorized = e.request instanceof PortForwardRequestMessage;
			});

			let clientForwardingChannel: SshChannel | null = null;
			let serverForwardingChannel: SshChannel | null = null;
			clientSession.onChannelOpening((e) => {
				clientForwardingChannel = e.channel;
			});
			serverSession.onChannelOpening((e) => {
				serverForwardingChannel = e.channel;
			});

			const pfs = clientSession.activateService(PortForwardingService);
			const forwarder = await pfs.forwardFromRemotePort(loopbackV4, 0, loopbackV4, localPort);
			assert(forwarder);

			const acceptPromise = acceptSocketConnection(localServer);
			const remoteClient = await withTimeout(
				connectSocket(loopbackV4, forwarder!.remotePort),
				timeoutMs,
			);
			const localClient = await withTimeout(acceptPromise, timeoutMs);

			await until(() => !!(clientForwardingChannel && serverForwardingChannel), timeoutMs);

			await (remoteError ? serverForwardingChannel! : clientForwardingChannel!).close(
				'SIGABRT',
				'Test error.',
			);

			const readError = await expectError(
				withTimeout(readSocket(remoteError ? localClient : remoteClient), timeoutMs),
				'ECONNRESET',
			);

			// TODO: The socket read should have thrown a connection-reset error:
			// https://github.com/nodejs/node/issues/27428
			////assert(readError, 'Socket read should have thrown an error.');
		} finally {
			localServer.close();
		}
	}

	@test
	public async forwardFromRemotePortCancel() {
		const testPort = await getAvailablePort();
		const [clientSession, serverSession] = await this.createSessions();

		await connectSessionPair(clientSession, serverSession);
		serverSession.onRequest((e) => (e.isAuthorized = true));

		const pfs = clientSession.activateService(PortForwardingService);
		const forwarder = await pfs.forwardFromRemotePort(loopbackV4, 0, loopbackV4, testPort);
		assert(forwarder);

		forwarder!.dispose();

		// Wait until a connection failure indicates forwarding was successfully cancelled.
		await until(async () => {
			let remoteClient: net.Socket;
			try {
				remoteClient = await connectSocket(loopbackV4, forwarder!.remotePort);
			} catch (e) {
				return true;
			}

			await endSocket(remoteClient);
			return false;
		}, timeoutMs);

		// Forward the same port again after the previous forwarding was cancelled.
		const forwarder2 = await pfs.forwardFromRemotePort(loopbackV4, 0, loopbackV4, testPort);
		assert(forwarder2);

		await connectSocket(loopbackV4, forwarder2!.remotePort);
	}

	@test
	@params({ remoteEnd: true })
	@params({ remoteEnd: false })
	@params.naming((p) => `forwardFromRemotePortEndSession(remoteEnd=${p.remoteEnd})`)
	public async forwardFromRemotePortEndSession({ remoteEnd }: { remoteEnd: boolean }) {
		const localServer = await listenOnLocalPort(0);
		try {
			const localPort = (<net.AddressInfo>localServer.address()).port;

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);
			serverSession.onRequest((e) => {
				e.isAuthorized = e.request instanceof PortForwardRequestMessage;
			});

			let forwardingChannel: SshChannel | null = null;
			clientSession.onChannelOpening((e) => {
				forwardingChannel = e.channel;
			});

			const pfs = clientSession.activateService(PortForwardingService);
			const forwarder = await pfs.forwardFromRemotePort(loopbackV4, 0, loopbackV4, localPort);
			assert(forwarder);

			const acceptPromise = acceptSocketConnection(localServer);
			const remoteClient = await withTimeout(
				connectSocket(loopbackV4, forwarder!.remotePort),
				timeoutMs,
			);
			const localClient = await withTimeout(acceptPromise, timeoutMs);
			assert(forwardingChannel);

			(remoteEnd ? serverSession : clientSession).dispose();

			const readError = await expectError(
				withTimeout(readSocket(remoteEnd ? localClient : remoteClient), timeoutMs),
				'ECONNRESET',
			);

			// TODO: The socket read should have thrown a connection-reset error:
			// https://github.com/nodejs/node/issues/27428
			////assert(readError, 'Socket read should have thrown an error.');

			// The channel will be closed asnynchronously.
			await until(() => forwardingChannel!.isClosed, timeoutMs);
		} finally {
			localServer.close();
		}
	}

	@test
	@params({ acceptLocalConnections: false })
	@params({ acceptLocalConnections: true })
	@params.naming(
		(p) => `forwardFromRemotePortRace(acceptLocalConnections=${p.acceptLocalConnections})`,
	)
	public async forwardFromRemotePortRace({
		acceptLocalConnections,
	}: {
		acceptLocalConnections: boolean;
	}) {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);
		clientSession.onRequest((e) => {
			e.isAuthorized = e.request instanceof PortForwardRequestMessage;
		});
		const clientPfs = clientSession.activateService(PortForwardingService);
		const serverPfs = serverSession.activateService(PortForwardingService);
		clientPfs.acceptLocalConnectionsForForwardedPorts = acceptLocalConnections;

		const testPort = await getAvailablePort();
		const forwarder1Promise = serverPfs.forwardFromRemotePort(loopbackV4, testPort);
		const forwarder2Promise = serverPfs.forwardFromRemotePort(loopbackV4, testPort);

		// TODO: Remove the try/catch here and error assertions below after the TS SSH API
		// supports concurrent requests.
		let forwarder1: RemotePortForwarder | null = null;
		let error1: Error | null = null;
		try {
			forwarder1 = await forwarder1Promise;
		} catch (e) {
			error1 = <Error>e;
		}

		let forwarder2: RemotePortForwarder | null = null;
		let error2: Error | null = null;
		try {
			forwarder2 = await forwarder2Promise;
		} catch (e) {
			error2 = <Error>e;
		}

		// The same port was forwarded twice concurrently.
		// Only one forwarder should have been returned.
		assert.strictEqual((forwarder1 ? 1 : 0) + (forwarder2 ? 1 : 0), 1);

		// Currently the TS SSH API does not support concurrent requests. So one of the port-forward
		// requests throws an error 'Another request is already pending'.
		assert.strictEqual((error1 ? 1 : 0) + (error2 ? 1 : 0), 1);
		assert(
			error1?.message?.includes('request is already pending') ||
				error2?.message?.includes('request is already pending'),
		);
	}

	@test
	public async forwardToRemotePortRequest() {
		const testPort = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		const pfs = clientSession.activateService(PortForwardingService);
		const forwarder = await pfs.forwardToRemotePort(loopbackV4, testPort);

		assert(forwarder);
		assert.equal(forwarder.localIPAddress, loopbackV4);
		assert.equal(forwarder.localPort, testPort);
		assert.equal(forwarder.remoteHost, loopbackV4);
		assert.equal(forwarder.remotePort, testPort);
	}

	@test
	public async forwardToRemotePortAutoChoose() {
		const testPort = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		const pfs = clientSession.activateService(PortForwardingService);
		const forwarder = await pfs.forwardToRemotePort(loopbackV4, 0, loopbackV4, testPort);

		assert(forwarder);
		assert.equal(forwarder.localIPAddress, loopbackV4);
		assert(Number.isInteger(forwarder.localPort));
		assert(forwarder.localPort > 0);
		assert.equal(forwarder.remoteHost, loopbackV4);
		assert.equal(forwarder.remotePort, testPort);
	}

	@test
	public async forwardToRemotePortInUse() {
		const listener = await listenOnLocalPort(0);
		try {
			const testPort = (<net.AddressInfo>listener.address()).port;

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);

			const pfs = clientSession.activateService(PortForwardingService);

			try {
				await pfs.forwardToRemotePort(loopbackV4, testPort);
				assert(false, 'Port in use should have caused an error.');
			} catch (e) {
				assert.equal((<any>e).code, 'EADDRINUSE');
			}
		} finally {
			listener.close();
		}
	}

	@test
	public async forwardToRemotePortUnauthorized() {
		const testPort = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		const pfs = clientSession.activateService(PortForwardingService);
		const forwarder = await pfs.forwardToRemotePort(loopbackV4, 0, loopbackV4, testPort);

		let forwardingChannel: SshChannel | null = null;
		serverSession.onChannelOpening((e) => {
			if (e.request instanceof PortForwardChannelOpenMessage) {
				forwardingChannel = e.channel;
				e.failureReason = SshChannelOpenFailureReason.connectFailed;
			}
		});

		const localClient = await connectSocket(loopbackV4, forwarder.localPort);
		await until(() => !!forwardingChannel, timeoutMs);

		const readError = await expectError(withTimeout(readSocket(localClient), timeoutMs), [
			'ECONNRESET',
			'ERR_SOCKET_CLOSED',
		]);

		// TODO: The socket read should have thrown a connection-reset error:
		// https://github.com/nodejs/node/issues/27428
		////assert(readError, 'Socket read should have thrown an error.');

		// The channel will be closed asnynchronously.
		await until(() => forwardingChannel!.isClosed, timeoutMs);
	}

	@test
	@params({
		localServerIPAddress: anyV4,
		localClientIPAddress: loopbackV4,
		remoteForwardHost: 'localhost',
		remoteServerIPAddress: loopback,
	})
	@params({
		localServerIPAddress: loopbackV4,
		localClientIPAddress: loopbackV4,
		remoteForwardHost: loopbackV4,
		remoteServerIPAddress: loopbackV4,
	})
	@params({
		localServerIPAddress: loopbackV4,
		localClientIPAddress: loopbackV4,
		remoteForwardHost: 'localhost',
		remoteServerIPAddress: loopback,
	})
	@params({
		localServerIPAddress: anyV4,
		localClientIPAddress: loopbackV6,
		remoteForwardHost: loopbackV6,
		remoteServerIPAddress: loopbackV6,
	})
	@params({
		localServerIPAddress: loopbackV4,
		localClientIPAddress: loopbackV6,
		remoteForwardHost: loopbackV6,
		remoteServerIPAddress: loopbackV6,
	})
	@params({
		localServerIPAddress: anyV6,
		localClientIPAddress: loopbackV6,
		remoteForwardHost: loopbackV6,
		remoteServerIPAddress: loopbackV6,
	})
	@params({
		localServerIPAddress: loopbackV6,
		localClientIPAddress: loopbackV6,
		remoteForwardHost: loopbackV6,
		remoteServerIPAddress: loopbackV6,
	})
	@params.naming(
		(p) =>
			`forwardToRemotePortReadWrite(${p.localServerIPAddress}, ${p.localClientIPAddress}, ${p.remoteForwardHost}, ${p.remoteServerIPAddress})`,
	)
	public async forwardToRemotePortReadWrite({
		localServerIPAddress,
		localClientIPAddress,
		remoteForwardHost,
		remoteServerIPAddress,
	}: {
		localServerIPAddress: string;
		localClientIPAddress: string;
		remoteForwardHost: string;
		remoteServerIPAddress: string;
	}) {
		const remoteServer = await listenOnLocalPort(0, remoteServerIPAddress);
		try {
			const remotePort = (<net.AddressInfo>remoteServer.address()).port;
			const localPort = await getAvailablePort();

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);

			const pfs = clientSession.activateService(PortForwardingService);
			const forwarder = await pfs.forwardToRemotePort(
				localServerIPAddress,
				localPort,
				remoteForwardHost,
				remotePort,
			);
			assert(forwarder);

			const acceptPromise = acceptSocketConnection(remoteServer);

			const localClient = await connectSocket(localClientIPAddress, localPort);
			const remoteClient = await withTimeout(acceptPromise, timeoutMs);

			const writeBuffer = Buffer.from('hello', 'utf8');
			await writeSocket(remoteClient, writeBuffer);
			await writeSocket(localClient, writeBuffer);

			const readBuffer1 = await readSocket(localClient);
			const readBuffer2 = await readSocket(remoteClient);
			assert(readBuffer1.equals(writeBuffer));
			assert(readBuffer2.equals(writeBuffer));
		} finally {
			remoteServer.close();
		}
	}

	@test
	@params({ remoteClose: true })
	@params({ remoteClose: false })
	@params.naming((p) => `forwardToRemotePortClose(remoteClose=${p.remoteClose})`)
	public async forwardToRemotePortClose({ remoteClose }: { remoteClose: boolean }) {
		const remoteServer = await listenOnLocalPort(0);
		try {
			const remotePort = (<net.AddressInfo>remoteServer.address()).port;

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);
			serverSession.onRequest((e) => {
				e.isAuthorized = e.request instanceof PortForwardRequestMessage;
			});

			let forwardingChannel: SshChannel | null = null;
			serverSession.onChannelOpening((e) => {
				if (e.request instanceof PortForwardChannelOpenMessage) {
					forwardingChannel = e.channel;
				}
			});

			const pfs = clientSession.activateService(PortForwardingService);
			const forwarder = await pfs.forwardToRemotePort(loopbackV4, 0, loopbackV4, remotePort);
			assert(forwarder);
			assert(!forwardingChannel);

			const acceptPromise = acceptSocketConnection(remoteServer);

			const localClient = await connectSocket(loopbackV4, forwarder!.localPort);
			const remoteClient = await withTimeout(acceptPromise, timeoutMs);
			assert(forwardingChannel);

			await endSocket(remoteClose ? remoteClient : localClient);

			const readBuffer = await readSocket(remoteClose ? localClient : remoteClient);
			assert.equal(readBuffer.length, 0);

			await until(() => forwardingChannel!.isClosed, timeoutMs);
		} finally {
			remoteServer.close();
		}
	}

	@test
	@params({ remoteError: true })
	@params({ remoteError: false })
	@params.naming((p) => `forwardToRemotePortError(remoteError=${p.remoteError})`)
	public async forwardToRemotePortError({ remoteError }: { remoteError: boolean }) {
		const remoteServer = await listenOnLocalPort(0);
		try {
			const remotePort = (<net.AddressInfo>remoteServer.address()).port;

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);
			serverSession.onRequest((e) => {
				e.isAuthorized = e.request instanceof PortForwardRequestMessage;
			});

			let clientForwardingChannel: SshChannel | null = null;
			let serverForwardingChannel: SshChannel | null = null;
			clientSession.onChannelOpening((e) => {
				clientForwardingChannel = e.channel;
			});
			serverSession.onChannelOpening((e) => {
				serverForwardingChannel = e.channel;
			});

			const pfs = clientSession.activateService(PortForwardingService);
			const forwarder = await pfs.forwardToRemotePort(loopbackV4, 0, loopbackV4, remotePort);
			assert(forwarder);

			const acceptPromise = acceptSocketConnection(remoteServer);

			const localClient = await connectSocket(loopbackV4, forwarder!.localPort);
			const remoteClient = await withTimeout(acceptPromise, timeoutMs);

			await until(() => !!(clientForwardingChannel && serverForwardingChannel), timeoutMs);

			await (remoteError ? serverForwardingChannel! : clientForwardingChannel!).close(
				'SIGABRT',
				'Test error.',
			);

			const readError = await expectError(
				withTimeout(readSocket(remoteError ? localClient : remoteClient), timeoutMs),
				'ECONNRESET',
			);

			// TODO: The socket read should have thrown a connection-reset error:
			// https://github.com/nodejs/node/issues/27428
			////assert(readError, 'Socket read should have thrown an error.');
		} finally {
			remoteServer.close();
		}
	}

	@test
	public async forwardToRemotePortCancel() {
		const testPort = await getAvailablePort();
		const [clientSession, serverSession] = await this.createSessions();

		await connectSessionPair(clientSession, serverSession);
		serverSession.onRequest((e) => (e.isAuthorized = true));

		const pfs = clientSession.activateService(PortForwardingService);
		const forwarder = await pfs.forwardToRemotePort(loopbackV4, 0, loopbackV4, testPort);
		assert(forwarder);

		forwarder!.dispose();

		// Wait until a connection failure indicates forwarding was successfully cancelled.
		await until(async () => {
			let remoteClient: net.Socket;
			try {
				remoteClient = await connectSocket(loopbackV4, forwarder!.localPort);
			} catch (e) {
				return true;
			}

			await endSocket(remoteClient);
			return false;
		}, timeoutMs);

		// Forward the same port again after the previous forwarding was cancelled.
		const forwarder2 = await pfs.forwardToRemotePort(loopbackV4, 0, loopbackV4, testPort);
		assert(forwarder2);

		await connectSocket(loopbackV4, forwarder2!.localPort);
	}

	@test
	@params({ remoteEnd: true })
	@params({ remoteEnd: false })
	@params.naming((p) => `forwardToRemotePortEndSession(remoteEnd=${p.remoteEnd})`)
	public async forwardToRemotePortEndSession({ remoteEnd }: { remoteEnd: boolean }) {
		const remoteServer = await listenOnLocalPort(0);
		try {
			const remotePort = (<net.AddressInfo>remoteServer.address()).port;

			const [clientSession, serverSession] = await this.createSessions();
			await connectSessionPair(clientSession, serverSession);

			let forwardingChannel: SshChannel | null = null;
			serverSession.onChannelOpening((e) => {
				forwardingChannel = e.channel;
			});

			const pfs = clientSession.activateService(PortForwardingService);
			const forwarder = await pfs.forwardToRemotePort(loopbackV4, 0, loopbackV4, remotePort);
			assert(forwarder);

			const acceptPromise = acceptSocketConnection(remoteServer);

			const localClient = await connectSocket(loopbackV4, forwarder!.localPort);
			const remoteClient = await withTimeout(acceptPromise, timeoutMs);
			assert(forwardingChannel);

			(remoteEnd ? serverSession : clientSession).dispose();

			const readError = await expectError(
				withTimeout(readSocket(remoteEnd ? localClient : remoteClient), timeoutMs),
				'ECONNRESET',
			);

			// TODO: The socket read should have thrown a connection-reset error:
			// https://github.com/nodejs/node/issues/27428
			////assert(readError, 'Socket read should have thrown an error.');

			// The channel will be closed asnynchronously.
			await until(() => forwardingChannel!.isClosed, timeoutMs);
		} finally {
			remoteServer.close();
		}
	}

	@test
	public async streamToRemotePort() {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		const remoteServer = await listenOnLocalPort(0);
		try {
			const remotePort = (<net.AddressInfo>remoteServer.address()).port;
			const acceptPromise = acceptSocketConnection(remoteServer);

			const pfs = clientSession.activateService(PortForwardingService);
			const localStream = await pfs.streamToRemotePort(loopbackV4, remotePort);
			assert(localStream);

			const remoteClient = await withTimeout(acceptPromise, timeoutMs);

			const writeBuffer = Buffer.from('hello', 'utf8');
			await writeSocket(remoteClient, writeBuffer);
			await new Promise<void>((resolve, reject) => {
				localStream.write(writeBuffer, (e?: Error | null) => {
					if (e) reject(e);
					else resolve();
				});
			});

			const readBuffer1 = await new Promise<Buffer>((resolve, reject) => {
				localStream.once('data', resolve);
				localStream.once('end', () => resolve(Buffer.alloc(0)));
				localStream.once('error', reject);
			});
			const readBuffer2 = await readSocket(remoteClient);
			assert(readBuffer1.equals(writeBuffer));
			assert(readBuffer2.equals(writeBuffer));
		} finally {
			remoteServer.close();
		}
	}

	@test
	public async streamToRemotePortError() {
		const testPort = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		serverSession.onChannelOpening((e) => {
			e.failureReason = SshChannelOpenFailureReason.administrativelyProhibited;
		});

		const pfs = clientSession.activateService(PortForwardingService);

		try {
			await pfs.streamToRemotePort(loopbackV4, testPort);
			assert(false, 'Channel open request should have thrown an error.');
		} catch (e) {
			assert(e instanceof SshChannelError);
		}
	}

	@test
	@params({ autoChoose: true })
	@params({ autoChoose: false })
	@params.naming((p) => `streamFromRemotePort(autoChoose=${p.autoChoose})`)
	public async streamFromRemotePort({ autoChoose }: { autoChoose: boolean }) {
		let remotePort = autoChoose ? 0 : await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		serverSession.onRequest((e) => {
			e.isAuthorized = e.request instanceof PortForwardRequestMessage;
		});

		const pfs = clientSession.activateService(PortForwardingService);
		const streamer = await pfs.streamFromRemotePort(loopbackV4, remotePort);
		assert(streamer);

		if (autoChoose) {
			remotePort = streamer!.remotePort;
		} else {
			assert.equal(streamer!.remotePort, remotePort);
		}

		const openCompletion = new PromiseCompletionSource<SshStream>();
		streamer!.onStreamOpened((s) => openCompletion.resolve(s));

		const remoteClient = await connectSocket(loopbackV4, remotePort);
		const localStream = await withTimeout(openCompletion.promise, timeoutMs);

		const writeBuffer = Buffer.from('hello', 'utf8');
		await writeSocket(remoteClient, writeBuffer);
		await new Promise<void>((resolve, reject) => {
			localStream.write(writeBuffer, (e?: Error | null) => {
				if (e) reject(e);
				else resolve();
			});
		});

		const readBuffer1 = await new Promise<Buffer>((resolve, reject) => {
			localStream.once('data', resolve);
			localStream.once('end', () => resolve(Buffer.alloc(0)));
			localStream.once('error', reject);
		});
		const readBuffer2 = await readSocket(remoteClient);
		assert(readBuffer1.equals(writeBuffer));
		assert(readBuffer2.equals(writeBuffer));
	}

	@test
	public async connectToForwardedPort() {
		const testPort = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		serverSession.onRequest((e) => {
			e.isAuthorized = e.request instanceof PortForwardRequestMessage;
		});

		const clientPfs = clientSession.activateService(PortForwardingService);
		const serverPfs = serverSession.activateService(PortForwardingService);
		serverPfs.acceptLocalConnectionsForForwardedPorts = false;

		const localServer = await listenOnLocalPort(testPort);
		try {
			const acceptPromise = acceptSocketConnection(localServer);

			const waitPromise = serverPfs.waitForForwardedPort(testPort);
			const forwardPromise = await withTimeout(
				clientPfs.forwardFromRemotePort(loopbackV4, testPort),
				timeoutMs,
			);
			await withTimeout(waitPromise, timeoutMs);

			const remoteStream = await withTimeout(
				serverPfs.connectToForwardedPort(testPort),
				timeoutMs,
			);
			const localClient = await withTimeout(acceptPromise, timeoutMs);

			// Don't wait for the forward response until after connecting.
			// The side that receives the forward request can open a port-forwarding channel
			// immediately (before the request sender has received the response).
			await forwardPromise;
		} finally {
			localServer.close();
		}
	}

	@test
	public async connectToForwardedPortWithoutForwardingConnectionToLocalPort() {
		const testPort = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		serverSession.onRequest((e) => {
			e.isAuthorized = e.request instanceof PortForwardRequestMessage;
		});

		const clientPfs = clientSession.activateService(PortForwardingService);
		clientPfs.forwardConnectionsToLocalPorts = false;

		let localStream;
		clientSession.onChannelOpening((e) => {
			localStream = new SshStream(e.channel);
		});

		const serverPfs = serverSession.activateService(PortForwardingService);
		serverPfs.acceptLocalConnectionsForForwardedPorts = false;

		const waitPromise = serverPfs.waitForForwardedPort(testPort);
		const forwardPromise = await withTimeout(
			clientPfs.forwardFromRemotePort(loopbackV4, testPort),
			timeoutMs,
		);
		await withTimeout(waitPromise, timeoutMs);

		const remoteStream = await withTimeout(
			serverPfs.connectToForwardedPort(testPort),
			timeoutMs,
		);

		assert(localStream);
		assert(remoteStream);
	}

	@test
	public async blockConnectToNonForwardedPort(): Promise<void> {
		const testPort = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		const clientPfs = clientSession.activateService(PortForwardingService);
		const serverPfs = serverSession.activateService(PortForwardingService);
		serverPfs.acceptRemoteConnectionsForNonForwardedPorts = false;

		try {
			await withTimeout(clientPfs.streamToRemotePort('localhost', testPort), timeoutMs);
			assert(false, 'Connection should have been blocked.');
		} catch (e) {
			if (!(e instanceof SshChannelError)) throw e;
			assert.equal(e.reason, SshChannelOpenFailureReason.administrativelyProhibited);
		}
	}

	@test
	public async blockForwardAlreadyForwardedPort(): Promise<void> {
		const testPort1 = await getAvailablePort();
		const testPort2 = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		serverSession.onRequest((e) => {
			e.isAuthorized = e.request instanceof PortForwardRequestMessage;
		});

		const clientPfs = clientSession.activateService(PortForwardingService);

		try {
			const forwarder1 = await clientPfs.forwardFromRemotePort(loopbackV4, testPort1);
			assert(forwarder1);

			// Bypass the forwardFromRemotePort API because it has a client-side check
			// that prevents validation of the remote block.
			const portRequest = new PortForwardRequestMessage();
			portRequest.port = testPort1;
			const result = await clientSession.request(portRequest);
			assert(!result);

			// Cancel forwarding.
			forwarder1!.dispose();

			const forwarder3 = await clientPfs.forwardFromRemotePort(loopbackV4, testPort1);
			assert(forwarder3);
			forwarder3!.dispose();
		} finally {
			serverSession.dispose();
			clientSession.dispose();
		}
	}

	@test
	public async raiseForwardedPortEvents(): Promise<void> {
		const testPort1 = await getAvailablePort();
		const testPort2 = await getAvailablePort();

		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		serverSession.onRequest((e) => {
			e.isAuthorized = e.request instanceof PortForwardRequestMessage;
		});

		const clientPfs = clientSession.activateService(PortForwardingService);
		const serverPfs = serverSession.activateService(PortForwardingService);

		let clientLocalPortAddedEvent: ForwardedPortEventArgs | undefined;
		clientPfs.localForwardedPorts.onPortAdded((e) => (clientLocalPortAddedEvent = e));
		let clientRemotePortAddedEvent: ForwardedPortEventArgs | undefined;
		clientPfs.remoteForwardedPorts.onPortAdded((e) => (clientRemotePortAddedEvent = e));

		let serverLocalPortAddedEvent: ForwardedPortEventArgs | undefined;
		serverPfs.localForwardedPorts.onPortAdded((e) => (serverLocalPortAddedEvent = e));
		let serverRemotePortAddedEvent: ForwardedPortEventArgs | undefined;
		serverPfs.remoteForwardedPorts.onPortAdded((e) => (serverRemotePortAddedEvent = e));

		let clientLocalPortRemovedEvent: ForwardedPortEventArgs | undefined;
		clientPfs.localForwardedPorts.onPortRemoved((e) => (clientLocalPortRemovedEvent = e));
		let clientRemotePortRemovedEvent: ForwardedPortEventArgs | undefined;
		clientPfs.remoteForwardedPorts.onPortRemoved((e) => (clientRemotePortRemovedEvent = e));

		let serverLocalPortRemovedEvent: ForwardedPortEventArgs | undefined;
		serverPfs.localForwardedPorts.onPortRemoved((e) => (serverLocalPortRemovedEvent = e));
		let serverRemotePortRemovedEvent: ForwardedPortEventArgs | undefined;
		serverPfs.remoteForwardedPorts.onPortRemoved((e) => (serverRemotePortRemovedEvent = e));

		let clientLocalChannelAddedEvent: ForwardedPortChannelEventArgs | undefined;
		clientPfs.localForwardedPorts.onPortChannelAdded((e) => (clientLocalChannelAddedEvent = e));
		let clientRemoteChannelAddedEvent: ForwardedPortChannelEventArgs | undefined;
		clientPfs.remoteForwardedPorts.onPortChannelAdded((e) => (clientRemoteChannelAddedEvent = e));

		let serverLocalChannelAddedEvent: ForwardedPortChannelEventArgs | undefined;
		serverPfs.localForwardedPorts.onPortChannelAdded((e) => (serverLocalChannelAddedEvent = e));
		let serverRemoteChannelAddedEvent: ForwardedPortChannelEventArgs | undefined;
		serverPfs.remoteForwardedPorts.onPortChannelAdded((e) => (serverRemoteChannelAddedEvent = e));

		let clientLocalChannelRemovedEvent: ForwardedPortChannelEventArgs | undefined;
		clientPfs.localForwardedPorts.onPortChannelRemoved(
			(e) => (clientLocalChannelRemovedEvent = e),
		);
		let clientRemoteChannelRemovedEvent: ForwardedPortChannelEventArgs | undefined;
		clientPfs.remoteForwardedPorts.onPortChannelRemoved(
			(e) => (clientRemoteChannelRemovedEvent = e),
		);

		let serverLocalChannelRemovedEvent: ForwardedPortChannelEventArgs | undefined;
		serverPfs.localForwardedPorts.onPortChannelRemoved(
			(e) => (serverLocalChannelRemovedEvent = e),
		);
		let serverRemoteChannelRemovedEvent: ForwardedPortChannelEventArgs | undefined;
		serverPfs.remoteForwardedPorts.onPortChannelRemoved(
			(e) => (serverRemoteChannelRemovedEvent = e),
		);

		serverPfs.tcpListenerFactory = new TestTcpListenerFactory(testPort2);

		const forwarder = await withTimeout(
			clientPfs.forwardFromRemotePort(loopbackV4, testPort1),
			timeoutMs,
		);

		assert.equal(clientPfs.localForwardedPorts.size, 1);
		assert.equal(clientPfs.remoteForwardedPorts.size, 0);
		assert.equal(serverPfs.localForwardedPorts.size, 0);
		assert.equal(serverPfs.remoteForwardedPorts.size, 1);
		assert(
			clientPfs.localForwardedPorts.find(
				(p) => p.localPort === testPort1 && p.remotePort === testPort1,
			),
		);
		assert(
			serverPfs.remoteForwardedPorts.find(
				(p) => p.localPort === testPort2 && p.remotePort === testPort1,
			),
		);

		assert(clientLocalPortAddedEvent);
		assert.equal(clientLocalPortAddedEvent!.port.localPort, testPort1);
		assert.equal(clientLocalPortAddedEvent!.port.remotePort, testPort1);
		assert(!clientRemotePortAddedEvent);
		assert(!serverLocalPortAddedEvent);
		assert(serverRemotePortAddedEvent);
		assert.equal(serverRemotePortAddedEvent!.port.localPort, testPort2);
		assert.equal(serverRemotePortAddedEvent!.port.remotePort, testPort1);

		assert(!clientLocalChannelAddedEvent);
		assert(!clientRemoteChannelAddedEvent);
		assert(!serverLocalChannelAddedEvent);
		assert(!serverRemoteChannelAddedEvent);

		const localServer = await listenOnLocalPort(testPort1);
		try {
			const acceptPromise = acceptSocketConnection(localServer);

			const remoteStream = await withTimeout(
				serverPfs.connectToForwardedPort(testPort1),
				timeoutMs,
			);
			const localClient = await withTimeout(acceptPromise, timeoutMs);

			assert.equal(clientPfs.localForwardedPorts.size, 1);
			const clientLocalForwardedPort = clientPfs.localForwardedPorts.find(() => true)!;
			assert.equal(
				clientPfs.localForwardedPorts.getChannels(clientLocalForwardedPort).length,
				1,
			);
			assert.equal(clientPfs.remoteForwardedPorts.size, 0);
			assert.equal(serverPfs.localForwardedPorts.size, 0);
			assert.equal(serverPfs.remoteForwardedPorts.size, 1);
			const serverRemoteForwardedPort = serverPfs.remoteForwardedPorts.find(() => true)!;
			assert.equal(
				serverPfs.remoteForwardedPorts.getChannels(serverRemoteForwardedPort).length,
				1,
			);

			assert(clientLocalChannelAddedEvent);
			assert.equal(
				(<ForwardedPortChannelEventArgs>clientLocalChannelAddedEvent).port.localPort,
				testPort1);
			assert.equal(
				(<ForwardedPortChannelEventArgs>clientLocalChannelAddedEvent).port.remotePort,
				testPort1);
			assert((<ForwardedPortChannelEventArgs>clientLocalChannelAddedEvent).channel);
			assert(!clientRemoteChannelAddedEvent);

			assert(!serverLocalChannelAddedEvent);
			assert(serverRemoteChannelAddedEvent);
			assert.equal(
				(<ForwardedPortChannelEventArgs>serverRemoteChannelAddedEvent).port.localPort,
				testPort2);
			assert.equal(
				(<ForwardedPortChannelEventArgs>serverRemoteChannelAddedEvent).port.remotePort,
				testPort1);
			assert((<ForwardedPortChannelEventArgs>serverRemoteChannelAddedEvent).channel);

			assert(!clientLocalChannelRemovedEvent);
			assert(!clientRemoteChannelRemovedEvent);
			assert(!serverLocalChannelRemovedEvent);
			assert(!serverRemoteChannelRemovedEvent);

			remoteStream.destroy();
		} finally {
			localServer.close();
		}

		await new Promise((resolve) => setTimeout(resolve, 2000));

		await until(() => !!serverRemoteChannelRemovedEvent, timeoutMs);

		assert.equal(clientPfs.localForwardedPorts.size, 1);
		const clientLocalForwardedPort2 = clientPfs.localForwardedPorts.find(() => true)!;
		assert.equal(clientPfs.localForwardedPorts.getChannels(clientLocalForwardedPort2).length, 0);

		assert.equal(serverPfs.remoteForwardedPorts.size, 1);
		const serverRemoteForwardedPort2 = serverPfs.remoteForwardedPorts.find(() => true)!;
		assert.equal(
			serverPfs.remoteForwardedPorts.getChannels(serverRemoteForwardedPort2).length,
			0,
		);

		assert(clientLocalChannelRemovedEvent);
		assert.equal(
			(<ForwardedPortChannelEventArgs>clientLocalChannelRemovedEvent).port.localPort,
			testPort1);
		assert.equal(
			(<ForwardedPortChannelEventArgs>clientLocalChannelRemovedEvent).port.remotePort,
			testPort1);
		assert((<ForwardedPortChannelEventArgs>clientLocalChannelRemovedEvent).channel);
		assert(!clientRemoteChannelRemovedEvent);
		assert(!serverLocalChannelRemovedEvent);
		assert.equal(serverRemoteChannelRemovedEvent!.port.localPort, testPort2);
		assert.equal(serverRemoteChannelRemovedEvent!.port.remotePort, testPort1);
		assert(serverRemoteChannelRemovedEvent!.channel);

		forwarder!.dispose();

		await until(() => !!clientLocalPortRemovedEvent, timeoutMs);
		await until(() => !!serverRemotePortRemovedEvent, timeoutMs);

		assert.equal(clientPfs.localForwardedPorts.size, 0);
		assert.equal(clientPfs.remoteForwardedPorts.size, 0);
		assert.equal(serverPfs.localForwardedPorts.size, 0);
		assert(!clientRemotePortRemovedEvent);
		assert(!serverLocalPortRemovedEvent);
	}

	@test
	public async reforwardingTheSamePortWhenNotAcceptLocalConnectionsForForwardedPorts(): Promise<void> {
		const testPort = await getAvailablePort();
		const [clientSession, serverSession] = await this.createSessions();

		await connectSessionPair(clientSession, serverSession);
		serverSession.onRequest((e) => e.isAuthorized = true);

		const clientPfs = clientSession.activateService(PortForwardingService);
		const serverPfs = serverSession.activateService(PortForwardingService);
		serverPfs.acceptLocalConnectionsForForwardedPorts = false;

		const forwarder1 = await clientPfs.forwardFromRemotePort(loopbackV4, testPort);
		assert(forwarder1);

		forwarder1.dispose();

		// Wait until a connection failure indicates forwarding was successfully cancelled.
		await until(async () => {
			let remoteClient: net.Socket;
			try {
				remoteClient = await connectSocket(loopbackV4, forwarder1!.remotePort);
			} catch (e) {
				return true;
			}

			await endSocket(remoteClient);
			return false;
		}, timeoutMs);

		const forwarder2 = await clientPfs.forwardFromRemotePort(loopbackV4, testPort);
		assert(forwarder2);
	}
}
