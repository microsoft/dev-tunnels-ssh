//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout, pending } from '@testdeck/mocha';

import {
	KeyPair,
	SshAlgorithms,
	SshClientSession,
	SshServerSession,
	SshSessionConfiguration,
	PromiseCompletionSource,
	SshProtocolExtensionNames,
	SshDisconnectReason,
	SessionRequestMessage,
	SshChannel,
	SshConnectionError,
	SshReconnectError,
	SshReconnectFailureReason,
	ObjectDisposedError,
	SshStream,
	SshDataWriter,
	SshDataReader,
	CancellationToken,
	CancellationError,
	CancellationTokenSource,
	TraceLevel,
} from '@microsoft/dev-tunnels-ssh';

import { DuplexStream } from './duplexStream';
import { connectSessionPair, disconnectSessionPair, createSessionConfig } from './sessionPair';
import { MockNetworkStream } from './mockNetworkStream';

if (!assert.rejects) {
	// Polyfill for browsers that don't have this API
	(<any>assert).rejects = async function (action: () => Promise<any>, error?: Function) {
		try {
			await action();
		} catch (e) {
			if (error) assert(e instanceof error);
			return;
		}
		assert.fail('Promise was not rejected.');
	};
}

@suite
@slow(5000)
@timeout(30000)
export class ReconnectTests {
	private static readonly testUsername = 'test';
	private static clientKey: KeyPair;
	private static serverKey: KeyPair;
	private static testConfig: SshSessionConfiguration;

	@slow(10000)
	@timeout(30000)
	public static async before() {
		ReconnectTests.clientKey = await SshAlgorithms.publicKey.rsaWithSha512!.generateKeyPair();
		ReconnectTests.serverKey = await SshAlgorithms.publicKey.rsaWithSha512!.generateKeyPair();
		ReconnectTests.testConfig = createSessionConfig();
		ReconnectTests.testConfig.protocolExtensions.push(SshProtocolExtensionNames.sessionReconnect);
	}

	private readonly serverSession: SshServerSession;
	private readonly clientSession: SshClientSession;
	private readonly reconnectableSessions: SshServerSession[];
	private clientDisconnectedCompletion = new PromiseCompletionSource<void>();
	private serverDisconnectedCompletion = new PromiseCompletionSource<void>();
	private serverReconnectedCompletion = new PromiseCompletionSource<void>();
	private serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
	private clientReceivedCompletion = new PromiseCompletionSource<Buffer>();

	public constructor() {
		this.reconnectableSessions = [];
		this.serverSession = new SshServerSession(
			ReconnectTests.testConfig,
			this.reconnectableSessions,
		);
		this.clientSession = new SshClientSession(ReconnectTests.testConfig);

		this.serverSession.credentials.publicKeys = [ReconnectTests.serverKey];

		this.clientSession.onDisconnected(() => this.clientDisconnectedCompletion.resolve());
		this.serverSession.onDisconnected(() => this.serverDisconnectedCompletion.resolve());
		this.serverSession.onReconnected(() => this.serverReconnectedCompletion.resolve());

		this.clientSession.onClosed((e) =>
			this.clientDisconnectedCompletion.reject(e.error ?? new Error('Session closed.')),
		);
		this.serverSession.onClosed((e) =>
			this.clientDisconnectedCompletion.reject(e.error ?? new Error('Session closed.')),
		);
	}

	private async waitUntilReconnectEnabled() {
		assert(this.serverSession.isConnected);
		assert(this.clientSession.isConnected);

		// Reconnect is not enabled until a few messages are exchanged.
		while (
			!this.serverSession.protocolExtensions?.has(SshProtocolExtensionNames.sessionReconnect) ||
			!this.clientSession.protocolExtensions?.has(SshProtocolExtensionNames.sessionReconnect)
		) {
			await new Promise((c) => setTimeout(c, 5));
		}

		await this.waitUntilCollectionContains(this.serverSession, this.reconnectableSessions);
	}

	private async waitUntilCollectionContains<T>(expected: T, collection: T[]) {
		while (true) {
			if (collection.includes(expected)) {
				return;
			}

			await new Promise((c) => setTimeout(c, 5));
		}
	}

	private async initializeChannelPair(
		withCompletions: boolean = true,
	): Promise<[SshChannel, SshChannel]> {
		const serverChannelTask = this.serverSession.acceptChannel();
		const clientChannel = await this.clientSession.openChannel();
		const serverChannel = await serverChannelTask;

		if (withCompletions) {
			this.serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
			this.clientReceivedCompletion = new PromiseCompletionSource<Buffer>();
		}

		serverChannel.onDataReceived((data) => {
			serverChannel.adjustWindow(data.length);

			if (withCompletions) {
				this.serverReceivedCompletion.resolve(Buffer.from(data));
			}
		});
		clientChannel.onDataReceived((data) => {
			clientChannel.adjustWindow(data.length);

			if (withCompletions) {
				this.clientReceivedCompletion.resolve(Buffer.from(data));
			}
		});

		return [serverChannel, clientChannel];
	}

	private async doReconnect(): Promise<[MockNetworkStream, MockNetworkStream]> {
		assert(
			this.reconnectableSessions.length === 1 &&
				this.reconnectableSessions[0] == this.serverSession,
		);

		this.serverReconnectedCompletion = new PromiseCompletionSource<void>();
		const newServerSession = new SshServerSession(
			ReconnectTests.testConfig,
			this.reconnectableSessions,
		);
		newServerSession.credentials.publicKeys = [ReconnectTests.serverKey];

		let serverDisconnected = false;
		let serverRequest = false;
		newServerSession.onDisconnected((e) => (serverDisconnected = true));
		newServerSession.onRequest((e) => (serverRequest = true));

		// Reconnect the session using a new pair of streams (and a temporary server session).
		const [newStream1, newStream2] = await DuplexStream.createStreams();
		const newServerStream = new MockNetworkStream(newStream1);
		const newClientStream = new MockNetworkStream(newStream2);
		const serverConnectPromise = newServerSession.connect(newServerStream);
		await this.clientSession.reconnect(newClientStream);
		await serverConnectPromise;
		await this.serverReconnectedCompletion.promise;

		assert(newServerSession.isClosed);
		assert(!this.clientSession.isClosed);
		assert(!this.serverSession.isClosed);
		assert(!serverDisconnected);
		assert(!serverRequest);

		// The session should still be in the reconnectable collection.
		assert(
			this.reconnectableSessions.length === 1 &&
				this.reconnectableSessions[0] == this.serverSession,
		);

		return [newClientStream, newServerStream];
	}

	@test
	public async disconnectViaStreamClose() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();
		disconnectSessionPair(clientStream, serverStream);

		await this.clientDisconnectedCompletion.promise;
		assert(!this.clientSession.isConnected);
		assert(!this.clientSession.isClosed);
		await this.serverDisconnectedCompletion.promise;
		assert(!this.serverSession.isConnected);
		assert(!this.serverSession.isClosed);
	}

	@test
	public async disconnectViaStreamError() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();
		disconnectSessionPair(clientStream, serverStream, new Error('Mock error.'));

		await this.clientDisconnectedCompletion.promise;
		assert(!this.clientSession.isConnected);
		assert(!this.clientSession.isClosed);
		await this.serverDisconnectedCompletion.promise;
		assert(!this.serverSession.isConnected);
		assert(!this.serverSession.isClosed);
	}

	@test
	public async disconnectViaClientSessionClose() {
		await connectSessionPair(this.clientSession, this.serverSession);
		await this.waitUntilReconnectEnabled();
		await this.clientSession.close(SshDisconnectReason.connectionLost);

		await this.clientDisconnectedCompletion.promise;
		assert(!this.clientSession.isConnected);
		assert(!this.clientSession.isClosed);
		await this.serverDisconnectedCompletion.promise;
		assert(!this.serverSession.isConnected);
		assert(!this.serverSession.isClosed);
	}

	@test
	public async disconnectViaServerSessionClose() {
		await connectSessionPair(this.clientSession, this.serverSession);
		await this.waitUntilReconnectEnabled();
		await this.serverSession.close(SshDisconnectReason.connectionLost);

		await this.clientDisconnectedCompletion.promise;
		assert(!this.clientSession.isConnected);
		assert(!this.clientSession.isClosed);
		await this.serverDisconnectedCompletion.promise;
		assert(!this.serverSession.isConnected);
		assert(!this.serverSession.isClosed);
	}

	@test
	public async reconnect() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();
		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		await this.doReconnect();

		// Verify messages can be sent and received after reconnecting.
		this.serverSession.onRequest((e) => (e.isAuthorized = true));
		const requestMessage = new SessionRequestMessage();
		requestMessage.requestType = 'test';
		requestMessage.wantReply = true;
		const requestResult = await this.clientSession.request(
			new SessionRequestMessage('test', true),
		);
		assert(requestResult);
	}

	@test
	public async reconnectBeforeServerDisconnected() {
		// The server may not immediately detect the network disconnection, especially
		// if it is not trying to send any messages. Meanwhile the client may already try
		// to reconnect. That should work so the reconnection is not unnecessarily delayed.

		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		let serverDisconnected = false;
		this.serverSession.onDisconnected(() => (serverDisconnected = true));

		clientStream.disposeUnderlyingStream = false;
		clientStream.dispose();
		await this.clientDisconnectedCompletion.promise;
		assert(!serverDisconnected);

		await this.doReconnect();
	}

	@test
	public async reconnectChannel() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		const [serverChannel, clientChannel] = await this.initializeChannelPair();

		const testData = Buffer.from('test');
		await clientChannel.send(testData);
		await serverChannel.send(testData);
		await this.serverReceivedCompletion.promise;
		await this.clientReceivedCompletion.promise;

		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		await this.doReconnect();

		// Send more channel messages and verify they are received.
		this.serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
		this.clientReceivedCompletion = new PromiseCompletionSource<Buffer>();
		await clientChannel.send(testData);
		await serverChannel.send(testData);
		await this.serverReceivedCompletion.promise;
		await this.clientReceivedCompletion.promise;
	}

	@test
	public async reconnectWithRetransmittedClientData() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		const [serverChannel, clientChannel] = await this.initializeChannelPair();

		const testData = Buffer.from('test');
		await clientChannel.send(testData);
		await serverChannel.send(testData);
		await this.serverReceivedCompletion.promise;
		await this.clientReceivedCompletion.promise;

		let serverReceived = false;
		serverChannel.onDataReceived((data) => (serverReceived = true));

		this.serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
		serverStream.dispose();
		clientStream.mockDisconnect(new Error('Mock disconnect.'), 96);
		await clientChannel.send(testData);
		assert(clientStream.isDisposed);

		// The last sent message should have been dropped by the disconnection.
		await new Promise((c) => setTimeout(c, 5));
		assert(!serverReceived);

		await this.doReconnect();

		// The dropped message should be retransmitted after reconnection.
		await this.serverReceivedCompletion.promise;

		// Send more channel messages and verify they are received.
		this.serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
		this.clientReceivedCompletion = new PromiseCompletionSource<Buffer>();
		await clientChannel.send(testData);
		await serverChannel.send(testData);
		await this.serverReceivedCompletion.promise;
		await this.clientReceivedCompletion.promise;
	}

	@test
	public async reconnectWithRetransmittedServerData() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		const [serverChannel, clientChannel] = await this.initializeChannelPair();

		const testData = Buffer.from('test');
		await clientChannel.send(testData);
		await serverChannel.send(testData);
		await this.serverReceivedCompletion.promise;
		await this.clientReceivedCompletion.promise;

		let clientReceived = false;
		serverChannel.onDataReceived((data) => (clientReceived = true));

		this.clientReceivedCompletion = new PromiseCompletionSource<Buffer>();
		serverStream.mockDisconnect(new Error('Mock disconnect.'), 96);
		clientStream.dispose();
		await serverChannel.send(testData);
		assert(serverStream.isDisposed);

		// The last sent message should have been dropped by the disconnection.
		await new Promise((c) => setTimeout(c, 5));
		assert(!clientReceived);

		await this.doReconnect();

		// The dropped message should be retransmitted after reconnection.
		await this.clientReceivedCompletion.promise;

		// Send more channel messages and verify they are received.
		this.serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
		this.clientReceivedCompletion = new PromiseCompletionSource<Buffer>();
		await clientChannel.send(testData);
		await serverChannel.send(testData);
		await this.serverReceivedCompletion.promise;
		await this.clientReceivedCompletion.promise;
	}

	@test
	public async sendWhileDisconnected() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		const [serverChannel, clientChannel] = await this.initializeChannelPair();

		const testData = Buffer.from('test');
		await clientChannel.send(testData);
		await serverChannel.send(testData);
		await this.serverReceivedCompletion.promise;
		await this.clientReceivedCompletion.promise;

		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		// Sending on a disconnected session should still be possible. (Messages are buffered.)
		this.clientReceivedCompletion = new PromiseCompletionSource<Buffer>();
		this.serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
		await clientChannel.send(testData);
		await serverChannel.send(testData);

		await this.doReconnect();

		// The messages sent during disconnection should be received after reconnect.
		await this.serverReceivedCompletion.promise;
		await this.clientReceivedCompletion.promise;

		this.clientReceivedCompletion = new PromiseCompletionSource<Buffer>();
		this.serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
		await clientChannel.send(testData);
		await serverChannel.send(testData);
		await this.serverReceivedCompletion.promise;
		await this.clientReceivedCompletion.promise;
	}

	@test
	@slow(10000)
	public async multiReconnect() {
		let [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		const [serverChannel, clientChannel] = await this.initializeChannelPair();

		const testData = Buffer.from('test');

		for (let i = 0; i < 3; i++) {
			// Send some messages while the session is connected.
			this.clientReceivedCompletion = new PromiseCompletionSource<Buffer>();
			this.serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
			await clientChannel.send(testData);
			await serverChannel.send(testData);
			await this.serverReceivedCompletion.promise;
			await this.clientReceivedCompletion.promise;

			// Disconnect while no messages are being sent.
			disconnectSessionPair(clientStream, serverStream);

			// Send some messages while the session is disconnected.
			this.clientReceivedCompletion = new PromiseCompletionSource<Buffer>();
			this.serverReceivedCompletion = new PromiseCompletionSource<Buffer>();
			await clientChannel.send(testData);
			await serverChannel.send(testData);

			await this.clientDisconnectedCompletion.promise;
			await this.serverDisconnectedCompletion.promise;

			[clientStream, serverStream] = await this.doReconnect();

			// The messages sent during disconnection should be received after reconnect.
			await this.serverReceivedCompletion.promise;
			await this.clientReceivedCompletion.promise;
		}
	}

	@test
	public async reconnectThenKeyExchange() {
		const testKeyRotationThreshold = 10 * 1024 * 1024; // 10 MB
		(<any>this.clientSession.config).keyRotationThreshold = testKeyRotationThreshold;
		(<any>this.serverSession.config).keyRotationThreshold = testKeyRotationThreshold;

		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		const [serverChannel, clientChannel] = await this.initializeChannelPair(false);

		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		await this.doReconnect();

		// After reconnecting, send enough data to trigger a key rotation.
		const largeMessageSize = (1024 * 1024 * 3) / 2;
		const largeData = Buffer.alloc(largeMessageSize);
		for (let i = 0; i < largeMessageSize; i++) largeData[i] = i & 0xff;

		const messageCount = testKeyRotationThreshold / largeMessageSize + 5;
		for (let i = 0; i < messageCount; i++) {
			await clientChannel.send(largeData);
		}
	}

	@test
	public async reconnectSessionNotFound() {
		let [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		this.reconnectableSessions.splice(0, this.reconnectableSessions.length);

		const newServerSession = new SshServerSession(
			ReconnectTests.testConfig,
			this.reconnectableSessions,
		);
		newServerSession.credentials.publicKeys = [ReconnectTests.serverKey];

		let serverDisconnected = false;
		let clientDisconnected = false;
		newServerSession.onDisconnected((e) => (serverDisconnected = true));
		this.clientSession.onDisconnected((e) => (clientDisconnected = true));

		const [newServerStream, newClientStream] = await DuplexStream.createStreams();
		serverStream = new MockNetworkStream(newServerStream);
		clientStream = new MockNetworkStream(newClientStream);
		const serverConnectPromise = newServerSession.connect(serverStream);
		const reconnectPromise = this.clientSession.reconnect(clientStream);

		try {
			await Promise.all([serverConnectPromise, reconnectPromise]);
			assert(false);
		} catch (e) {
			assert(e instanceof SshReconnectError);
			assert.equal((<SshReconnectError>e).reason, SshReconnectFailureReason.sessionNotFound);
		}

		assert(!serverDisconnected);
		assert(!clientDisconnected);
	}

	@test
	public async acceptChannelOnServerReconnect() {
		let [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		const newServerSession = new SshServerSession(
			ReconnectTests.testConfig,
			this.reconnectableSessions,
		);
		newServerSession.credentials.publicKeys = [ReconnectTests.serverKey];

		const [newServerStream, newClientStream] = await DuplexStream.createStreams();
		serverStream = new MockNetworkStream(newServerStream);
		clientStream = new MockNetworkStream(newClientStream);
		const reconnectPromise = this.clientSession.reconnect(clientStream);
		const acceptChannelPromise = assert.rejects(async () => {
			await newServerSession.connect(serverStream);
			await newServerSession.acceptChannel();
		}, ObjectDisposedError);

		await Promise.all([reconnectPromise, acceptChannelPromise]);
		await reconnectPromise;
		await acceptChannelPromise;
	}

	@test
	public async reconnectAfterInterruptedReconnect() {
		let [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();

		await this.initializeChannelPair();

		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		this.serverReconnectedCompletion = new PromiseCompletionSource<void>();
		let newServerSession = new SshServerSession(
			ReconnectTests.testConfig,
			this.reconnectableSessions,
		);
		newServerSession.credentials.publicKeys = [ReconnectTests.serverKey];

		const [newServerStream, newClientStream] = await DuplexStream.createStreams();
		serverStream = new MockNetworkStream(newServerStream);
		clientStream = new MockNetworkStream(newClientStream);

		// Cause the first reconnect attempt to be interrupted by another disconnection.
		clientStream.mockDisconnect(new Error('Test disconnection'), 80);

		const serverConnectPromise = assert.rejects(() => newServerSession.connect(serverStream));
		const reconnectPromise = assert.rejects(() => this.clientSession.reconnect(clientStream));
		await Promise.all([serverConnectPromise, reconnectPromise]);

		assert(!this.clientSession.isConnected);
		assert(!this.serverSession.isConnected);
		assert(
			this.reconnectableSessions.length === 1 &&
				this.reconnectableSessions[0] == this.serverSession,
		);

		// Try again, this time with no interruption.
		newServerSession = new SshServerSession(
			ReconnectTests.testConfig,
			this.reconnectableSessions,
		);
		newServerSession.credentials.publicKeys = [ReconnectTests.serverKey];

		const [newServerStream2, newClientStream2] = await DuplexStream.createStreams();
		serverStream = new MockNetworkStream(newServerStream2);
		clientStream = new MockNetworkStream(newClientStream2);

		const serverConnectPromise2 = newServerSession.connect(serverStream);
		const reconnectPromise2 = this.clientSession.reconnect(clientStream);
		await reconnectPromise2;
		await serverConnectPromise2;
		await this.serverReconnectedCompletion.promise;
	}

	@test
	public async reconnectWrongSessionId() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();
		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		// Change the ID of the reconnectable server session to invalidate the reconnect attempt.
		this.reconnectableSessions[0].sessionId?.fill(0, 0, 10);

		const newServerSession = new SshServerSession(
			ReconnectTests.testConfig,
			this.reconnectableSessions,
		);
		newServerSession.credentials.publicKeys = [ReconnectTests.serverKey];

		let serverDisconnected = false;
		let serverRequest = false;
		newServerSession.onDisconnected((e) => (serverDisconnected = true));
		newServerSession.onRequest((e) => (serverRequest = true));

		// Reconnect the session using a new pair of streams (and a temporary server session).
		const [newStream1, newStream2] = await DuplexStream.createStreams();
		const newServerStream = new MockNetworkStream(newStream1);
		const newClientStream = new MockNetworkStream(newStream2);
		const serverConnectPromise = newServerSession.connect(newServerStream);
		const reconnectPromise = this.clientSession.reconnect(newClientStream);

		await serverConnectPromise;

		// Reconnection should fail.
		try {
			await reconnectPromise;
			assert(false);
		} catch (e) {
			assert(e instanceof SshReconnectError);
			assert.equal((<SshReconnectError>e).reason, SshReconnectFailureReason.sessionNotFound);
		}
	}

	@test
	public async reconnectWrongHostKey() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();
		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		const newServerSession = new SshServerSession(
			ReconnectTests.testConfig,
			this.reconnectableSessions,
		);

		// Change the host key of the server session to invalidate the reconnect attempt.
		newServerSession.credentials.publicKeys = [
			await SshAlgorithms.publicKey.ecdsaSha2Nistp384!.generateKeyPair(),
		];

		let serverDisconnected = false;
		let serverRequest = false;
		newServerSession.onDisconnected((e) => (serverDisconnected = true));
		newServerSession.onRequest((e) => (serverRequest = true));

		// Reconnect the session using a new pair of streams (and a temporary server session).
		const [newStream1, newStream2] = await DuplexStream.createStreams();
		const newServerStream = new MockNetworkStream(newStream1);
		const newClientStream = new MockNetworkStream(newStream2);
		const serverConnectPromise = newServerSession.connect(newServerStream);
		const reconnectPromise = this.clientSession.reconnect(newClientStream);

		await serverConnectPromise;

		// Reconnection should fail.
		try {
			await reconnectPromise;
			assert(false);
		} catch (e) {
			assert(e instanceof SshReconnectError);
			assert.equal(
				(<SshReconnectError>e).reason,
				SshReconnectFailureReason.differentServerHostKey,
			);
		}
	}

	@test
	public async reconnectWhileStreaming() {
		const [clientStream, serverStream] = await connectSessionPair(
			this.clientSession,
			this.serverSession,
		);
		await this.waitUntilReconnectEnabled();
		const [serverChannel, clientChannel] = await this.initializeChannelPair();

		// Start continuously sending/receiving data with both client and server sessions.
		const sendAndReceiveUntilEnd = async (
			channel: SshChannel,
			cancellation: CancellationToken,
		): Promise<number> => {
			const stream = new SshStream(channel);
			cancellation.onCancellationRequested(() => stream.end());

			let receiveCount = 0;
			const sendBuffer = Buffer.alloc(4);
			let receiveBuffer = Buffer.alloc(0);
			stream.on('data', (data) => (receiveBuffer = Buffer.concat([receiveBuffer, data])));
			const streamErrorPromise = new Promise<void>((_, reject) => stream.once('error', reject));

			while (true) {
				const writer = new SshDataWriter(sendBuffer);
				writer.writeUInt32(receiveCount);
				const readPromise = new Promise<void>((resolve, reject) => {
					if (receiveBuffer.length === 0) {
						stream.once('data', resolve);
					} else {
						resolve();
					}
				});

				let sent = false;
				try {
					await Promise.race([new Promise<void>((resolve, reject) => {
						if (!stream.write(sendBuffer, (e) => (e ? reject(e) : resolve()))) {
							stream.once('drain', resolve);
						}
					}), streamErrorPromise]);
					sent = true;

					await Promise.race([readPromise, streamErrorPromise]);
					const reader = new SshDataReader(receiveBuffer);
					assert.strictEqual(reader.readUInt32(), receiveCount);
					receiveBuffer = receiveBuffer.subarray(4);
				} catch (e) {
					if (cancellation.isCancellationRequested) break;
					channel.session.trace(
						TraceLevel.Warning,
						0,
						`Failed to ${sent ? 'receive' : 'send'} *${receiveCount}: ${e}`,
					);
					throw e;
				}

				receiveCount++;
				await new Promise((c) => setTimeout(c, 0));
			}

			return receiveCount;
		};

		const streamCancellationSource = new CancellationTokenSource();
		const clientStreamPromise = sendAndReceiveUntilEnd(
			clientChannel,
			streamCancellationSource.token,
		);
		const serverStreamPromise = sendAndReceiveUntilEnd(
			serverChannel,
			streamCancellationSource.token,
		);

		// Wait for a few messages to be exchanged.
		await new Promise((c) => setTimeout(c, 100));

		const serverBytesReceivedBeforeReconnect = serverChannel.metrics.bytesReceived;
		const clientBytesReceivedBeforeReconnect = clientChannel.metrics.bytesReceived;
		assert(serverBytesReceivedBeforeReconnect > 0);
		assert(clientBytesReceivedBeforeReconnect > 0);

		// Disconnect and reconnect.
		disconnectSessionPair(clientStream, serverStream);
		await this.clientDisconnectedCompletion.promise;
		await this.serverDisconnectedCompletion.promise;

		await this.doReconnect();

		// Wait for a few more messages to be exchanged.
		await new Promise((c) => setTimeout(c, 100));

		// Verify some messages were received after reconnection.
		assert(serverChannel.metrics.bytesReceived > serverBytesReceivedBeforeReconnect);
		assert(clientChannel.metrics.bytesReceived > clientBytesReceivedBeforeReconnect);

		streamCancellationSource.cancel();
		const clientPacketsReceived = await clientStreamPromise;
		const serverPacketsReceived = await serverStreamPromise;
		assert(clientPacketsReceived > 0);
		assert(serverPacketsReceived > 0);
	}
}
