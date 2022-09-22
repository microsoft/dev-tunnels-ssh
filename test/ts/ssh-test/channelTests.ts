//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout, pending, params } from '@testdeck/mocha';

import {
	KeyPair,
	SshAlgorithms,
	SshClientSession,
	SshServerSession,
	SshChannel,
	SshChannelError,
	SshChannelOpenFailureReason,
	ChannelRequestMessage,
	SshDisconnectReason,
	SshChannelClosedEventArgs,
	CancellationError,
	PromiseCompletionSource,
	SshChannelOpeningEventArgs,
	ChannelOpenMessage,
} from '@microsoft/dev-tunnels-ssh';
import { shutdownWebSocketServer } from './duplexStream';
import {
	createSessionPair,
	connectSessionPair,
	authenticateClient,
	authenticateServer,
} from './sessionPair';
import { CancellationTokenSource } from 'vscode-jsonrpc';
import { withTimeout } from './promiseUtils';

@suite
@slow(3000)
@timeout(20000)
export class ChannelTests {
	private static serverKey: KeyPair;

	@slow(10000)
	@timeout(20000)
	public static async before() {
		ChannelTests.serverKey = await SshAlgorithms.publicKey.ecdsaSha2Nistp384!.generateKeyPair();
	}

	public static async after() {
		shutdownWebSocketServer();
	}

	public static async createSessions(
		useServerExtensions: boolean = true,
		useClientExtensions: boolean = true,
	): Promise<[SshClientSession, SshServerSession]> {
		const [clientSession, serverSession] = await createSessionPair(
			useServerExtensions,
			useClientExtensions,
		);

		authenticateClient(clientSession, serverSession);
		authenticateServer(clientSession, serverSession, ChannelTests.serverKey);

		await connectSessionPair(clientSession, serverSession);

		const authenticated = await clientSession.authenticate({ username: 'test' });
		assert(authenticated);

		return [clientSession, serverSession];
	}

	@test
	public async openAndCloseChannelFromClient() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();

		const serverChannelPromise = serverSession.acceptChannel();

		assert.equal(serverSession.channels.length, 0);
		assert.equal(clientSession.channels.length, 0);

		const clientChannel = await clientSession.openChannel();

		assert(clientChannel);
		assert.equal(clientChannel.channelType, SshChannel.sessionChannelType);

		const serverChannel = await serverChannelPromise;
		assert(serverChannel);
		assert.equal(serverChannel.channelType, SshChannel.sessionChannelType);

		const serverChannelClosePromise = new Promise<void>((resolve, reject) => {
			serverChannel.onClosed(() => resolve());
		});

		assert.equal(serverSession.channels.length, 1);
		assert(Object.is(serverChannel, serverSession.channels[0]));
		assert.equal(clientSession.channels.length, 1);
		assert(Object.is(clientChannel, clientSession.channels[0]));

		await clientChannel.close();

		await serverChannelClosePromise;

		assert.equal(serverSession.channels.length, 0);
		assert.equal(clientSession.channels.length, 0);
	}

	@test
	public async openAndCloseChannelFromServer() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();

		const clientChannelPromise = clientSession.acceptChannel();

		const serverChannel = await serverSession.openChannel();

		assert(serverChannel);
		assert.equal(serverChannel.channelType, SshChannel.sessionChannelType);

		const clientChannel = await clientChannelPromise;
		assert(clientChannel);
		assert.equal(clientChannel.channelType, SshChannel.sessionChannelType);

		const clientChannelClosePromise = new Promise<void>((resolve, reject) => {
			clientChannel.onClosed(() => resolve());
		});

		await serverChannel.close();

		await clientChannelClosePromise;
	}

	@test
	public async openChannelCancelByOpener() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();

		const cancellationSource = new CancellationTokenSource();
		cancellationSource.cancel();

		try {
			await clientSession.openChannel(cancellationSource.token);
		} catch (e) {
			assert(e instanceof CancellationError);
			return;
		}
		assert(false, 'Open channel should have thrown an exception.');
	}

	@test
	public async openChannelCancelByAcceptor() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();

		serverSession.onChannelOpening((e) => {
			e.failureReason = SshChannelOpenFailureReason.connectFailed;
			e.failureDescription = 'test';
		});

		try {
			await clientSession.openChannel();
		} catch (e) {
			assert(e instanceof SshChannelError);
			const channelError = e as SshChannelError;
			assert.equal(channelError.reason, SshChannelOpenFailureReason.connectFailed);
			assert.equal(channelError.message, 'test');
			return;
		}
		assert(false, 'Open channel should have thrown an exception.');
	}

	@params({ serverExtension: false, clientExtension: false })
	@params({ serverExtension: false, clientExtension: true })
	@params({ serverExtension: true, clientExtension: false })
	@params({ serverExtension: true, clientExtension: true })
	@params.naming((params) => 'openChannelWithRequest: ' + JSON.stringify(params))
	public async openChannelWithRequest({
		serverExtension,
		clientExtension,
	}: {
		serverExtension: boolean;
		clientExtension: boolean;
	}) {
		const [clientSession, serverSession] = await ChannelTests.createSessions(
			serverExtension,
			clientExtension,
		);

		let serverRequest: ChannelRequestMessage | null = null;
		serverSession.onChannelOpening((e) => {
			e.channel.onRequest((e) => {
				serverRequest = e.request;
				e.isAuthorized = true;
			});
		});

		const serverChannelTask = serverSession.acceptChannel();

		const testRequestType = 'test';
		const clientRequest = new ChannelRequestMessage();
		clientRequest.requestType = testRequestType;
		clientRequest.wantReply = true;
		const clientChannel = await clientSession.openChannel(null, clientRequest);
		const serverChannel = await serverChannelTask;

		assert(clientChannel);
		assert(serverRequest);
		assert.equal(testRequestType, serverRequest!.requestType);
	}

	@params({ serverExtension: false, clientExtension: false })
	@params({ serverExtension: false, clientExtension: true })
	@params({ serverExtension: true, clientExtension: false })
	@params({ serverExtension: true, clientExtension: true })
	@params.naming((params) => 'openChannelWithRequestFail: ' + JSON.stringify(params))
	public async openChannelWithRequestFail({
		serverExtension,
		clientExtension,
	}: {
		serverExtension: boolean;
		clientExtension: boolean;
	}) {
		const [clientSession, serverSession] = await ChannelTests.createSessions(
			serverExtension,
			clientExtension,
		);

		let serverRequest: ChannelRequestMessage | null = null;
		serverSession.onChannelOpening((e) => {
			e.channel.onRequest((e) => {
				serverRequest = e.request;
				e.isAuthorized = false;
			});
		});

		const serverChannelTask = serverSession.acceptChannel();

		const testRequestType = 'test';
		const clientRequest = new ChannelRequestMessage();
		clientRequest.requestType = testRequestType;
		clientRequest.wantReply = true;

		let openError: Error | null = null;
		try {
			await clientSession.openChannel(null, clientRequest);
		} catch (e) {
			openError = e as Error;
		}
		assert(openError);

		await serverChannelTask;

		assert(serverRequest);
		assert.equal(testRequestType, serverRequest!.requestType);
	}

	@params({ serverExtension: false, clientExtension: false })
	@params({ serverExtension: false, clientExtension: true })
	@params({ serverExtension: true, clientExtension: false })
	@params({ serverExtension: true, clientExtension: true })
	@params.naming((params) => 'openChannelWithRequestNoReply: ' + JSON.stringify(params))
	public async openChannelWithRequestNoReply({
		serverExtension,
		clientExtension,
	}: {
		serverExtension: boolean;
		clientExtension: boolean;
	}) {
		const [clientSession, serverSession] = await ChannelTests.createSessions(
			serverExtension,
			clientExtension,
		);

		let serverRequest: ChannelRequestMessage | null = null;
		serverSession.onChannelOpening((e) => {
			e.channel.onRequest((e) => {
				serverRequest = e.request;
				e.isAuthorized = false; // Will be ignored.
			});
		});

		const serverChannelTask = serverSession.acceptChannel();

		const testRequestType = 'test';
		const clientRequest = new ChannelRequestMessage();
		clientRequest.requestType = testRequestType;
		clientRequest.wantReply = false;
		await clientSession.openChannel(null, clientRequest);
		await serverChannelTask;

		// Wait for the request to be received by the server.
		await new Promise((c) => setImmediate(c));

		assert(serverRequest);
		assert.equal(testRequestType, serverRequest!.requestType);
	}

	@test
	public async openChannelWithRequestUnauthenticated() {
		const [clientSession, serverSession] = await createSessionPair();
		serverSession.credentials.publicKeys.push(ChannelTests.serverKey);
		await connectSessionPair(clientSession, serverSession, undefined, false);

		let requestArgs: SshChannelOpeningEventArgs | null = null;
		serverSession.onChannelOpening((e) => {
			requestArgs = e;
		});

		let error: Error | null = null;
		try {
			await clientSession.openChannel();
		} catch (e) {
			error = e as Error;
		}

		assert(error);
		assert(error instanceof SshChannelError);
		assert.equal(
			(<SshChannelError>error).reason,
			SshChannelOpenFailureReason.administrativelyProhibited,
		);
		assert.equal(requestArgs, null);
	}

	@params({ success: true })
	@params({ success: false })
	@params.naming((params) => 'channelRequest: ' + JSON.stringify(params))
	public async channelRequest({ success }: { success: boolean }) {
		const [clientSession, serverSession] = await ChannelTests.createSessions();

		const serverChannelPromise = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = await serverChannelPromise;

		let serverRequest: ChannelRequestMessage | null = null;
		serverChannel.onRequest((e) => {
			serverRequest = e.request;
			e.isAuthorized = success;
		});

		const testRequestType = 'test';
		const clientRequest = new ChannelRequestMessage();
		clientRequest.requestType = testRequestType;
		clientRequest.wantReply = true;
		const result = await clientChannel.request(clientRequest);

		assert.equal(success, result);
		assert(serverRequest);
		assert.equal(testRequestType, serverRequest!.requestType);
	}

	@test
	public async channelRequestEarlyCancellation() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();

		const cancellationSource = new CancellationTokenSource();
		serverSession.onChannelOpening((ce) => {
			ce.channel.onRequest((e) => {
				e.isAuthorized = true;
			});
		});

		const serverChannelTask = serverSession.acceptChannel();
		let clientChannel = await clientSession.openChannel();
		const clientRequest = new ChannelRequestMessage('test');
		clientRequest.wantReply = false;

		// Cancel the request before it is sent.
		cancellationSource.cancel();
		try {
			await clientChannel.request(clientRequest, cancellationSource.token);
			assert(false, 'Channel request should have been cancelled.');
		} catch (e) {
			assert(e instanceof CancellationError);
		}

		// Open another channel
		clientChannel = await clientSession.openChannel();
		assert(await clientChannel.request(clientRequest));
		assert(!clientSession.isClosed);
		assert(!serverSession.isClosed);
	}

	@test
	public async channelRequestLateCancellation() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();

		const cancellationSource = new CancellationTokenSource();
		serverSession.onChannelOpening((ce) => {
			ce.channel.onRequest((e) => {
				// Cancel the request once it reaches the server.
				cancellationSource.cancel();
				e.isAuthorized = true;
			});
		});

		const serverChannelTask = serverSession.acceptChannel();
		let clientChannel = await clientSession.openChannel();
		const clientRequest = new ChannelRequestMessage('test');
		clientRequest.wantReply = true;

		try {
			await clientChannel.request(clientRequest, cancellationSource.token);
			assert(false, 'Channel request should have been cancelled.');
		} catch (e) {
			assert(e instanceof CancellationError);
		}

		// Open another channel
		clientChannel = await clientSession.openChannel();
		assert(await clientChannel.request(clientRequest));
		assert(!clientSession.isClosed);
		assert(!serverSession.isClosed);
	}

	@test
	public async channelRequestHandlerClosesChannel() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();

		serverSession.onChannelOpening((e) => {
			e.channel.onRequest((ce) => {
				ce.isAuthorized = true;

				if (ce.requestType === 'close') {
					// Close the channel while handling the request.
					e.channel.close();
				}
			});
		});

		const clientChannel = await clientSession.openChannel();

		const closedCompletion = new PromiseCompletionSource<void>();
		clientChannel.onClosed((e) => {
			closedCompletion.resolve();
		});

		// The request should not throw an error if the channel was closed by the request handler.
		const closeRequest = new ChannelRequestMessage();
		closeRequest.requestType = 'close';
		closeRequest.wantReply = true;
		const closeResponse = await clientChannel.request(closeRequest);

		assert(closeResponse);

		// The channel should be closed shortly after receiving the response from the request.
		assert(await closedCompletion);

		// Open another channel and send a request on that channel.
		const clientChannel2 = await clientSession.openChannel();
		const testRequest = new ChannelRequestMessage();
		testRequest.requestType = 'test';
		testRequest.wantReply = true;
		assert(await clientChannel2.request(testRequest));
		assert(!clientSession.isClosed);
		assert(!serverSession.isClosed);
	}

	@params({
		clientWindowSize: SshChannel.defaultMaxWindowSize,
		serverWindowSize: SshChannel.defaultMaxWindowSize,
	})
	@params({
		clientWindowSize: SshChannel.defaultMaxWindowSize,
		serverWindowSize: 5 * SshChannel.defaultMaxWindowSize,
	})
	@params({
		clientWindowSize: 5 * SshChannel.defaultMaxWindowSize,
		serverWindowSize: SshChannel.defaultMaxWindowSize,
	})
	@params.naming(
		(params) => `sendLargeChannelData: ${params.clientWindowSize}-${params.serverWindowSize}`,
	)
	@slow(6000)
	public async sendLargeChannelData({
		clientWindowSize,
		serverWindowSize,
	}: {
		clientWindowSize: number;
		serverWindowSize: number;
	}) {
		const largeDataSize = (1024 * 1024 * 5) / 2;
		const largeData = Buffer.alloc(largeDataSize);
		for (let i = 0; i < largeData.length; i++) largeData[i] = i & 0xff;

		const [clientSession, serverSession] = await ChannelTests.createSessions();

		serverSession.onChannelOpening((e) => {
			e.channel.maxWindowSize = serverWindowSize;
		});

		const openMessage = new ChannelOpenMessage();
		openMessage.channelType = SshChannel.sessionChannelType;
		openMessage.maxWindowSize = clientWindowSize;

		const serverChannelTask = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel(openMessage);
		const serverChannel = await serverChannelTask;

		assert.equal(clientChannel.maxWindowSize, clientWindowSize);
		assert.equal(serverChannel.maxWindowSize, serverWindowSize);

		await ChannelTests.sendDataFromClientToServerChannel(
			[largeData],
			clientChannel,
			serverChannel,
		);

		await clientChannel.close();
		await serverChannel.close();
	}

	@test
	@slow(6000)
	public async sendIncreasingChannelData() {
		// This test is designed to catch bugs related to expanding send/receive buffers.

		const maxDataSize = 4096;
		const data = Buffer.alloc(maxDataSize);
		for (let i = 0; i < data.length; i++) data[i] = i & 0xff;

		const [clientSession, serverSession] = await ChannelTests.createSessions();

		const serverChannelTask = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = await serverChannelTask;

		for (let size = 32; size <= maxDataSize; size += 32) {
			await ChannelTests.sendDataFromClientToServerChannel(
				[data.slice(0, size)],
				clientChannel,
				serverChannel,
			);
		}

		await clientChannel.close();
		await serverChannel.close();
	}

	@test
	@slow(6000)
	public async sendTwoLargeDataWithoutWaiting() {
		const largeData1Size = (1024 * 1024 * 5) / 2;
		const largeData1 = Buffer.alloc(largeData1Size);
		for (let i = 0; i < largeData1Size; i++) largeData1[i] = (i * 2) & 0xff;

		const largeDataSize2 = (1024 * 1024 * 5) / 2;
		const largeData2 = Buffer.alloc(largeDataSize2);
		for (let i = 0; i < largeDataSize2; i++) largeData2[i] = (i * 2 + 1) & 0xff;

		const [clientSession, serverSession] = await ChannelTests.createSessions();
		const serverChannelTask = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = await serverChannelTask;

		const receivedData = Buffer.alloc(largeData1Size + largeDataSize2);
		const eom = new PromiseCompletionSource<void>();
		let offset = 0;
		serverChannel.onDataReceived((data) => {
			data.copy(receivedData, offset);
			offset += data.byteLength;

			serverChannel.adjustWindow(data.length);

			if (offset >= largeData1Size + largeDataSize2) {
				eom.resolve(undefined);
			}
		});

		clientChannel.send(largeData1);
		clientChannel.send(largeData2);

		await eom.promise;

		assert.equal(Buffer.compare(Buffer.concat([largeData1, largeData2]), receivedData), 0);

		await clientChannel.close();
		await serverChannel.close();
	}

	private static async sendDataFromClientToServerChannel(
		data: Buffer[],
		clientChannel: SshChannel,
		serverChannel: SshChannel,
	): Promise<void> {
		let receivingBuffer: Buffer | null = null;
		let receivedCompletion: PromiseCompletionSource<Buffer> | null = null;
		let expectedDataLength = 0;

		const dataReceivedRegistration = serverChannel.onDataReceived(async (received) => {
			receivingBuffer = Buffer.concat([receivingBuffer!, received]);
			if (receivingBuffer.length >= expectedDataLength) {
				receivedCompletion!.resolve(receivingBuffer);
			}

			serverChannel.adjustWindow(received.length);
		});

		for (let i = 0; i < data.length; i++) {
			receivingBuffer = Buffer.alloc(0);
			receivedCompletion = new PromiseCompletionSource<Buffer>();
			expectedDataLength = data[i].length;

			await clientChannel.send(data[i]);

			const receivedData = await receivedCompletion.promise;
			assert.equal(Buffer.compare(data[i], receivedData), 0);
		}

		dataReceivedRegistration.dispose();
	}

	@test
	public async closeSessionClosesChannel() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();
		const clientChannel = await clientSession.openChannel();

		let closedEvent: SshChannelClosedEventArgs | null = null;
		clientChannel.onClosed((e) => {
			closedEvent = e;
		});
		await clientSession.close(SshDisconnectReason.byApplication, 'test');
		assert(closedEvent);
		assert(!closedEvent!.error);
	}

	@test
	public async closeSessionClosesChannelWithException() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();
		const clientChannel = await clientSession.openChannel();

		let closedEvent: SshChannelClosedEventArgs | null = null;
		clientChannel.onClosed((e) => {
			closedEvent = e;
		});
		const closeWithError = new Error('test');
		await clientSession.close(SshDisconnectReason.byApplication, 'test', closeWithError);
		assert(closedEvent);
		assert(Object.is(closeWithError, closedEvent!.error));
	}

	@test
	public async closeServerChannel() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = serverSession.channels[0];
		const closedCompletion = new PromiseCompletionSource<SshChannelClosedEventArgs>();
		clientChannel.onClosed((e) => closedCompletion.resolve(e));
		await serverChannel.close();
		const closedEvent = await closedCompletion.promise;
		assert(closedEvent);
		assert(!closedEvent.exitStatus);
		assert(!closedEvent.exitSignal);
		assert(!closedEvent.error);
	}

	@test
	public async closeClientChannel() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = serverSession.channels[0];
		const closedCompletion = new PromiseCompletionSource<SshChannelClosedEventArgs>();
		serverChannel.onClosed((e) => closedCompletion.resolve(e));
		await clientChannel.close();
		const closedEvent = await closedCompletion.promise;
		assert(closedEvent);
		assert(!closedEvent.exitStatus);
		assert(!closedEvent.exitSignal);
		assert(!closedEvent.error);
	}

	@test
	public async closeChannelWithStatus() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = serverSession.channels[0];
		const closedCompletion = new PromiseCompletionSource<SshChannelClosedEventArgs>();
		clientChannel.onClosed((e) => closedCompletion.resolve(e));
		await serverChannel.close(11);
		const closedEvent = await closedCompletion.promise;
		assert(closedEvent);
		assert.equal(closedEvent.exitStatus, 11);
	}

	@test
	public async closeChannelWithSignal() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = serverSession.channels[0];
		const closedCompletion = new PromiseCompletionSource<SshChannelClosedEventArgs>();
		clientChannel.onClosed((e) => closedCompletion.resolve(e));
		await serverChannel.close('test', 'message');
		const closedEvent = await closedCompletion.promise;
		assert(closedEvent);
		assert.equal(closedEvent.exitSignal, 'test');
		assert.equal(closedEvent.errorMessage, 'message');
	}

	@test
	public async disposeChannelCloses() {
		const serverClosedCompletion = new PromiseCompletionSource<SshChannelClosedEventArgs>();
		const clientClosedCompletion = new PromiseCompletionSource<SshChannelClosedEventArgs>();
		const [clientSession, serverSession] = await ChannelTests.createSessions();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = serverSession.channels[0];
		serverChannel.onClosed((e) => serverClosedCompletion.resolve(e));
		clientChannel.onClosed((e) => clientClosedCompletion.resolve(e));
		serverChannel.dispose();
		await serverClosedCompletion.promise;
		await clientClosedCompletion.promise;
	}

	@test
	public async sendWhileOpening() {
		const [clientSession, serverSession] = await ChannelTests.createSessions();
		serverSession.onChannelOpening((e) => {
			e.channel.send(Buffer.from('test', 'utf8'));
		});

		const clientChannel = await clientSession.openChannel();

		const dataReceivedCompletion = new PromiseCompletionSource<Buffer>();
		clientChannel.onDataReceived((data) => {
			dataReceivedCompletion.resolve(data);
		});
		const receiveResult = await withTimeout(dataReceivedCompletion.promise, 5000);
		assert.equal('test', receiveResult.toString('utf8'));
	}
}
