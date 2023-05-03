//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import * as net from 'net';
import { suite, test, params, pending, slow, timeout } from '@testdeck/mocha';

import {
	ChannelOpenMessage,
	ChannelRequestMessage,
	PromiseCompletionSource,
	SessionRequestFailureMessage,
	SessionRequestMessage,
	SessionRequestSuccessMessage,
	SshAlgorithms,
	SshChannel,
	SshChannelClosedEventArgs,
	SshChannelError,
	SshChannelOpenFailureReason,
	SshClientSession,
	SshDataReader,
	SshDataWriter,
	SshDisconnectReason,
	SshServerSession,
	SshSessionClosedEventArgs,
} from '@microsoft/dev-tunnels-ssh';
import { connectSessionPair, createSessionPair, openChannel } from './sessionPair';
import { expectError, until, withTimeout } from './promiseUtils';

const timeoutMs = 5000;

class TestSessionRequestMessage extends SessionRequestMessage {
	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);
		writer.writeUInt32(1);
	}

	protected onRead(reader: SshDataReader) {
		super.onRead(reader);
		assert.equal(1, reader.readUInt32());
	}
}

class TestSessionRequestSuccessMessage extends SessionRequestSuccessMessage {
	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);
		writer.writeUInt32(1);
	}

	protected onRead(reader: SshDataReader) {
		super.onRead(reader);
		assert.equal(1, reader.readUInt32());
	}
}

class TestChannelOpenMessage extends ChannelOpenMessage {
	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);
		writer.writeUInt32(1);
	}

	protected onRead(reader: SshDataReader) {
		super.onRead(reader);
		assert.equal(1, reader.readUInt32());
	}
}

class TestChannelRequestMessage extends ChannelRequestMessage {
	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);
		writer.writeUInt32(1);
	}

	protected onRead(reader: SshDataReader) {
		super.onRead(reader);
		assert.equal(1, reader.readUInt32());
	}
}

@suite
@slow(4000)
@timeout(2 * timeoutMs)
export class PipeTests {
	private clientSession1!: SshClientSession;
	private serverSession1!: SshServerSession;
	private clientSession2!: SshClientSession;
	private serverSession2!: SshServerSession;

	public after(): void {
		this.clientSession1?.dispose();
		this.serverSession1?.dispose();
		this.clientSession2?.dispose();
		this.serverSession2?.dispose();
	}

	private async createSessions(): Promise<void> {
		[this.clientSession1, this.serverSession1] = await createSessionPair();
		[this.clientSession2, this.serverSession2] = await createSessionPair();

		const serverKey = await SshAlgorithms.publicKey.ecdsaSha2Nistp384!.generateKeyPair();
		this.serverSession1.credentials.publicKeys = [serverKey];
		this.serverSession2.credentials.publicKeys = [serverKey];
	}

	@test
	@params({ closeTarget: true })
	@params({ closeTarget: false })
	@params.naming((p) => `pipeChannelClose(closeTarget=${p.closeTarget})`)
	public async pipeChannelClose({ closeTarget }: { closeTarget: boolean }): Promise<void> {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const [clientChannel1, serverChannel1] = await openChannel(
			this.clientSession1,
			this.serverSession1,
		);
		const [clientChannel2, serverChannel2] = await openChannel(
			this.clientSession2,
			this.serverSession2,
		);
		const pipePromise = serverChannel1.pipe(serverChannel2);

		const closedCompletion = new PromiseCompletionSource<SshChannelClosedEventArgs>();
		(closeTarget ? clientChannel1 : clientChannel2).onClosed((e) => {
			closedCompletion.resolve(e);
		});
		await (closeTarget ? clientChannel2 : clientChannel1).close();
		await withTimeout(closedCompletion.promise, timeoutMs);
		await withTimeout(pipePromise, timeoutMs);
	}

	@test
	@params({ fromTarget: true })
	@params({ fromTarget: false })
	@params.naming((p) => `pipeChannelSend(fromTarget=${p.fromTarget})`)
	public async pipeChannelSend({ fromTarget }: { fromTarget: boolean }): Promise<void> {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const [clientChannel1, serverChannel1] = await openChannel(
			this.clientSession1,
			this.serverSession1,
		);
		const [clientChannel2, serverChannel2] = await openChannel(
			this.clientSession2,
			this.serverSession2,
		);
		const pipePromise = serverChannel1.pipe(serverChannel2);

		const testData = Buffer.from('test', 'utf8');
		const dataCompletion = new PromiseCompletionSource<Buffer>();
		(fromTarget ? clientChannel1 : clientChannel2).onDataReceived((data) => {
			dataCompletion.resolve(data);
		});
		await (fromTarget ? clientChannel2 : clientChannel1).send(testData);
		const receivedData = await withTimeout(dataCompletion.promise, timeoutMs);
		assert(receivedData.equals(testData));
	}

	@test
	@params({ fromTarget: true })
	@params({ fromTarget: false })
	@params.naming((p) => `pipeChannelSendSequence(fromTarget=${p.fromTarget})`)
	public async pipeChannelSendSequence({ fromTarget }: { fromTarget: boolean }): Promise<void> {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const [clientChannel1, serverChannel1] = await openChannel(
			this.clientSession1,
			this.serverSession1,
		);
		const [clientChannel2, serverChannel2] = await openChannel(
			this.clientSession2,
			this.serverSession2,
		);
		const pipePromise = serverChannel1.pipe(serverChannel2);

		const count = 1000;
		const receivedCompletion = new PromiseCompletionSource<void>();
		let receivedCount = 0;
		(fromTarget ? clientChannel1 : clientChannel2).onDataReceived((data) => {
			const expectedData = Buffer.from('test:' + receivedCount, 'utf8');
			assert(data.equals(expectedData));
			if (++receivedCount === count) {
				receivedCompletion.resolve();
			}
			(fromTarget ? clientChannel1 : clientChannel2).adjustWindow(data.length);
		});

		for (let i = 0; i < count; i++) {
			const testData = Buffer.from('test:' + i, 'utf8');
			const _ = (fromTarget ? clientChannel2 : clientChannel1).send(testData);
		}

		await withTimeout(receivedCompletion.promise, timeoutMs);
	}

	@test
	@params({ fromTarget: true })
	@params({ fromTarget: false })
	@params.naming((p) => `pipeChannelSendLargeData(fromTarget=${p.fromTarget})`)
	public async pipeChannelSendLargeData({ fromTarget }: { fromTarget: boolean }): Promise<void> {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const [clientChannel1, serverChannel1] = await openChannel(
			this.clientSession1,
			this.serverSession1,
		);
		const [clientChannel2, serverChannel2] = await openChannel(
			this.clientSession2,
			this.serverSession2,
		);
		const pipePromise = serverChannel1.pipe(serverChannel2);

		// Test data that is larger than the channel flow-control window size (1MB).
		const largeDataSize = (1024 * 1024 * 7) / 2;
		const largeData = Buffer.alloc(largeDataSize);
		for (let i = 0; i < largeData.length; i++) largeData[i] = i & 0xff;

		let receivingBuffer = Buffer.alloc(0);
		const receivedCompletion = new PromiseCompletionSource<Buffer>();

		(fromTarget ? clientChannel1 : clientChannel2).onDataReceived((data) => {
			receivingBuffer = Buffer.concat([receivingBuffer, data]);
			if (receivingBuffer.length >= largeDataSize) {
				receivedCompletion.resolve(receivingBuffer);
			}

			(fromTarget ? clientChannel1 : clientChannel2).adjustWindow(data.length);
		});

		await (fromTarget ? clientChannel2 : clientChannel1).send(largeData);
		const receivedData = await withTimeout(receivedCompletion.promise, timeoutMs);
		assert(receivedData.equals(largeData));
	}

	@test
	@params({ closeTarget: true })
	@params({ closeTarget: false })
	@params.naming((p) => `pipeSessionClose(closeTarget=${p.closeTarget})`)
	public async pipeSessionClose({ closeTarget }: { closeTarget: boolean }): Promise<void> {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const pipePromise = this.serverSession1.pipe(this.serverSession2);

		const closedCompletion = new PromiseCompletionSource<SshSessionClosedEventArgs>();
		(closeTarget ? this.clientSession1 : this.clientSession2).onClosed((e) => {
			closedCompletion.resolve(e);
		});
		await (closeTarget ? this.clientSession2 : this.clientSession1).close(
			SshDisconnectReason.byApplication,
		);

		const closedEvent = await withTimeout(closedCompletion.promise, timeoutMs);
		assert.equal(SshDisconnectReason.byApplication, closedEvent.reason);
		await withTimeout(pipePromise, timeoutMs);
	}

	@test
	@params({ fromTarget: true })
	@params({ fromTarget: false })
	@params.naming((p) => `pipeSessionChannelOpen(fromTarget=${p.fromTarget})`)
	public async pipeSessionChannelOpen({ fromTarget }: { fromTarget: boolean }): Promise<void> {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const pipePromise = this.serverSession1.pipe(this.serverSession2);

		const channelPromise = (fromTarget ? this.clientSession1 : this.clientSession2).acceptChannel(
			'test',
		);
		await (fromTarget ? this.clientSession2 : this.clientSession1).openChannel('test');
		const channel = await withTimeout(channelPromise, timeoutMs);
		assert.equal('test', channel.channelType);
	}

	@test
	@params({ fromTarget: true })
	@params({ fromTarget: false })
	@params.naming((p) => `pipeSessionChannelOpenAndClose(fromTarget=${p.fromTarget})`)
	public async pipeSessionChannelOpenAndClose({
		fromTarget,
	}: {
		fromTarget: boolean;
	}): Promise<void> {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const pipePromise = this.serverSession1.pipe(this.serverSession2);

		const channelPromise = (fromTarget ? this.clientSession1 : this.clientSession2).acceptChannel(
			'test',
		);
		const channelA = await (fromTarget ? this.clientSession2 : this.clientSession1).openChannel(
			'test',
		);
		const channelB = await withTimeout(channelPromise, timeoutMs);

		const closedCompletion = new PromiseCompletionSource<SshChannelClosedEventArgs>();
		(fromTarget ? channelA : channelB).onClosed((e) => {
			closedCompletion.resolve(e);
		});
		await (fromTarget ? channelB : channelA).close();
		await withTimeout(closedCompletion.promise, timeoutMs);
	}

	@test
	@params({ fromTarget: true })
	@params({ fromTarget: false })
	@params.naming((p) => `pipeSessionChannelSend(fromTarget=${p.fromTarget})`)
	public async pipeSessionChannelSend({ fromTarget }: { fromTarget: boolean }): Promise<void> {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const pipePromise = this.serverSession1.pipe(this.serverSession2);

		const channelPromise = (fromTarget ? this.clientSession1 : this.clientSession2).acceptChannel(
			'test',
		);
		const channelA = await (fromTarget ? this.clientSession2 : this.clientSession1).openChannel(
			'test',
		);
		const channelB = await withTimeout(channelPromise, timeoutMs);

		const testData = Buffer.from('test', 'utf8');
		const dataCompletion = new PromiseCompletionSource<Buffer>();
		(fromTarget ? channelA : channelB).onDataReceived((data) => {
			dataCompletion.resolve(data);
		});
		await (fromTarget ? channelB : channelA).send(testData);
		const receivedData = await withTimeout(dataCompletion.promise, timeoutMs);
		assert(receivedData.equals(testData));
	}

	@test
	public async pipeExtensibleSessionRequest() {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const pipePromise = this.serverSession1.pipe(this.serverSession2);

		const requestCompletion = new PromiseCompletionSource<SessionRequestMessage>();
		this.clientSession2.onRequest((e) => {
			requestCompletion.resolve(e.request);
			e.responsePromise = Promise.resolve(new TestSessionRequestSuccessMessage());
		});

		const request = new TestSessionRequestMessage();
		request.requestType = 'test';
		const requestTask = this.clientSession1.requestResponse(
			request,
			TestSessionRequestSuccessMessage,
			SessionRequestFailureMessage,
		);

		const testRequest = await withTimeout(requestCompletion.promise, timeoutMs);
		assert.equal('test', testRequest.requestType);
		testRequest.convertTo(new TestSessionRequestMessage());

		const testResponse = await requestTask;
		assert(testResponse);
	}

	@test
	public async pipeExtensibleSessionMultipleRequestNoReply() {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const pipePromise = this.serverSession1.pipe(this.clientSession2);

		for (let i = 0; i < 3; i++) {
			const requestCompletion = new PromiseCompletionSource<SessionRequestMessage>();
			const toDispose = this.clientSession1.onRequest((e) => {
				requestCompletion.resolve(e.request);
				e.isAuthorized = true;
			});

			const request = new TestSessionRequestMessage();
			request.requestType = 'test';
			const requestTask = this.serverSession2.request(
				request
			);

			const testRequest = await withTimeout(requestCompletion.promise, timeoutMs);
			assert.equal('test', testRequest.requestType);
			testRequest.convertTo(new TestSessionRequestMessage());

			const testResponse = await requestTask;
			assert(testResponse);

			toDispose.dispose();
		}
	}

	@test
	public async pipeExtensibleChannelOpen() {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);
		const pipePromise = this.serverSession1.pipe(this.serverSession2);

		const requestCompletion = new PromiseCompletionSource<ChannelOpenMessage>();
		const channelCompletion = new PromiseCompletionSource<SshChannel>();
		this.clientSession2.onChannelOpening((e) => {
			requestCompletion.resolve(e.request);
			channelCompletion.resolve(e.channel);
		});

		const openMessage = new TestChannelOpenMessage();
		openMessage.channelType = 'test';
		const openPromise = this.clientSession1.openChannel(openMessage);

		const testRequest = await withTimeout(requestCompletion.promise, timeoutMs);
		testRequest.convertTo(new TestChannelOpenMessage());

		const channel1 = await withTimeout(openPromise, timeoutMs);
		assert.equal(channel1.channelType, 'test');

		const channel2 = await withTimeout(channelCompletion.promise, timeoutMs);
		assert.equal(channel2.channelType, 'test');
	}

	@test
	@params({ withChannelIdMapping: false })
	@params({ withChannelIdMapping: true })
	@params.naming(
		(p) => `pipeExtensibleChannelRequest(withChannelIdMapping=${p.withChannelIdMapping})`,
	)
	public async pipeExtensibleChannelRequest({
		withChannelIdMapping,
	}: {
		withChannelIdMapping: boolean;
	}) {
		await this.createSessions();
		await connectSessionPair(this.clientSession1, this.serverSession1);
		await connectSessionPair(this.clientSession2, this.serverSession2);

		if (withChannelIdMapping) {
			// Open a channel BEFORE piping, so that the channel IDs will not be in sync.
			// Channel piping should support re-mapping channel IDs.
			const _ = await this.clientSession1.openChannel();
		}

		const pipePromise = this.serverSession1.pipe(this.serverSession2);

		const acceptPromise = this.clientSession2.acceptChannel('test');
		const channel1 = await withTimeout(this.clientSession1.openChannel('test'), timeoutMs);
		const channel2 = await withTimeout(acceptPromise, timeoutMs);

		const requestCompletion = new PromiseCompletionSource<ChannelRequestMessage>();
		channel2.onRequest((e) => {
			requestCompletion.resolve(e.request);
			e.isAuthorized = true;
		});

		const requestMessage = new TestChannelRequestMessage();
		requestMessage.requestType = 'test';
		const requestPromise = channel1.request(requestMessage);

		const request = await withTimeout(requestCompletion.promise, timeoutMs);
		assert.equal(request.requestType, 'test');
		request.convertTo(new TestChannelRequestMessage());

		const result = await withTimeout(requestPromise, timeoutMs);
		assert(result);
	}
}
