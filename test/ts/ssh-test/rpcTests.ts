//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, params, slow, timeout, pending } from '@testdeck/mocha';

import {
	SshChannel,
	SshRpcMessageStream,
	SshChannelClosedEventArgs,
} from '@microsoft/dev-tunnels-ssh';
import {
	Emitter,
	Message,
	createMessageConnection,
	ConnectionError,
	ConnectionErrors,
} from 'vscode-jsonrpc';
import { ChannelTests } from './channelTests';

function formatJsonRpc(message: Message): string {
	const messageJson = JSON.stringify(message);
	const messageLength = messageJson.length;
	return `Content-Length: ${messageLength}\r\n\r\n${messageJson}`;
}

@suite
export class RpcTests {
	@slow(10000)
	@timeout(20000)
	public static async before() {
		await ChannelTests.before();
	}

	private static createMockChannel(
		dataReceivedEmitter?: Emitter<Buffer>,
		closedEmitter?: Emitter<SshChannelClosedEventArgs>,
	): SshChannel {
		return <SshChannel>(<any>{
			onDataReceived: dataReceivedEmitter?.event ?? ((data) => {}),
			onClosed: closedEmitter?.event ?? ((e) => {}),
			adjustWindow: (size: number) => {},
		});
	}

	@test
	public async readOneMessage() {
		const mockDataReceivedEmitter = new Emitter<Buffer>();
		const mockChannel = RpcTests.createMockChannel(mockDataReceivedEmitter);

		const messageStream = new SshRpcMessageStream(mockChannel);
		let receivedMessages: Message[] = [];
		messageStream.reader.listen((message) => {
			receivedMessages.push(message);
		});
		const testMessage = { jsonrpc: '2.0', test: 1 };
		mockDataReceivedEmitter.fire(Buffer.from(formatJsonRpc(testMessage)));
		assert.equal(receivedMessages.length, 1);
		assert.equal((<any>receivedMessages[0]).test, 1);
	}

	@test
	public async readSecondMessage() {
		const mockDataReceivedEmitter = new Emitter<Buffer>();
		const mockChannel = RpcTests.createMockChannel(mockDataReceivedEmitter);

		const messageStream = new SshRpcMessageStream(mockChannel);
		let receivedMessages: Message[] = [];
		messageStream.reader.listen((message) => {
			receivedMessages.push(message);
		});
		const testMessage1 = { jsonrpc: '2.0', test: 1 };
		const testMessage2 = { jsonrpc: '2.0', test: 2 };
		mockDataReceivedEmitter.fire(
			Buffer.from(formatJsonRpc(testMessage1) + formatJsonRpc(testMessage2)),
		);
		assert.equal(receivedMessages.length, 2);
		assert.equal((<any>receivedMessages[0]).test, 1);
		assert.equal((<any>receivedMessages[1]).test, 2);
	}

	@test
	public async readBrokenMessage() {
		const mockDataReceivedEmitter = new Emitter<Buffer>();
		const mockChannel = RpcTests.createMockChannel(mockDataReceivedEmitter);

		const messageStream = new SshRpcMessageStream(mockChannel);
		let receivedMessages: Message[] = [];
		messageStream.reader.listen((message) => {
			receivedMessages.push(message);
		});
		const testMessage = { jsonrpc: '2.0', test: 1 };
		const messageBuffer = Buffer.from(formatJsonRpc(testMessage));
		mockDataReceivedEmitter.fire(messageBuffer.slice(0, 5));
		mockDataReceivedEmitter.fire(messageBuffer.slice(5));
		assert.equal(receivedMessages.length, 1);
		assert.equal((<any>receivedMessages[0]).test, 1);
	}

	@test
	public async readBrokenSecondMessage() {
		const mockDataReceivedEmitter = new Emitter<Buffer>();
		const mockChannel = RpcTests.createMockChannel(mockDataReceivedEmitter);

		const messageStream = new SshRpcMessageStream(mockChannel);
		let receivedMessages: Message[] = [];
		messageStream.reader.listen((message) => {
			receivedMessages.push(message);
		});
		const testMessage1 = { jsonrpc: '2.0', test: 1 };
		const testMessage2 = { jsonrpc: '2.0', test: 2 };
		const messageBuffer = Buffer.from(formatJsonRpc(testMessage1) + formatJsonRpc(testMessage2));
		const breakAtOffset = formatJsonRpc(testMessage1).length + 5;
		mockDataReceivedEmitter.fire(messageBuffer.slice(0, breakAtOffset));
		mockDataReceivedEmitter.fire(messageBuffer.slice(breakAtOffset));
		assert.equal(receivedMessages.length, 2);
		assert.equal((<any>receivedMessages[0]).test, 1);
		assert.equal((<any>receivedMessages[1]).test, 2);
	}

	@test
	public async readBrokenThirdMessage() {
		const mockDataReceivedEmitter = new Emitter<Buffer>();
		const mockChannel = RpcTests.createMockChannel(mockDataReceivedEmitter);

		const messageStream = new SshRpcMessageStream(mockChannel);
		let receivedMessages: Message[] = [];
		messageStream.reader.listen((message) => {
			receivedMessages.push(message);
		});
		const testMessage1 = { jsonrpc: '2.0', test: 1 };
		const testMessage2 = { jsonrpc: '2.0', test: 2 };
		const testMessage3 = { jsonrpc: '2.0', test: 3, value: 'test' };
		const messageBuffer = Buffer.from(
			formatJsonRpc(testMessage1) + formatJsonRpc(testMessage2) + formatJsonRpc(testMessage3),
		);
		const breakAtOffset1 = formatJsonRpc(testMessage1).length - 5;
		const breakAtOffset2 = formatJsonRpc(testMessage1).length + 25;
		mockDataReceivedEmitter.fire(messageBuffer.slice(0, breakAtOffset1));
		mockDataReceivedEmitter.fire(messageBuffer.slice(breakAtOffset1, breakAtOffset2));
		mockDataReceivedEmitter.fire(messageBuffer.slice(breakAtOffset2));
		assert.equal(receivedMessages.length, 3);
		assert.equal((<any>receivedMessages[0]).test, 1);
		assert.equal((<any>receivedMessages[1]).test, 2);
		assert.equal((<any>receivedMessages[2]).test, 3);
	}

	@test
	public async propagateCloseEvent() {
		const mockCloseEmitter = new Emitter<SshChannelClosedEventArgs>();
		const mockChannel = RpcTests.createMockChannel(undefined, mockCloseEmitter);

		let writerClosed = false;
		let readerClosed = false;

		const messageStream = new SshRpcMessageStream(mockChannel);
		messageStream.writer.onClose(() => {
			writerClosed = true;
		});
		messageStream.reader.onClose(() => {
			readerClosed = true;
		});
		mockCloseEmitter.fire({});

		assert.ok(writerClosed);
		assert.ok(readerClosed);
	}

	@test
	public async propagateErrorEvent() {
		const mockErrorEmitter = new Emitter<SshChannelClosedEventArgs>();
		const mockChannel = <SshChannel>(<any>{
			onDataReceived: () => {},
			onClosed: mockErrorEmitter.event,
		});

		let writerError: Error | undefined;
		let readerError: Error | undefined;
		let writerClosed = false;
		let readerClosed = false;
		let rpcIsClosed = false;
		const messageStream = new SshRpcMessageStream(mockChannel);

		const rpcConnection = createMessageConnection(messageStream.reader, messageStream.writer);
		rpcConnection.listen();

		rpcConnection.onClose(() => {
			rpcIsClosed = true;
		});

		messageStream.writer.onError((event) => {
			writerError = event[0];
		});
		messageStream.reader.onError((event) => {
			readerError = event;
		});
		messageStream.writer.onClose(() => {
			writerClosed = true;
		});
		messageStream.reader.onClose(() => {
			readerClosed = true;
		});
		const errorMessage = 'Test error propagation';
		mockErrorEmitter.fire({ error: new Error(errorMessage) });

		assert.ok(writerError);
		assert.equal(writerError!.message, errorMessage);
		assert.ok(readerError);
		assert.equal(readerError!.message, errorMessage);
		assert.ok(writerClosed);
		assert.ok(readerClosed);
		assert.ok(rpcIsClosed);

		// The rpc connection should throw a dispose
		assert.throws(
			() => rpcConnection.sendRequest('service1.method1'),
			(e: Error) => e instanceof ConnectionError && e.code == ConnectionErrors.Closed,
		);
	}

	@slow(5000)
	@timeout(30000)
	@params({ size: 1, count: 1 })
	@params({ size: 1, count: 100 })
	@params({ size: 1, count: 50000 })
	@params({ size: 20000, count: 1 })
	@params({ size: 20000, count: 100 })
	@params({ size: 2000000, count: 1 })
	@params.naming((params) => 'readFromChannel: ' + JSON.stringify(params))
	public async readFromChannel({ size, count }: { size: number; count: number }) {
		const [clientSession, serverSession] = await ChannelTests.createSessions();
		const serverChannelTask = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = await serverChannelTask;

		const clientMessageStream = new SshRpcMessageStream(clientChannel);
		const serverMessageStream = new SshRpcMessageStream(serverChannel);

		let receivedMessages: Message[] = [];
		clientMessageStream.reader.listen((message) => {
			receivedMessages.push(message);
		});

		for (let i = 0; i < count; i++) {
			const testMessage = { jsonrpc: '2.0', test: '#'.repeat(size) };
			serverMessageStream.writer.write(testMessage);

			for (let w = 0; w < 100 && receivedMessages.length < i + 1; w++) {
				await new Promise((c) => setImmediate(c));
			}

			assert.equal(receivedMessages.length, i + 1);
			assert.equal((<any>receivedMessages[i]).test, testMessage.test);
		}
	}
}
