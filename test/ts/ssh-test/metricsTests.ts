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
	SshDisconnectReason,
	PromiseCompletionSource,
	SshSessionConfiguration,
	SshProtocolExtensionNames,
	SessionContour,
} from '@microsoft/dev-tunnels-ssh';
import {
	createSessionPair,
	connectSessionPair,
	authenticateClient,
	authenticateServer,
} from './sessionPair';
import { SessionMetrics } from 'src/ts/ssh/metrics/sessionMetrics';
import { withTimeout } from './promiseUtils';

@suite
@slow(3000)
@timeout(10000)
export class MetricsTests {
	private static serverKey: KeyPair;

	@slow(10000)
	@timeout(20000)
	public static async before() {
		MetricsTests.serverKey = await SshAlgorithms.publicKey.ecdsaSha2Nistp384!.generateKeyPair();
	}

	public static async createSessions(): Promise<[SshClientSession, SshServerSession]> {
		const config = new SshSessionConfiguration();
		config.protocolExtensions.push(SshProtocolExtensionNames.sessionReconnect);
		config.protocolExtensions.push(SshProtocolExtensionNames.sessionLatency);

		const serverSession = new SshServerSession(config, []);
		const clientSession = new SshClientSession(config);

		authenticateClient(clientSession, serverSession);
		authenticateServer(clientSession, serverSession, MetricsTests.serverKey);

		await connectSessionPair(clientSession, serverSession);

		const authenticated = await clientSession.authenticate({ username: 'test' });
		assert(authenticated);

		return [clientSession, serverSession];
	}

	@test
	public async measureChannelBytes() {
		const [clientSession, serverSession] = await MetricsTests.createSessions();
		const serverChannelTask = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = await serverChannelTask;

		await MetricsTests.sendDataFromClientToServerChannel(
			[Buffer.from('A', 'utf8'), Buffer.from('abc', 'utf8')],
			clientChannel,
			serverChannel,
		);

		assert.equal(clientChannel.metrics.bytesSent, 4);
		assert.equal(clientChannel.metrics.bytesReceived, 0);
		assert.equal(serverChannel.metrics.bytesSent, 0);
		assert.equal(serverChannel.metrics.bytesReceived, 4);
	}

	@test
	public async measureSessionBytes() {
		const [clientSession, serverSession] = await MetricsTests.createSessions();
		const serverChannelTask = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = await serverChannelTask;

		const initialClientBytesSent = clientSession.metrics.bytesSent;
		const initialClientBytesReceived = clientSession.metrics.bytesReceived;
		const initialServerBytesSent = serverSession.metrics.bytesSent;
		const initialServerBytesReceived = serverSession.metrics.bytesReceived;

		assert.notEqual(initialClientBytesSent, 0);
		assert.notEqual(initialClientBytesReceived, 0);
		assert.notEqual(initialServerBytesSent, 0);
		assert.notEqual(initialServerBytesReceived, 0);

		await MetricsTests.sendDataFromClientToServerChannel(
			[Buffer.from('A', 'utf8'), Buffer.from('abc', 'utf8')],
			clientChannel,
			serverChannel,
		);

		assert(clientSession.metrics.bytesSent > initialClientBytesSent);
		assert.equal(clientSession.metrics.bytesReceived, initialClientBytesReceived);
		assert.equal(serverSession.metrics.bytesSent, initialServerBytesSent);
		assert(serverSession.metrics.bytesReceived > initialServerBytesReceived);
	}

	@test
	public async measureSessionMessages() {
		const [clientSession, serverSession] = await MetricsTests.createSessions();
		const serverChannelTask = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = await serverChannelTask;

		const initialClientMessagesSent = clientSession.metrics.messagesSent;
		const initialClientMessagesReceived = clientSession.metrics.messagesReceived;
		const initialServerMessagesSent = serverSession.metrics.messagesSent;
		const initialServerMessagesReceived = serverSession.metrics.messagesReceived;

		assert.notEqual(initialClientMessagesSent, 0);
		assert.notEqual(initialClientMessagesReceived, 0);
		assert.notEqual(initialServerMessagesSent, 0);
		assert.notEqual(initialServerMessagesReceived, 0);

		await MetricsTests.sendDataFromClientToServerChannel(
			[Buffer.from('A', 'utf8'), Buffer.from('abc', 'utf8')],
			clientChannel,
			serverChannel,
		);

		assert(clientSession.metrics.messagesSent > initialClientMessagesSent);
		assert.equal(clientSession.metrics.messagesReceived, initialClientMessagesReceived);
		assert.equal(serverSession.metrics.messagesSent, initialServerMessagesSent);
		assert(serverSession.metrics.messagesReceived > initialServerMessagesReceived);
	}

	@test
	public async measureSessionLatency() {
		const [clientSession, serverSession] = await MetricsTests.createSessions();
		const serverChannelTask = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = await serverChannelTask;

		for (let i = 0; i < 100; i++) {
			await MetricsTests.sendDataFromClientToServerChannel(
				[Buffer.from('abc'.repeat(1000), 'utf8')],
				clientChannel,
				serverChannel,
			);
		}

		function validateLatency(metrics: SessionMetrics): void {
			assert.notEqual(metrics.latencyMinMs, 0);
			assert.notEqual(metrics.latencyAverageMs, 0);
			assert.notEqual(metrics.latencyMaxMs, 0);
			assert.notEqual(metrics.latencyCurrentMs, 0);
			assert(metrics.latencyMinMs <= metrics.latencyAverageMs);
			assert(metrics.latencyAverageMs <= metrics.latencyMaxMs);
		}

		validateLatency(clientSession.metrics);
		validateLatency(serverSession.metrics);
	}

	@test
	public async closedSessionHasNoLatency() {
		const [clientSession, serverSession] = await MetricsTests.createSessions();
		const serverChannelTask = serverSession.acceptChannel();
		await clientSession.openChannel();
		await serverChannelTask;

		await clientSession.close(SshDisconnectReason.byApplication);
		await serverSession.close(SshDisconnectReason.byApplication);

		assert.equal(clientSession.metrics.latencyCurrentMs, 0);
		assert.equal(serverSession.metrics.latencyCurrentMs, 0);
	}

	@test
	@slow(7000)
	public async recordSessionContour() {
		const [clientSession, serverSession] = await MetricsTests.createSessions();

		const clientContour = new SessionContour(256);
		const serverContour = new SessionContour(256);

		const clientContourPromise = clientContour.collectMetrics(clientSession.metrics);
		const serverContourPromise = serverContour.collectMetrics(serverSession.metrics);

		const validateContour = (contour: SessionContour) => {
			// Normally the interval should be 1 second, but tests tests need to work
			// on very slow build machines where the interval could grow larger.
			assert([1000, 2000, 4000].indexOf(contour.interval) >= 0);

			assert.notEqual(contour.intervalCount, 0);
			const sum = (array: readonly number[]) => array.reduce((a, b) => a + b, 0);
			assert.notEqual(sum(contour.latencyMinMs), 0);
			assert.notEqual(sum(contour.latencyMaxMs), 0);
			assert.notEqual(sum(contour.latencyAverageMs), 0);
			assert.notEqual(sum(contour.bytesSent), 0);
			assert.notEqual(sum(contour.bytesReceived), 0);

			for (let i = 0; i < contour.intervalCount; i++) {
				assert(contour.latencyMinMs[i] <= contour.latencyAverageMs[i]);
				assert(contour.latencyAverageMs[i] <= contour.latencyMaxMs[i]);
			}
		};

		const serverChannelTask = serverSession.acceptChannel();
		const clientChannel = await clientSession.openChannel();
		const serverChannel = await serverChannelTask;

		await new Promise((c) => setTimeout(c, 1000));
		const data = [Buffer.from('A', 'utf8')];
		await MetricsTests.sendDataFromClientToServerChannel(data, clientChannel, serverChannel);
		await MetricsTests.sendDataFromClientToServerChannel(data, serverChannel, clientChannel);
		await new Promise((c) => setTimeout(c, 1000));
		await MetricsTests.sendDataFromClientToServerChannel(data, clientChannel, serverChannel);
		await MetricsTests.sendDataFromClientToServerChannel(data, serverChannel, clientChannel);
		await new Promise((c) => setTimeout(c, 1000));
		await MetricsTests.sendDataFromClientToServerChannel(data, clientChannel, serverChannel);
		await MetricsTests.sendDataFromClientToServerChannel(data, serverChannel, clientChannel);

		await MetricsTests.waitForContourUpdate(clientContour, clientContourPromise);
		await MetricsTests.waitForContourUpdate(serverContour, serverContourPromise);

		validateContour(clientContour);
		validateContour(serverContour);
	}

	@test
	public async expandContourIntervals() {
		const session = new SshClientSession(new SshSessionConfiguration());
		const metrics = session.metrics;

		const sessionContour = new SessionContour(4);
		let updatePromise = sessionContour.collectMetrics(metrics);
		MetricsTests.addMessageReceived(sessionContour, 2000, 2);
		MetricsTests.updateLatency(sessionContour, 3000, 16);
		MetricsTests.updateLatency(sessionContour, 3500, 32);
		MetricsTests.addMessageSent(sessionContour, 3800, 1);
		MetricsTests.addMessageReceived(sessionContour, 3900, 3);
		await MetricsTests.waitForContourUpdate(sessionContour, updatePromise);
		assert.equal(sessionContour.interval, 1000);
		assert.deepEqual(sessionContour.latencyMinMs, [0, 0, 0, 16]);
		assert.deepEqual(sessionContour.latencyMaxMs, [0, 0, 0, 32]);
		assert.deepEqual(sessionContour.latencyAverageMs, [0, 0, 0, 24]);
		assert.deepEqual(sessionContour.bytesSent, [0, 0, 0, 1]);
		assert.deepEqual(sessionContour.bytesReceived, [0, 0, 2, 3]);
		updatePromise = sessionContour.collectMetrics(metrics);
		MetricsTests.addMessageSent(sessionContour, 4000, 1);
		MetricsTests.updateLatency(sessionContour, 4500, 32);
		MetricsTests.updateLatency(sessionContour, 4600, 16);
		await MetricsTests.waitForContourUpdate(sessionContour, updatePromise);
		assert.equal(sessionContour.interval, 2000);
		assert.deepEqual(sessionContour.latencyMinMs, [0, 16, 16]);
		assert.deepEqual(sessionContour.latencyMaxMs, [0, 32, 32]);
		assert.deepEqual(sessionContour.latencyAverageMs, [0, 24, 24]);
		assert.deepEqual(sessionContour.bytesSent, [0, 1, 1]);
		assert.deepEqual(sessionContour.bytesReceived, [0, 5, 0]);
		updatePromise = sessionContour.collectMetrics(metrics);
		MetricsTests.addMessageSent(sessionContour, 8000, 1);
		MetricsTests.updateLatency(sessionContour, 8100, 32);
		MetricsTests.addMessageSent(sessionContour, 12000, 2);
		MetricsTests.updateLatency(sessionContour, 12500, 64);
		await MetricsTests.waitForContourUpdate(sessionContour, updatePromise);
		assert.equal(sessionContour.interval, 4000);
		assert.deepEqual(sessionContour.latencyMinMs, [16, 16, 32, 64]);
		assert.deepEqual(sessionContour.latencyMaxMs, [32, 32, 32, 64]);
		assert.deepEqual(sessionContour.latencyAverageMs, [24, 24, 32, 64]);
		assert.deepEqual(sessionContour.bytesSent, [1, 1, 1, 2]);
		assert.deepEqual(sessionContour.bytesReceived, [5, 0, 0, 0]);
		updatePromise = sessionContour.collectMetrics(metrics);
		MetricsTests.addMessageSent(sessionContour, 16000, 10);
		await MetricsTests.waitForContourUpdate(sessionContour, updatePromise);
		assert.equal(sessionContour.interval, 8000);
		assert.deepEqual(sessionContour.latencyMinMs, [16, 32, 0]);
		assert.deepEqual(sessionContour.latencyMaxMs, [32, 64, 0]);
		assert.deepEqual(sessionContour.latencyAverageMs, [24, 48, 0]);
		assert.deepEqual(sessionContour.bytesSent, [2, 3, 10]);
		assert.deepEqual(sessionContour.bytesReceived, [5, 0, 0]);
	}

	@test
	public async exportImportContour() {
		const session = new SshClientSession(new SshSessionConfiguration());
		const metrics = session.metrics;

		const sessionContour = new SessionContour(4);
		let updatePromise = sessionContour.collectMetrics(metrics);
		MetricsTests.addMessageReceived(sessionContour, 0, 2000);
		MetricsTests.updateLatency(sessionContour, 2000, 16);
		MetricsTests.updateLatency(sessionContour, 3000, 32);
		MetricsTests.addMessageSent(sessionContour, 3600, 1000);
		MetricsTests.addMessageReceived(sessionContour, 3800, 3000);
		MetricsTests.addMessageSent(sessionContour, 4800, 1);
		MetricsTests.updateLatency(sessionContour, 5000, 32);
		MetricsTests.updateLatency(sessionContour, 5200, 16);
		await MetricsTests.waitForContourUpdate(sessionContour, updatePromise);
		assert.equal(sessionContour.interval, 2000);

		const result = sessionContour.export();
		const resultBytes = Array.from(Buffer.from(result, 'base64'));

		assert.deepEqual(resultBytes, [
			1, // version
			5, // metric count
			1, // timeScale
			0, // \
			0, //  \
			0, //   } value scales
			2, //  /
			4, // /
			1, // \
			2, //  \
			3, //   } metric IDs
			11, //  /
			12, // /
			0, // \
			0, //  \
			0, //   } interval 0
			0, //  /
			125, // /
			16, // \
			32, //  \
			24, //   } interval 1
			250, //  /
			188, // /
			16, // \
			32, //  \
			24, //   } interval 2
			0, //  /
			0, // /
		]);

		const sessionContour2 = SessionContour.import(result);
		assert.equal(sessionContour2.intervalCount, 3);
		assert.equal(2000, sessionContour2.interval);

		const result2 = sessionContour2.export();
		const result2Bytes = Array.from(Buffer.from(result2, 'base64'));
		assert.deepEqual(result2Bytes, resultBytes);
	}

	private static addMessageSent(sessionContour: SessionContour, time: number, size: number): void {
		(<any>sessionContour).onMessageSent({ time, size });
	}

	private static addMessageReceived(
		sessionContour: SessionContour,
		time: number,
		size: number,
	): void {
		(<any>sessionContour).onMessageReceived({ time, size });
	}

	private static updateLatency(
		sessionContour: SessionContour,
		time: number,
		latency: number,
	): void {
		(<any>sessionContour).onLatencyUpdated({ time, latency });
	}

	private static async waitForContourUpdate(
		sessionContour: SessionContour,
		p: Promise<void>,
	): Promise<void> {
		(<any>sessionContour).onSessionClosed();
		await withTimeout(p, 5000);
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
}
