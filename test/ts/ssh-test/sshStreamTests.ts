//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout } from '@testdeck/mocha';

import {
	KeyPair,
	SshAlgorithms,
	SshClientSession,
	SshServerSession,
	SshStream,
	PromiseCompletionSource,
} from '@microsoft/dev-tunnels-ssh';
import { shutdownWebSocketServer } from './duplexStream';
import {
	createSessionPair,
	connectSessionPair,
	authenticateClient,
	authenticateServer,
} from './sessionPair';

@suite
@slow(3000)
@timeout(20000)
export class SshStreamTests {
	private static serverKey: KeyPair;

	@slow(10000)
	@timeout(20000)
	public static async before() {
		SshStreamTests.serverKey = await SshAlgorithms.publicKey.rsaWithSha512!.generateKeyPair();
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
		authenticateServer(clientSession, serverSession, SshStreamTests.serverKey);

		await connectSessionPair(clientSession, serverSession);

		const authenticated = await clientSession.authenticate({ username: 'test' });
		assert(authenticated);

		return [clientSession, serverSession];
	}

	@test
	public async oneSide() {
		const chunks = ['abc', 'def'].map((v) => Buffer.from(v, 'utf8'));

		const [clientSession, serverSession] = await SshStreamTests.createSessions();
		const channels = await Promise.all([
			clientSession.acceptChannel(),
			serverSession.openChannel(),
		]);
		const clientChannel = new SshStream(channels[0]);
		const serverChannel = channels[1];

		const receivedData = Buffer.alloc(chunks[0].length + chunks[1].length);
		const eom = new PromiseCompletionSource<void>();
		let offset = 0;
		serverChannel.onDataReceived((data) => {
			data.copy(receivedData, offset);
			offset += data.byteLength;

			serverChannel.adjustWindow(data.length);

			if (offset >= chunks[0].length + chunks[1].length) {
				eom.resolve(undefined);
			}
		});

		await writeAsync(clientChannel, chunks[0]);
		await writeAsync(clientChannel, chunks[1]);

		await eom.promise;

		assert.equal(Buffer.compare(Buffer.concat([chunks[0], chunks[1]]), receivedData), 0);

		await clientChannel.end();
		await serverChannel.close();
	}

	@test
	public async corkedSend() {
		const chunks = ['abc', 'def'].map((v) => Buffer.from(v, 'utf8'));

		const [clientSession, serverSession] = await SshStreamTests.createSessions();
		const channels = await Promise.all([
			clientSession.acceptChannel(),
			serverSession.openChannel(),
		]);
		const clientChannel = new SshStream(channels[0]);
		const serverChannel = channels[1];

		const receivedData = Buffer.alloc(chunks[0].length + chunks[1].length);
		const eom = new PromiseCompletionSource<void>();
		let offset = 0;
		let packetCount = 0;
		serverChannel.onDataReceived((data) => {
			packetCount++;
			data.copy(receivedData, offset);
			offset += data.byteLength;

			serverChannel.adjustWindow(data.length);

			if (offset >= chunks[0].length + chunks[1].length) {
				eom.resolve(undefined);
			}
		});

		clientChannel.cork();
		const write1Promise = writeAsync(clientChannel, chunks[0]);
		const write2Promise = writeAsync(clientChannel, chunks[1]);
		clientChannel.uncork();
		await Promise.all([write1Promise, write2Promise]);

		await eom.promise;

		assert.equal(Buffer.compare(Buffer.concat([chunks[0], chunks[1]]), receivedData), 0);
		assert.equal(packetCount, 1);

		await clientChannel.end();
		await serverChannel.close();
	}

	@test
	public async onBothSides() {
		const chunks = ['abc', 'def'].map((v) => Buffer.from(v, 'utf8'));

		const [clientSession, serverSession] = await SshStreamTests.createSessions();
		const channels = await Promise.all([
			clientSession.acceptChannel(),
			serverSession.openChannel(),
		]);
		const clientChannel = new SshStream(channels[0]);
		const serverChannel = new SshStream(channels[1]);

		const receivedData = Buffer.alloc(chunks[0].length + chunks[1].length);
		const eom = new PromiseCompletionSource<void>();
		let offset = 0;
		serverChannel.on('data', (data) => {
			data.copy(receivedData, offset);
			offset += data.byteLength;

			if (offset >= chunks[0].length + chunks[1].length) {
				eom.resolve(undefined);
			}
		});

		await writeAsync(clientChannel, chunks[0]);
		await writeAsync(clientChannel, chunks[1]);

		await eom.promise;

		assert.equal(Buffer.compare(Buffer.concat([chunks[0], chunks[1]]), receivedData), 0);

		await clientChannel.end();
		await serverChannel.end();
	}

	@test
	public async endPropagatesAsSshChannelShutdown() {
		const [clientSession, serverSession] = await SshStreamTests.createSessions();
		const channels = await Promise.all([
			clientSession.acceptChannel(),
			serverSession.openChannel(),
		]);
		const clientChannel = new SshStream(channels[0]);
		const serverChannel = new SshStream(channels[1]);

		// Arrange to notice when the server stream is closed.
		const serverClosed = new Promise<void>((resolve) => serverChannel.on('end', () => resolve()));
		serverChannel.resume(); // Readable doesn't recognize the end unless it's reading.

		// Close the client stream.
		clientChannel.end();

		// Wait for the server to recognize that the channel has closed.
		await serverClosed;
	}

	@test
	public async throttled() {
		const largeData1Size = (1024 * 1024 * 5) / 2;
		const largeData1 = Buffer.alloc(largeData1Size);
		for (let i = 0; i < largeData1Size; i++) largeData1[i] = (i * 2) & 0xff;

		const largeDataSize2 = (1024 * 1024 * 5) / 2;
		const largeData2 = Buffer.alloc(largeDataSize2);
		for (let i = 0; i < largeDataSize2; i++) largeData2[i] = (i * 2 + 1) & 0xff;

		const [clientSession, serverSession] = await SshStreamTests.createSessions();
		const channels = await Promise.all([
			clientSession.acceptChannel(),
			serverSession.openChannel(),
		]);
		const clientChannel = new SshStream(channels[0]);
		const serverChannel = new SshStream(channels[1]);

		const allDataReceived = new PromiseCompletionSource<void>();
		let totalDataReceived = 0;
		serverChannel.on('data', (data) => {
			totalDataReceived += data.length;
			if (totalDataReceived >= largeData1.length + largeData2.length) {
				allDataReceived.resolve();
			}
		});

		await writeAsync(clientChannel, largeData1);
		await writeAsync(clientChannel, largeData2);
		await allDataReceived;
	}
}

async function writeAsync(writable: NodeJS.WritableStream, chunk: any): Promise<void> {
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
