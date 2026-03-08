//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Benchmark } from './benchmark';
import {
	SshChannel,
	SshClientCredentials,
	SshClientSession,
	SshSessionConfiguration,
	SshAlgorithms,
} from '@microsoft/dev-tunnels-ssh';
import { SshClient, SshServer } from '@microsoft/dev-tunnels-ssh-tcp';
import { CancellationTokenSource } from 'vscode-jsonrpc';

const MessageCountMeasurement = 'Throughput (msgs/s)';
const ByteCountMeasurement = 'Throughput (MB/s)';

declare type hrtime = [number, number];
const millis = ([s, ns]: hrtime) => s * 1000 + ns / 1000000;

export class ThroughputBenchmark extends Benchmark {
	private readonly port: number;
	private readonly initPromise: Promise<void>;
	private readonly server: SshServer;
	private readonly serverPromise: Promise<void>;
	private readonly client: SshClient;
	private readonly messageData: Buffer;

	// Reuse a single session+channel across all runs (matching Go).
	// Creating a fresh TCP+SSH session per run causes backpressure deadlocks
	// with large encrypted messages where TCP send/receive buffers create
	// a circular dependency between the client's send and the server's
	// window update on a "cold" connection.
	private clientSession: SshClientSession | null = null;
	private channel: SshChannel | null = null;

	public constructor(
		private readonly duration: number,
		messageSize: number,
		private readonly withEncryption: boolean,
	) {
		super(
			`Throughput - ${messageSize} byte messages ${
				withEncryption ? 'with' : 'without'
			} encryption`,
			'session-throughput',
			{ encryption: withEncryption ? 'true' : 'false', size: messageSize.toString() },
		);

		const config = new SshSessionConfiguration(withEncryption);
		this.server = new SshServer(config);
		this.client = new SshClient(config);

		this.messageData = Buffer.alloc(messageSize);
		SshAlgorithms.random.getBytes(this.messageData);

		this.initPromise = SshAlgorithms.publicKey
			.rsaWithSha512!.generateKeyPair()
			.then((serverKey) => {
				this.server.credentials.publicKeys.push(serverKey);
			});

		this.server.onSessionOpened((session) => {
			session.onAuthenticating((e) => {
				e.authenticationPromise = Promise.resolve({});
			});
			session.onChannelOpening((e) => {
				e.channel.onDataReceived((data) => {
					e.channel.adjustWindow(data.length);
				});
				e.channel.onRequest((e) => {
					e.isAuthorized = true;
				});
			});
		});

		this.port = Benchmark.findAvailablePort();
		this.serverPromise = this.server.acceptSessions(this.port, 'localhost');
	}

	private async ensureSession(): Promise<void> {
		if (this.channel) return;

		await this.initPromise;

		this.clientSession = await this.client.openSession('localhost', this.port);

		if (this.withEncryption) {
			this.clientSession.onAuthenticating((e) => {
				e.authenticationPromise = Promise.resolve({});
			});

			const credentials: SshClientCredentials = { username: 'benchmark', password: 'benchmark' };
			await this.clientSession.authenticate(credentials);
		}

		this.channel = await this.clientSession.openChannel();
	}

	public async run(): Promise<void> {
		await this.ensureSession();

		// Safety timeout: 4x the benchmark duration catches true deadlocks
		// caused by TCP buffer circular dependencies with large encrypted
		// messages, without affecting normal runs.
		const cancellationSource = new CancellationTokenSource();
		const timeoutHandle = setTimeout(
			() => cancellationSource.cancel(), this.duration * 4);

		let deadlocked = false;
		const startTime: hrtime = process.hrtime();
		let elapsed = 0;

		let messageCount = 0;
		try {
			while (elapsed < this.duration) {
				await this.channel!.send(this.messageData, cancellationSource.token);
				messageCount++;
				elapsed = millis(process.hrtime(startTime));
			}
		} catch {
			deadlocked = true;
		}

		clearTimeout(timeoutHandle);
		cancellationSource.dispose();

		// If the session deadlocked, reset it so the next run gets a fresh one.
		if (deadlocked) {
			this.clientSession?.dispose();
			this.clientSession = null;
			this.channel = null;
		}

		if (messageCount === 0) return;

		elapsed = millis(process.hrtime(startTime));
		const elapsedSeconds = elapsed / 1000;
		const messagesPerSecond = messageCount / elapsedSeconds;
		const bytesPerSecond = (messageCount * this.messageData.length) / elapsedSeconds;
		const megabytesPerSecond = bytesPerSecond / (1024 * 1024);
		this.addMeasurement(MessageCountMeasurement, messagesPerSecond);
		this.addMeasurement(ByteCountMeasurement, megabytesPerSecond);
	}

	public async verify(): Promise<void> {
		await this.initPromise;

		const messageCount = 5;
		let receivedCount = 0;
		const receivedPromise = new Promise<number>((resolve) => {
			const sessionReg = this.server.onSessionOpened((session) => {
				sessionReg.dispose();
				session.onChannelOpening((e) => {
					e.channel.onDataReceived((data) => {
						e.channel.adjustWindow(data.length);
						receivedCount++;
						if (receivedCount >= messageCount) {
							resolve(receivedCount);
						}
					});
				});
			});
		});

		const clientSession = await this.client.openSession('localhost', this.port);

		if (this.withEncryption) {
			clientSession.onAuthenticating((e) => {
				e.authenticationPromise = Promise.resolve({});
			});

			const credentials: SshClientCredentials = { username: 'benchmark', password: 'benchmark' };
			await clientSession.authenticate(credentials);
		}

		const channel = await clientSession.openChannel();

		for (let i = 0; i < messageCount; i++) {
			await channel.send(this.messageData);
		}

		// Wait for server to receive all messages (with timeout)
		const received = await Promise.race([
			receivedPromise,
			new Promise<number>((_, reject) =>
				setTimeout(() => reject(new Error('Timeout waiting for messages')), 5000),
			),
		]);

		if (received !== messageCount) {
			throw new Error(`Expected ${messageCount} messages, received ${received}`);
		}
	}

	public async dispose(): Promise<void> {
		this.clientSession?.dispose();
		this.server.dispose();
		this.client.dispose();
		await this.serverPromise;
	}
}
