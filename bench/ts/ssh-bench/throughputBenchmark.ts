//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Benchmark } from './benchmark';
import {
	SshClientCredentials,
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

	public constructor(
		private readonly duration: number,
		messageSize: number,
		private readonly withEncryption: boolean,
	) {
		super(
			`Throughput - ${messageSize} byte messages ${
				withEncryption ? 'with' : 'without'
			} encryption`,
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
				e.channel.onRequest((e) => {
					e.isAuthorized = true;
				});
			});
		});

		this.port = Benchmark.findAvailablePort();
		this.serverPromise = this.server.acceptSessions(this.port, 'localhost');
	}

	public async run(): Promise<void> {
		await this.initPromise;

		const sessionOpenedRegistration = this.server.onSessionOpened((session) => {
			sessionOpenedRegistration.dispose();

			session.onChannelOpening((e) => {
				e.channel.onDataReceived((data) => {
					e.channel.adjustWindow(data.length);
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

		const cancellationSource = new CancellationTokenSource();
		setTimeout(() => cancellationSource.cancel(), 2 * this.duration);

		const startTime: hrtime = process.hrtime();
		let elapsed = 0;

		let messageCount = 0;
		while (elapsed < this.duration) {
			await channel.send(this.messageData, cancellationSource.token);
			messageCount++;
			elapsed = millis(process.hrtime(startTime));
		}

		cancellationSource.dispose();

		const elapsedSeconds = elapsed / 1000;
		const messagesPerSecond = messageCount / elapsedSeconds;
		const bytesPerSecond = (messageCount * this.messageData.length) / elapsedSeconds;
		const megabytesPerSecond = bytesPerSecond / (1024 * 1024);
		this.addMeasurement(MessageCountMeasurement, messagesPerSecond);
		this.addMeasurement(ByteCountMeasurement, megabytesPerSecond);
	}

	public async dispose(): Promise<void> {
		this.server.dispose();
		this.client.dispose();
		await this.serverPromise;
	}
}
