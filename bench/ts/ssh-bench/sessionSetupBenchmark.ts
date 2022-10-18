//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as net from 'net';
import { Benchmark } from './benchmark';
import {
	SshClientCredentials,
	SshSessionConfiguration,
	SshAlgorithms,
	ChannelRequestMessage,
	Stream,
	SshProtocolExtensionNames,
} from '@microsoft/dev-tunnels-ssh';
import { SshClient, SshServer } from '@microsoft/dev-tunnels-ssh-tcp';
import { SlowStream } from './slowStream';
import { CancellationToken } from 'vscode-jsonrpc';

const ConnectTimeMeasurement = 'Connect time (ms)';
const EncryptTimeMeasurement = 'Encrypt time (ms)';
const AuthTimeMeasurement = 'Authenticate time (ms)';
const ChannelTimeMeasurement = 'Channnel open time (ms)';
const TotalTimeMeasurement = 'Total setup time (ms)';
const LatencyMeasurement = 'Latency (ms)';

declare type hrtime = [number, number];
const millis = ([s, ns]: hrtime) => s * 1000 + ns / 1000000;

const latencyInMilliseconds = 100;

export class SessionSetupBenchmark extends Benchmark {
	private readonly port: number;
	private readonly initPromise: Promise<void>;
	private readonly server: SshServer;
	private readonly serverPromise: Promise<void>;
	private readonly client: SshClient;

	public constructor(withLatency: boolean) {
		super('Session setup' + (withLatency ? ' with latency' : ''));

		this.higherIsBetter.set(ConnectTimeMeasurement, false);
		this.higherIsBetter.set(EncryptTimeMeasurement, false);
		this.higherIsBetter.set(AuthTimeMeasurement, false);
		this.higherIsBetter.set(ChannelTimeMeasurement, false);
		this.higherIsBetter.set(TotalTimeMeasurement, false);
		this.higherIsBetter.set(LatencyMeasurement, false);

		const config = new SshSessionConfiguration();
		config.protocolExtensions.push(SshProtocolExtensionNames.sessionReconnect);
		config.protocolExtensions.push(SshProtocolExtensionNames.sessionLatency);

		this.server = withLatency ? new SshServerWithLatency(config) : new SshServer(config);
		this.client = withLatency ? new SshClientWithLatency(config) : new SshClient(config);

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

		const startTime: hrtime = process.hrtime();

		let connectMark: hrtime = [0, 0];
		const sessionOpenedRegistration = this.server.onSessionOpened((session) => {
			connectMark = process.hrtime(startTime);
			sessionOpenedRegistration.dispose();
		});

		var clientSession = await this.client.openSession('localhost', this.port);

		var encryptMark: hrtime = process.hrtime(startTime);

		clientSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});

		await clientSession.authenticateServer();

		let clientAuthCallback: (err?: Error, result?: boolean) => void;
		const clientAuthPromise = new Promise((resolve, reject) => {
			clientAuthCallback = (err, result) => {
				if (err) reject(err);
				else resolve(result);
			};
		});

		const credentials: SshClientCredentials = { username: 'benchmark', password: 'benchmark' };
		await clientSession.authenticateClient(credentials, clientAuthCallback!);

		var authMark: hrtime = process.hrtime(startTime);

		var channelRequest = new ChannelRequestMessage('benchmark');
		channelRequest.wantReply = true;

		// Protocol extension: Send initial request when opening channel.
		const clientChannel = await clientSession.openChannel(null, channelRequest);

		await clientAuthPromise;

		var channelMark: hrtime = process.hrtime(startTime);

		this.addMeasurement(ConnectTimeMeasurement, millis(connectMark));
		this.addMeasurement(EncryptTimeMeasurement, millis(encryptMark) - millis(connectMark));
		this.addMeasurement(AuthTimeMeasurement, millis(authMark) - millis(encryptMark));
		this.addMeasurement(ChannelTimeMeasurement, millis(channelMark) - millis(authMark));
		this.addMeasurement(TotalTimeMeasurement, millis(channelMark));

		// Add an additional request-reply to enable latency measurement,
		// which doesn't start until after the extension-info exchange.
		const channelRequest2 = new ChannelRequestMessage();
		channelRequest2.requestType = 'test';
		channelRequest2.wantReply = true;
		await clientChannel.request(channelRequest2);

		this.addMeasurement(LatencyMeasurement, clientSession.metrics.latencyAverageMs);
	}

	public async dispose(): Promise<void> {
		this.server.dispose();
		this.client.dispose();
		await this.serverPromise;
	}
}

class SshServerWithLatency extends SshServer {
	public constructor(config: SshSessionConfiguration) {
		super(config);
	}

	protected async acceptConnection(socket: net.Socket): Promise<Stream> {
		const baseStream = await super.acceptConnection(socket);
		return new SlowStream(baseStream, latencyInMilliseconds);
	}
}

class SshClientWithLatency extends SshClient {
	public constructor(config: SshSessionConfiguration) {
		super(config);
	}

	protected async openConnection(
		serverHost: string,
		serverPort?: number,
		cancellation?: CancellationToken,
	): Promise<{ stream: Stream; ipAddress: string | undefined }> {
		const connectionResult = await super.openConnection(serverHost, serverPort, cancellation);
		return {
			stream: new SlowStream(connectionResult.stream, latencyInMilliseconds),
			ipAddress: connectionResult.ipAddress
		};
	}
}
