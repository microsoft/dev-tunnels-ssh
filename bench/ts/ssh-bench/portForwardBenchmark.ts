//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as net from 'net';
import { Benchmark } from './benchmark';
import {
	SshClientCredentials,
	SshSessionConfiguration,
	SshAlgorithms,
	PromiseCompletionSource,
	SshServerSession,
} from '@microsoft/dev-tunnels-ssh';
import {
	ForwardedPortChannelEventArgs,
	PortForwardingService,
	SshClient,
	SshServer,
} from '@microsoft/dev-tunnels-ssh-tcp';

const ConnectTimeMeasurement = 'Connect time (ms)';

declare type hrtime = [number, number];
const millis = ([s, ns]: hrtime) => s * 1000 + ns / 1000000;

export class PortForwardBenchmark extends Benchmark {
	private readonly hostAddress: string;
	private readonly listenAddress: string;
	private readonly port: number;
	private readonly initPromise: Promise<void>;
	private readonly server: SshServer;
	private readonly serverPromise: Promise<void>;
	private readonly client: SshClient;

	public constructor(listenAddress: string, hostAddress: string) {
		super(`Port forward to ${hostAddress} (${listenAddress})`);

		this.higherIsBetter.set(ConnectTimeMeasurement, false);

		this.hostAddress = hostAddress;
		this.listenAddress = listenAddress;

		const config = new SshSessionConfiguration();
		config.addService(PortForwardingService);

		this.server = new SshServer(config);
		this.client = new SshClient(config);

		////this.server.trace = (_, __, msg) => console.log('SERVER: ' + msg);
		////this.client.trace = (_, __, msg) => console.log('CLIENT: ' + msg);

		this.initPromise = SshAlgorithms.publicKey
			.rsaWithSha512!.generateKeyPair()
			.then((serverKey) => {
				this.server.credentials.publicKeys.push(serverKey);
			});

		this.server.onSessionOpened((session) => {
			session.onAuthenticating((e) => {
				e.authenticationPromise = Promise.resolve({});
			});
		});

		this.port = Benchmark.findAvailablePort();
		this.serverPromise = this.server.acceptSessions(this.port, '127.0.0.1');
	}

	public async run(): Promise<void> {
		await this.initPromise;

		const startTime: hrtime = process.hrtime();

		const serverSessionCompletion = new PromiseCompletionSource<SshServerSession>();
		const sessionOpenedRegistration = this.server.onSessionOpened((session) => {
			serverSessionCompletion.resolve(session);
			sessionOpenedRegistration.dispose();
		});

		var clientSession = await this.client.openSession('127.0.0.1', this.port);
		clientSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});
		await clientSession.authenticate({ username: 'benchmark' });
		clientSession.onRequest((e) => {
			e.isAuthorized = true;
		});

		const serverSession = await serverSessionCompletion.promise;

		const connectServer = new net.Server();
		const listeningCompletion = new PromiseCompletionSource<void>();
		connectServer.listen(0, this.listenAddress, undefined, () => listeningCompletion.resolve());
		await listeningCompletion.promise;
		const serverPort = (<net.AddressInfo>connectServer.address()).port;

		const availableServer = new net.Server();
		const availableCompletion = new PromiseCompletionSource<void>();
		availableServer.listen(0, this.listenAddress, undefined, () => availableCompletion.resolve());
		await availableCompletion.promise;
		const clientPort = (<net.AddressInfo>availableServer.address()).port;
		await new Promise<void>((resolve, reject) => {
			availableServer.close((err) => (err ? reject(err) : resolve()));
		});

		const serverPfs = serverSession.activateService(PortForwardingService);
		const forwarder = await serverPfs.forwardFromRemotePort(
			'127.0.0.1',
			clientPort,
			this.hostAddress,
			serverPort,
		);
		if (!forwarder) throw new Error('Failed to forward port.');

		const channelOpenedCompletion = new PromiseCompletionSource<ForwardedPortChannelEventArgs>();
		const clientPfs = clientSession.activateService(PortForwardingService);
		clientPfs.remoteForwardedPorts.onPortChannelAdded((e) => channelOpenedCompletion.resolve(e));

		const connectClient = new net.Socket();
		const connectStartMark: hrtime = process.hrtime(startTime);

		const serverAcceptPromise = new Promise<void>((resolve, reject) => {
			connectServer.on('error', reject).once('connection', resolve);
		});
		const connectClientPromise = new Promise<void>((resolve, reject) => {
			connectClient.on('error', reject).connect(clientPort, '127.0.0.1', resolve);
		});
		await Promise.all([
			connectClientPromise,
			serverAcceptPromise,
			channelOpenedCompletion.promise,
		]);

		const connectEndMark: hrtime = process.hrtime(startTime);

		connectClient.end();
		await new Promise<void>((resolve, reject) => {
			connectServer.close((err) => (err ? reject(err) : resolve()));
		});

		this.addMeasurement(
			ConnectTimeMeasurement,
			millis(connectEndMark) - millis(connectStartMark),
		);
	}

	public async dispose(): Promise<void> {
		this.server.dispose();
		this.client.dispose();
		await this.serverPromise;
	}
}
