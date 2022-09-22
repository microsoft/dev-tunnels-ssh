//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout, pending } from '@testdeck/mocha';

import {
	CancellationToken,
	ChannelRequestMessage,
	DebugMessage,
	KeyPair,
	PromiseCompletionSource,
	serviceActivation,
	SessionRequestMessage,
	SessionRequestSuccessMessage,
	SshAlgorithms,
	SshChannel,
	SshChannelOpeningEventArgs,
	SshClientSession,
	SshDataReader,
	SshDataWriter,
	SshDisconnectReason,
	SshRequestEventArgs,
	SshServerSession,
	SshService,
	SshSession,
	SshMessage,
} from '@microsoft/dev-tunnels-ssh';
import { connectSessionPair, createSessionConfig } from './sessionPair';

@suite
@slow(3000)
@timeout(20000)
export class ServiceTests {
	private static readonly testUsername = 'test';

	private readonly testConfig = new TestServiceConfig();
	private clientClosedCompletion = new PromiseCompletionSource<void>();
	private serverClosedCompletion = new PromiseCompletionSource<void>();
	private activatedService: SshService | null = null;

	private static serverKey: KeyPair;

	@slow(10000)
	@timeout(20000)
	public static async before() {
		ServiceTests.serverKey = await SshAlgorithms.publicKey.rsaWithSha512!.generateKeyPair();
	}

	private async createSessions(): Promise<[SshClientSession, SshServerSession]> {
		var clientConfig = createSessionConfig();
		var serverConfig = createSessionConfig();
		clientConfig.services.set(MessageService, null);
		serverConfig.services.set(TestService1, null);
		serverConfig.services.set(TestService2, this.testConfig);
		serverConfig.services.set(TestService3, this.testConfig);
		serverConfig.services.set(TestService4, null);
		serverConfig.services.set(TestService5, null);

		const clientSession = new SshClientSession(clientConfig);
		const serverSession = new SshServerSession(serverConfig);

		serverSession.credentials.publicKeys = [ServiceTests.serverKey];

		serverSession.onAuthenticating((e) => (e.authenticationPromise = Promise.resolve({})));
		clientSession.onAuthenticating((e) => (e.authenticationPromise = Promise.resolve({})));

		serverSession.onServiceActivated((service) => {
			this.activatedService = service;
		});

		clientSession.onClosed((e) => {
			this.clientClosedCompletion.resolve();
		});
		serverSession.onClosed((e) => {
			this.serverClosedCompletion.resolve();
		});

		return [clientSession, serverSession];
	}

	private async closeSessions(
		clientSession: SshSession,
		serverSession: SshSession,
	): Promise<void> {
		await clientSession.close(SshDisconnectReason.byApplication, 'test');
		await serverSession.close(SshDisconnectReason.byApplication, 'test');

		await Promise.all([this.serverClosedCompletion.promise, this.clientClosedCompletion.promise]);
	}

	@test
	public async activateOnServiceRequest(): Promise<void> {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		assert(!serverSession.services.find((s) => s instanceof TestService1));

		await clientSession.requestService(TestService1.serviceName);
		assert(serverSession.services.find((s) => s instanceof TestService1));
		assert(this.activatedService instanceof TestService1);

		const testService = <TestService1>(
			serverSession.services.find((s) => s instanceof TestService1)
		);
		assert.equal(testService.config, null);

		assert(!testService.isDisposed);
		await this.closeSessions(clientSession, serverSession);
		await testService.disposedPromise;
	}

	@test
	public async activateOnSessionRequest(): Promise<void> {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		assert(!serverSession.services.find((s) => s instanceof TestService2));

		const request = new SessionRequestMessage(TestService2.requestName, true);

		var result = await clientSession.request(request);
		assert(result);
		assert(serverSession.services.find((s) => s instanceof TestService2));
		assert(this.activatedService instanceof TestService2);

		const testService = <TestService2>(
			serverSession.services.find((s) => s instanceof TestService2)
		);
		assert.equal(this.testConfig, testService.config);
		assert(testService.requestMessage);

		await this.closeSessions(clientSession, serverSession);
	}

	@test
	public async activateOnChannelType(): Promise<void> {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		assert(!serverSession.services.find((s) => s instanceof TestService3));

		await clientSession.openChannel(TestService3.channelType);
		assert(serverSession.services.find((s) => s instanceof TestService3));
		assert(this.activatedService instanceof TestService3);

		const testService = <TestService3>(
			serverSession.services.find((s) => s instanceof TestService3)
		);
		assert.equal(this.testConfig, testService.config);
		assert(testService.channel);

		await this.closeSessions(clientSession, serverSession);
	}

	@test
	public async activateOnChannelRequest(): Promise<void> {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		assert(!serverSession.services.find((s) => s instanceof TestService4));

		const channel = await clientSession.openChannel();
		assert(!serverSession.services.find((s) => s instanceof TestService4));

		const request = new ChannelRequestMessage();
		request.requestType = TestService4.requestName;
		request.wantReply = true;
		await channel.request(request);
		assert(serverSession.services.find((s) => s instanceof TestService4));
		assert(this.activatedService instanceof TestService4);

		const testService = <TestService4>(
			serverSession.services.find((s) => s instanceof TestService4)
		);
		assert(testService.requestMessage);

		await this.closeSessions(clientSession, serverSession);
	}

	@test
	public async activateOnChannelTypeChannelRequest(): Promise<void> {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		assert(!serverSession.services.find((s) => s instanceof TestService5));

		var channel = await clientSession.openChannel(TestService5.channelType);
		assert(!serverSession.services.find((s) => s instanceof TestService5));

		const request = new ChannelRequestMessage();
		request.requestType = TestService5.requestName;
		request.wantReply = true;
		await channel.request(request);
		assert(serverSession.services.find((s) => s instanceof TestService5));
		assert(this.activatedService instanceof TestService5);

		const testService = <TestService5>(
			serverSession.services.find((s) => s instanceof TestService5)
		);
		assert(testService.channel);
		assert(testService.requestMessage);

		await this.closeSessions(clientSession, serverSession);
	}

	@test
	public async sendUnimplementedMessage() {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		const messageService = <MessageService>(
			clientSession.activateService(MessageService.serviceName)!
		);
		await messageService.sendMessage(new TestMessage());

		// Wait for open channel response, to ensure the message is processed.
		await clientSession.openChannel();
	}

	@test
	public async sendDebugMessage() {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession);

		const messageService = <MessageService>(
			clientSession.activateService(MessageService.serviceName)!
		);
		await messageService.sendMessage(new DebugMessage('test'));

		// Wait for open channel response, to ensure the message is processed.
		await clientSession.openChannel();
	}
}

class TestServiceConfig {}

@serviceActivation({ serviceRequest: TestService1.serviceName })
class TestService1 extends SshService {
	public static readonly serviceName = 'test-service-1';
	private readonly disposedCompletion = new PromiseCompletionSource<void>();

	public constructor(session: SshSession, config?: TestServiceConfig) {
		super(session);
		this.config = config;
	}

	public readonly config: TestServiceConfig | undefined;

	public get disposedPromise(): Promise<void> {
		return this.disposedCompletion.promise;
	}

	public isDisposed: boolean = false;

	public dispose(): void {
		this.isDisposed = true;
		this.disposedCompletion.resolve();
		super.dispose();
	}
}

@serviceActivation({ sessionRequest: TestService2.requestName })
class TestService2 extends SshService {
	public static readonly requestName = 'test-service-2';

	public constructor(session: SshSession, config?: TestServiceConfig) {
		super(session);
		this.config = config;
	}

	public readonly config: TestServiceConfig | undefined;

	public requestMessage: SessionRequestMessage | undefined;

	public async onSessionRequest(
		request: SshRequestEventArgs<SessionRequestMessage>,
	): Promise<void> {
		this.requestMessage = request.request;
		request.isAuthorized = true;

		if (request.request.wantReply) {
			await this.sendMessage(new SessionRequestSuccessMessage());
		}
	}
}

@serviceActivation({ channelType: TestService3.channelType })
class TestService3 extends SshService {
	public static readonly channelType = 'test-service-3';

	public constructor(session: SshSession, config?: TestServiceConfig) {
		super(session);
		this.config = config;
	}

	public readonly config: TestServiceConfig | undefined;

	public channel: SshChannel | undefined;

	public async onChannelOpening(args: SshChannelOpeningEventArgs): Promise<void> {
		this.channel = args.channel;
	}
}

@serviceActivation({ channelRequest: TestService4.requestName })
class TestService4 extends SshService {
	public static readonly requestName = 'test-service-4';

	public constructor(session: SshSession) {
		super(session);
	}

	public channel: SshChannel | undefined;

	public requestMessage: ChannelRequestMessage | undefined;

	public async onChannelRequest(
		channel: SshChannel,
		request: SshRequestEventArgs<ChannelRequestMessage>,
	): Promise<void> {
		this.channel = channel;
		this.requestMessage = request.request;
		request.isAuthorized = true;
	}
}

@serviceActivation({
	channelType: TestService5.channelType,
	channelRequest: TestService5.requestName,
})
class TestService5 extends SshService {
	public static readonly channelType = 'test-service-5-channel';
	public static readonly requestName = 'test-service-5';

	public constructor(session: SshSession) {
		super(session);
	}

	public channel: SshChannel | undefined;

	public requestMessage: ChannelRequestMessage | undefined;

	public async onChannelRequest(
		channel: SshChannel,
		request: SshRequestEventArgs<ChannelRequestMessage>,
	): Promise<void> {
		this.channel = channel;
		this.requestMessage = request.request;
		request.isAuthorized = true;
	}
}

@serviceActivation({ serviceRequest: MessageService.serviceName })
class MessageService extends SshService {
	public static readonly serviceName = 'test-message-service';

	public constructor(session: SshSession) {
		super(session);
	}

	public sendMessage(message: SshMessage, cancellation?: CancellationToken): Promise<void> {
		return super.sendMessage(message, cancellation);
	}
}

class TestMessage extends SshMessage {
	public get messageType(): number {
		return 199;
	}
	protected onRead(reader: SshDataReader): void {}

	protected onWrite(writer: SshDataWriter): void {}
}
