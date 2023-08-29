//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Trace, TraceLevel, SshTraceEventIds } from './trace';
import { Buffer } from 'buffer';
import { CancellationToken, Emitter, Event, Disposable } from 'vscode-jsonrpc';
import { Stream } from './streams';
import { SshSessionConfiguration, SshProtocolExtensionNames } from './sshSessionConfiguration';
import { SshChannel } from './sshChannel';
import { SshVersionInfo } from './sshVersionInfo';
import { SshProtocol } from './io/sshProtocol';
import { KeyExchangeService } from './services/keyExchangeService';
import { SshService, SshServiceConstructor } from './services/sshService';
import { findService, ServiceActivation } from './services/serviceActivation';
import { ConnectionService } from './services/connectionService';
import { AuthenticationService } from './services/authenticationService';
import { SshMessage } from './messages/sshMessage';
import { KeyExchangeMessage, NewKeysMessage, KeyExchangeInitMessage } from './messages/kexMessages';
import {
	ConnectionMessage,
	ChannelRequestMessage,
	ChannelOpenMessage,
} from './messages/connectionMessages';
import { AuthenticationMessage } from './messages/authenticationMessages';
import {
	SshDisconnectReason,
	DisconnectMessage,
	ServiceRequestMessage,
	SessionRequestMessage,
	SessionRequestSuccessMessage,
	SessionRequestFailureMessage,
	ExtensionInfoMessage,
	SessionChannelRequestMessage,
	ServiceAcceptMessage,
	UnimplementedMessage,
	DebugMessage,
	IgnoreMessage,
} from './messages/transportMessages';
import { SessionMetrics } from './metrics/sessionMetrics';
import { PromiseCompletionSource } from './util/promiseCompletionSource';
import { SshAuthenticatingEventArgs } from './events/sshAuthenticatingEventArgs';
import { SshSessionClosedEventArgs } from './events/sshSessionClosedEventArgs';
import { SshChannelOpeningEventArgs } from './events/sshChannelOpeningEventArgs';
import { SshRequestEventArgs } from './events/sshRequestEventArgs';
import { SshSessionAlgorithms } from './sshSessionAlgorithms';
import { algorithmNames, KeyExchangeAlgorithm } from './algorithms/sshAlgorithms';
import { withCancellation, CancellationError } from './util/cancellation';
import { SshConnectionError, ObjectDisposedError } from './errors';
import { Semaphore } from './util/semaphore';
import { PipeExtensions } from './pipeExtensions';
import { Queue } from './util/queue';

declare type SessionRequestResponseMessage =
	| SessionRequestSuccessMessage
	| SessionRequestFailureMessage;

export const enum ExtensionRequestTypes {
	initialChannelRequest = 'initial-channel-request@microsoft.com',
	enableSessionReconnect = 'enable-session-reconnect@microsoft.com',
	sessionReconnect = 'session-reconnect@microsoft.com',
}

interface RequestHandler {
	/** Callback invoked when the (success or failure) response is received. */
	(err?: Error, result?: SessionRequestResponseMessage): void;
	/** Flag indicating the request has been cancelled. */
	isCancelled?: boolean;
}

/**
 * Base class for an SSH server or client connection; coordinates high-level SSH
 * protocol details and dispatches messages to registered internal services.
 * Enables opening and accepting `SshChannel` instances.
 */
export class SshSession implements Disposable {
	public static readonly localVersion = SshVersionInfo.getLocalVersion();

	public remoteVersion: SshVersionInfo | null = null;

	private readonly activatedServices = new Map<SshServiceConstructor, SshService>();
	protected kexService: KeyExchangeService | null;
	protected connectionService: ConnectionService | null = null;
	private connectPromise?: Promise<void>;
	private requestHandlers: Queue<RequestHandler> = new Queue<RequestHandler>();
	private versionExchangePromise?: Promise<void>;
	private readonly blockedMessages: SshMessage[] = [];
	private readonly blockedMessagesSemaphore = new Semaphore(1);
	private connected: boolean = false;
	private disposed: boolean = false;
	private closedError?: Error;

	public get algorithms(): SshSessionAlgorithms | null {
		return this.protocol ? this.protocol.algorithms : null;
	}

	/**
	 * Gets an object that reports current and cumulative measurements about the session.
	 */
	public readonly metrics = new SessionMetrics();

	/* @internal */
	public protocol?: SshProtocol;

	/* @internal */
	public reconnecting: boolean = false;

	public sessionId: Buffer | null = null;

	private principalValue: object | null = null;

	/**
	 * Gets an object containing claims about the server or client on the
	 * other end of the session, or `null` if the session is not authenticated.
	 *
	 * This property is initially `null` for an unauthenticated session. On
	 * successful authentication, the session Authenticating event handler
	 * provides a Task that returns a principal that is stored here.
	 */
	public get principal(): object | null {
		return this.principalValue;
	}

	/* @internal */
	public set principal(value: object | null) {
		this.principalValue = value;
	}

	private readonly authenticatingEmitter = new Emitter<SshAuthenticatingEventArgs>();

	/**
	 * Event that is raised when a client or server is requesting authentication.
	 *
	 * See `SshAuthenticationType` for a description of the different authentication
	 * methods and how they map to the event-args object.
	 *
	 * After validating the credentials, the event handler must set the
	 * `SshAuthenticatingEventArgs.authenticationPromise` property to a task that
	 * resolves to a principal object to indicate successful authentication. That principal will
	 * then be associated with the sesssion as the `principal` property.
	 */
	public readonly onAuthenticating = this.authenticatingEmitter.event;

	private readonly closedEmitter = new Emitter<SshSessionClosedEventArgs>();
	public readonly onClosed = this.closedEmitter.event;

	private readonly disconnectedEmitter = new Emitter<void>();
	public readonly onDisconnected = this.disconnectedEmitter.event;

	private readonly serviceActivatedEmitter = new Emitter<SshService>();
	public readonly onServiceActivated = this.serviceActivatedEmitter.event;

	private readonly channelOpeningEmitter = new Emitter<SshChannelOpeningEventArgs>();
	public readonly onChannelOpening = this.channelOpeningEmitter.event;

	private readonly requestEmitter = new Emitter<SshRequestEventArgs<SessionRequestMessage>>();
	public readonly onRequest: Event<SshRequestEventArgs<SessionRequestMessage>> =
		this.requestEmitter.event;

	/**
	 * Gets or sets a function that handles trace messages associated with the session.
	 *
	 * By default, no messages are traced. To enable tracing, set this property to a function
	 * that routes the message to console.log, a file, or anywhere else.
	 *
	 * @param level Level of message: error, warning, info, or verbose
	 * @param eventId Integer identifier of the event being traced.
	 * @param msg Message (non-localized) describing the event.
	 */
	public trace: Trace = (level, eventId, msg, err) => {};

	public constructor(public readonly config: SshSessionConfiguration, isClientSession?: boolean) {
		this.isClientSession = isClientSession;

		if (!config) throw new TypeError('Session configuration is required.');

		if (!config.keyExchangeAlgorithms.find((a) => !!a)) {
			if (
				config.encryptionAlgorithms.length > 0 &&
				config.encryptionAlgorithms.indexOf(null) < 0
			) {
				throw new Error('Encryption requires a key-exchange algorithm to be configured.');
			} else if (config.hmacAlgorithms.length > 0 && config.hmacAlgorithms.indexOf(null) < 0) {
				throw new Error('HMAC requires a key-exchange algorithm to be configured.');
			} else if (
				config.publicKeyAlgorithms.length > 0 &&
				config.publicKeyAlgorithms.indexOf(null) < 0
			) {
				throw new Error(
					'Host authentication requires a key-exchange algorithm to be configured.',
				);
			}

			// No key exchange, no encryption, no HMAC.
			this.kexService = null;
			this.activateService(ConnectionService);
		} else {
			this.kexService = new KeyExchangeService(this);
		}

		config.onConfigurationChanged(() => {
			const protocol = this.protocol;
			if (protocol) {
				protocol.traceChannelData = config.traceChannelData;
			}
		});
	}

	/**
	 * Allows other internal components to check whether a session is a client (or server),
	 * without using `instanceof` which is slower and can cause circular dependencies.
	 */
	/* @internal */
	public readonly isClientSession?: boolean;

	public get isConnected(): boolean {
		return this.connected;
	}

	public get isClosed(): boolean {
		return this.disposed;
	}

	public get services(): readonly SshService[] {
		return [...this.activatedServices.values()];
	}

	public get channels(): readonly SshChannel[] {
		return this.connectionService?.channels ?? [];
	}

	public get protocolExtensions(): Map<string, string> | null {
		return this.protocol?.extensions || null;
	}

	/**
	 * Gets an activated service instance by type.
	 *
	 * @returns The service instance, or `null` if the service has not been activated.
	 */
	public getService<T extends SshService>(serviceType: SshServiceConstructor<T>): T | null {
		const service = this.activatedServices.get(serviceType);
		return service ? <T>service : null;
	}

	/**
	 * Activates a service by name (if not already activated).
	 *
	 * The service must declare support for activation by name,
	 * via `ServiceActivation.serviceRequest`.
	 *
	 * @returns The activated service instance, or `null` if no service could be found that declares
	 * support for activation with the specified name.
	 */
	public activateService(serviceName: string): SshService | null;

	/**
	 * Activates a service by type (if not already activated).
	 *
	 * @returns The activated service instance.
	 * @throws If the service type is not found in the sesion configuration.
	 */
	public activateService<T extends SshService>(serviceType: SshServiceConstructor<T>): T;

	/* @internal */
	public activateService<T extends SshService = SshService>(
		serviceTypeOrName: SshServiceConstructor<T> | string,
	): T | null {
		let serviceType: SshServiceConstructor | null;
		if (typeof serviceTypeOrName === 'function') {
			serviceType = serviceTypeOrName;
		} else {
			const serviceName: string = serviceTypeOrName;
			serviceType = findService(
				this.config.services,
				(a: ServiceActivation) => a.serviceRequest === serviceName,
			);
			if (!serviceType) {
				return null;
			}
		}

		let activatedService = this.activatedServices.get(serviceType);
		if (!activatedService) {
			if (!this.config.services.has(serviceType)) {
				throw new Error(`Service type not configured: ${serviceType.name}`);
			}

			const serviceConfig = this.config.services.get(serviceType);
			activatedService = new serviceType(this, serviceConfig);

			// This service is maintained in a separate member because it is accessed frequently.
			if (serviceType === ConnectionService) {
				this.connectionService = <ConnectionService>activatedService;
			}

			this.activatedServices.set(serviceType, activatedService);
			this.serviceActivatedEmitter.fire(activatedService);
		}
		return <T>activatedService;
	}

	public async connect(stream: Stream, cancellation?: CancellationToken): Promise<void> {
		if (!stream) throw new TypeError('A session stream is required.');
		if (this.disposed) throw new ObjectDisposedError(this);

		if (!this.connectPromise) {
			this.connectPromise = this.doConnect(stream, cancellation);
		}
		await this.connectPromise;
	}

	private async doConnect(stream: Stream, cancellation?: CancellationToken): Promise<void> {
		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.sessionConnecting,
			`${this} ${this.reconnecting ? 're' : ''}connecting...`,
		);

		this.protocol = new SshProtocol(stream, this.config, this.metrics, this.trace);
		this.protocol.kexService = this.kexService;

		await this.exchangeVersions(cancellation);

		if (this.kexService) {
			await this.encrypt(cancellation);
		} else {
			// When there's no key-exchange service configured, send a key-exchange init message
			// that specifies "none" for all algorithms.
			await this.sendMessage(KeyExchangeInitMessage.none, cancellation);

			// When encrypting, the key-exchange step will wait on the version-exchange.
			// When not encrypting, it must be directly awaited.
			await withCancellation(this.versionExchangePromise!, cancellation);
			this.connected = true;
		}

		this.processMessages().catch((e) => {
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.unknownError,
				`Unhandled error processing messages: ${e.message}`,
				e,
			);
		});
	}

	private async exchangeVersions(cancellation?: CancellationToken): Promise<void> {
		const writePromise = this.protocol!.writeProtocolVersion(
			SshSession.localVersion.toString(),
			cancellation,
		);
		const readPromise = this.protocol!.readProtocolVersion(cancellation);

		// Don't wait for and verify the other side's version info yet.
		// Instead save a promise that can be awaited later.
		this.versionExchangePromise = readPromise.then(async (remoteVersion) => {
			this.trace(
				TraceLevel.Info,
				SshTraceEventIds.protocolVersion,
				`Local version: ${SshSession.localVersion}, remote version: ${remoteVersion}`,
			);

			let errorMessage: string;
			const remoteVersionInfo = SshVersionInfo.tryParse(remoteVersion);
			if (remoteVersionInfo) {
				this.remoteVersion = remoteVersionInfo;
				if (remoteVersionInfo.protocolVersion === '2.0') {
					return;
				}

				errorMessage =
					`Remote SSH version ${this.remoteVersion} is not supported. ` +
					'This library only supports SSH v2.0.';
			} else {
				errorMessage = `Could not parse remote SSH version ${remoteVersion}`;
			}

			await this.close(
				SshDisconnectReason.protocolVersionNotSupported,
				errorMessage,
				new Error(errorMessage),
			);
		});

		await writePromise;
	}

	private async encrypt(cancellation?: CancellationToken): Promise<void> {
		const protocol = this.protocol;
		if (!protocol) throw new ObjectDisposedError(this);

		await protocol.considerReExchange(true, cancellation);

		// Ensure the protocol version has been received before receiving any messages.
		await withCancellation(this.versionExchangePromise!, cancellation);
		this.connected = true;

		let message: SshMessage | null = null;
		while (
			!this.isClosed &&
			!this.protocol?.algorithms &&
			!(message instanceof DisconnectMessage)
		) {
			message = await protocol.receiveMessage(cancellation);
			if (!message) {
				break;
			}

			await this.handleMessage(message, cancellation);
		}

		if (!this.protocol?.algorithms) {
			throw new SshConnectionError(
				'Session closed while encrypting.',
				SshDisconnectReason.connectionLost,
			);
		} else if (this.protocol.algorithms.cipher) {
			this.trace(TraceLevel.Info, SshTraceEventIds.sessionEncrypted, `${this} encrypted.`);
		}
	}

	/* @internal */
	protected async processMessages(): Promise<void> {
		this.connected = true;

		while (!this.disposed) {
			const protocol = this.protocol;
			if (!protocol) {
				break;
			}

			let message: SshMessage | null = null;
			try {
				message = await protocol.receiveMessage();
			} catch (e) {
				if (!(e instanceof Error)) throw e;
				let reason = SshDisconnectReason.protocolError;
				if (e instanceof SshConnectionError) {
					reason = (<SshConnectionError>e).reason ?? reason;
				} else {
					this.trace(
						TraceLevel.Error,
						SshTraceEventIds.receiveMessageFailed,
						`Error receiving message: ${e.message}`,
						e,
					);
				}
				await this.close(reason, e.message, e);
			}

			if (!message) {
				await this.close(SshDisconnectReason.connectionLost, 'Connection lost.');
				break;
			}

			try {
				await this.handleMessage(message);
			} catch (e) {
				if (!(e instanceof Error)) throw e;
				this.trace(
					TraceLevel.Error,
					SshTraceEventIds.handleMessageFailed,
					`Error handling ${message}: ${e.message}`,
					e,
				);
				await this.close(SshDisconnectReason.protocolError, e.message, e);
			}
		}

		this.connected = false;
	}

	/**
	 * Checks whether the session is in a state that allows requests, such as session requests
	 * and open-channel requests.
	 *
	 * A session with disabled crypto (no key-exchange service) always allows requests. A
	 * session with enabled crypto does not allow requests until the first key-exchange has
	 * completed (algorithms are negotiated). If the negotiated algorithms enabled encryption,
	 * then the session must be authenticated (have a principal) before allowing requests.
	 */
	/* @internal */
	public get canAcceptRequests(): boolean {
		return (
			!this.kexService ||
			(!!this.protocol?.algorithms && (!this.protocol.algorithms.cipher || !!this.principal))
		);
	}

	public async sendMessage(message: SshMessage, cancellation?: CancellationToken): Promise<void> {
		if (!message) throw new TypeError('Message expected.');
		if (cancellation && cancellation.isCancellationRequested) throw new CancellationError();

		const protocol = this.protocol;
		if (!protocol || this.disposed) {
			throw new ObjectDisposedError(this);
		}

		// Delay sending messages if in the middle of a key (re-)exchange.
		if (
			this.kexService &&
			this.kexService.exchanging &&
			message.messageType > 4 &&
			(message.messageType < 20 || message.messageType > 49)
		) {
			this.blockedMessages.push(message);
			return;
		}

		await this.blockedMessagesSemaphore.wait(cancellation);

		let result: boolean;
		try {
			result = await protocol.sendMessage(message, cancellation);
			this.blockedMessagesSemaphore.release();
		} catch (e) {
			this.blockedMessagesSemaphore.release();
			if (e instanceof SshConnectionError) {
				const ce = <SshConnectionError>e;
				if (
					ce.reason === SshDisconnectReason.connectionLost &&
					this.protocolExtensions?.has(SshProtocolExtensionNames.sessionReconnect)
				) {
					// Connection-lost error when reconnect is enabled. Don't throw an error;
					// the message will remain in the reconnect message cache and will be re-sent
					// upon reconnection.
					return;
				}
			}

			if (!(e instanceof Error)) throw e;
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.sendMessageFailed,
				`Error sending ${message}: ${e.message}`,
				e,
			);
			throw e;
		}

		if (!result) {
			// Sending failed due to a closed stream, but don't throw when reconnect is enabled.
			// In that case the sent message is buffered and will be re-sent after reconnecting.
			if (!this.protocolExtensions?.has(SshProtocolExtensionNames.sessionReconnect)) {
				throw new SshConnectionError(
					'Session disconnected.',
					SshDisconnectReason.connectionLost,
				);
			}
		}
	}

	/**
	 * Handles an incoming message. Can be overridden by subclasses to handle additional
	 * message types that are registered via `SshSessionConfiguration.messages`.
	 */
	protected handleMessage(
		message: SshMessage,
		cancellation?: CancellationToken,
	): void | Promise<void> {
		if (message instanceof ConnectionMessage && this.connectionService) {
			return this.connectionService.handleMessage(message, cancellation);
		} else if (message instanceof NewKeysMessage) {
			return this.handleNewKeysMessage(message, cancellation);
		} else if (message instanceof KeyExchangeMessage) {
			return this.handleKeyExchangeMessage(message, cancellation);
		} else if (message instanceof AuthenticationMessage) {
			return this.getService(AuthenticationService)?.handleMessage(message, cancellation);
		} else if (message instanceof ServiceRequestMessage) {
			return this.handleServiceRequestMessage(message, cancellation);
		} else if (message instanceof ServiceAcceptMessage) {
			return this.handleServiceAcceptMessage(message, cancellation);
		} else if (message instanceof SessionRequestMessage) {
			return this.handleRequestMessage(message, cancellation);
		} else if (message instanceof SessionRequestSuccessMessage) {
			return this.handleRequestSuccessMessage(message);
		} else if (message instanceof SessionRequestFailureMessage) {
			return this.handleRequestFailureMessage(message);
		} else if (message instanceof ExtensionInfoMessage) {
			return this.handleExtensionInfoMessage(message, cancellation);
		} else if (message instanceof DisconnectMessage) {
			return this.handleDisconnectMessage(message);
		} else if (message instanceof UnimplementedMessage) {
			return this.handleUnimplementedMessage(message, cancellation);
		} else if (message instanceof DebugMessage) {
			return this.handleDebugMessage(message);
		} else if (message instanceof IgnoreMessage) {
			// Do nothing for ignore message
			return;
		} else if (message instanceof SshMessage) {
			throw new Error(`Unhandled message type: ${message.constructor.name}`);
		} else {
			throw new TypeError('Message argument was ' + (message ? 'invalid type.' : 'null.'));
		}
	}

	/* @internal */
	protected async handleRequestMessage(
		message: SessionRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		let result = false;
		let response: SshMessage | null = null;

		if (
			message.requestType === ExtensionRequestTypes.initialChannelRequest &&
			this.config.protocolExtensions.includes(SshProtocolExtensionNames.openChannelRequest)
		) {
			const sessionChannelRequest = message.convertTo(new SessionChannelRequestMessage());
			const remoteChannelId = sessionChannelRequest.senderChannel;
			const channel = this.channels.find((c) => c.remoteChannelId === remoteChannelId);
			if (channel && sessionChannelRequest.request) {
				sessionChannelRequest.request.wantReply = false; // Avoid redundant reply
				result = await channel.handleRequest(sessionChannelRequest.request, cancellation);
			}
		} else if (
			message.requestType === ExtensionRequestTypes.enableSessionReconnect &&
			this.config.protocolExtensions?.includes(SshProtocolExtensionNames.sessionReconnect)
		) {
			if (!this.protocol!.incomingMessagesHaveReconnectInfo) {
				// Starting immediately after this message, all incoming messages include
				// an extra field or two after the payload.
				this.protocol!.incomingMessagesHaveReconnectInfo = true;
				this.protocol!.incomingMessagesHaveLatencyInfo = this.protocol!.extensions!.has(
					SshProtocolExtensionNames.sessionLatency,
				);
				result = true;
			}
		} else if (!this.canAcceptRequests) {
			this.trace(
				TraceLevel.Warning,
				SshTraceEventIds.sessionRequestFailed,
				'Session request blocked because the session is not yet authenticated.',
			);
			result = false;
		} else {
			const args = new SshRequestEventArgs<SessionRequestMessage>(
				message.requestType || '',
				message,
				this.principal,
				cancellation,
			);

			const serviceType = findService(
				this.config.services,
				(a: ServiceActivation) => a.sessionRequest === message.requestType,
			);
			if (serviceType) {
				// A service was configured for activation via this session request type.
				const service = this.activateService(serviceType);

				// `onSessionRequest` should really be 'protected internal'.
				await (<any>service).onSessionRequest(args, cancellation);
			} else {
				// Raise a request event to let an event listener handle this request.
				this.raiseSessionRequest(args);
			}

			// TODO: do not block requests in TS (similar to CS)
			// see https://dev.azure.com/devdiv/DevDiv/_git/SSH/commit/0b84a48811e2f015107c73bf4584b6c3b676a6de
			if (args.responsePromise) {
				response = await args.responsePromise;
				result = response instanceof SessionRequestSuccessMessage;
			} else {
				result = args.isAuthorized || false;
			}
		}

		if (message.wantReply) {
			if (result) {
				if (!(response instanceof SessionRequestSuccessMessage)) {
					response = new SessionRequestSuccessMessage();
				}
			} else {
				if (!(response instanceof SessionRequestFailureMessage)) {
					response = new SessionRequestFailureMessage();
				}
			}

			await this.sendMessage(response, cancellation);
		}
	}

	/* @internal */
	public raiseSessionRequest(args: SshRequestEventArgs<SessionRequestMessage>) {
		this.requestEmitter.fire(args);
	}

	/* @internal */
	protected async handleServiceRequestMessage(
		message: ServiceRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		// Do nothing. Subclasses may override.
	}

	/* @internal */
	protected async handleServiceAcceptMessage(
		message: ServiceAcceptMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		// Do nothing. Subclasses may override.
	}

	private async handleKeyExchangeMessage(
		message: KeyExchangeMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (this.kexService) {
			await this.kexService.handleMessage(message, cancellation);
		} else if (!(message instanceof KeyExchangeInitMessage && message.allowsNone)) {
			// The other side required some security, but it's not configured here.
			await this.close(SshDisconnectReason.keyExchangeFailed, 'Encryption is disabled.');
		}
	}

	/* @internal */
	public async handleNewKeysMessage(
		message: NewKeysMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		try {
			await this.blockedMessagesSemaphore.wait(cancellation);

			await this.protocol!.handleNewKeys(cancellation);

			if (this.algorithms?.isExtensionInfoRequested) {
				await this.sendExtensionInfo(cancellation);
			}

			try {
				// Send messages that were blocked during key exchange.
				while (this.blockedMessages.length > 0) {
					const blockedMessage = this.blockedMessages.shift()!;
					if (!this.protocol) throw new ObjectDisposedError(this);
					await this.protocol.sendMessage(blockedMessage, cancellation);
				}
			} catch (e) {
				if (!(e instanceof Error)) throw e;
				await this.close(SshDisconnectReason.protocolError, undefined, e);
			}
		} finally {
			this.blockedMessagesSemaphore.release();
		}
	}

	private async handleUnimplementedMessage(
		message: UnimplementedMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (message.unimplementedMessageType !== undefined) {
			// Received a message type that is unimplemented by this side.
			// Send a reply to inform the other side.
			await this.sendMessage(message, cancellation);
		} else {
			// This is a reply indicating this side previously sent a message type
			// that is not implemented by the other side. It has already been traced.
		}
	}

	private handleDebugMessage(message: DebugMessage): void {
		if (message.message) {
			this.trace(
				message.alwaysDisplay ? TraceLevel.Info : TraceLevel.Verbose,
				SshTraceEventIds.debugMessage,
				message.message,
			);
		}
	}

	/* @internal */
	protected async raiseAuthenticatingEvent(
		args: SshAuthenticatingEventArgs,
	): Promise<object | null> {
		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.sessionAuthenticating,
			`${this} Authenticating(${args})`,
		);

		this.authenticatingEmitter.fire(args);

		let authPromise = args.authenticationPromise;
		if (!authPromise) {
			authPromise = Promise.resolve(null);
		}

		const principal = await authPromise;
		return principal;
	}

	/**
	 * Sends a session request and waits for a response.
	 *
	 * Note if `wantReply` is `false`, this method returns `true` immediately after sending
	 * the request, without waiting for a response.
	 *
	 * @returns The authorization status of the response; if `false`, the other side denied the
	 * request.
	 */
	public async request(
		request: SessionRequestMessage,
		cancellation?: CancellationToken,
	): Promise<boolean> {
		if (!request) throw new TypeError('Request is required.');

		if (!request.wantReply) {
			await this.sendMessage(request, cancellation);
			return true;
		}

		const response = await this.requestResponse(
			request,
			SessionRequestSuccessMessage,
			SessionRequestFailureMessage,
			cancellation,
		);
		return response instanceof SessionRequestSuccessMessage;
	}

	/**
	 * Sends a session request and waits for a specific type of success or failure message.
	 *
	 * @returns The success or failure response message.
	 */
	public async requestResponse<
		TSuccess extends SessionRequestSuccessMessage,
		TFailure extends SessionRequestFailureMessage,
	>(
		request: SessionRequestMessage,
		successType: { new (): TSuccess },
		failureType: { new (): TFailure },
		cancellation?: CancellationToken,
	): Promise<TSuccess | TFailure> {
		if (!request) throw new TypeError('Request is required.');
		if (!successType) throw new TypeError('Success response type is required.');
		if (!failureType) throw new TypeError('Failure response type is required.');

		request.wantReply = true;

		const requestHandler: RequestHandler = (
			err?: Error,
			result?: SessionRequestResponseMessage,
		) => {
			if (err) {
				requestCompletionSource.reject(err);
			} else if (requestHandler.isCancelled) {
				// The completion source was already rejected with a cancellation error.
				return;
			} else if (result instanceof SessionRequestFailureMessage) {
				const failure = result?.convertTo(new failureType(), true) ?? null;
				requestCompletionSource.resolve(failure);
			} else if (result instanceof SessionRequestSuccessMessage) {
				// Make a copy of the response message because the continuation may be
				// asynchronous; meanwhile the receive buffer will be re-used.
				const success = result?.convertTo(new successType(), true) ?? null;
				requestCompletionSource.resolve(success);
			} else {
				requestCompletionSource.reject(new Error('Unknown response message type.'));
			}
		};

		const requestCompletionSource = new PromiseCompletionSource<TSuccess | TFailure>();
		if (cancellation) {
			if (cancellation.isCancellationRequested) throw new CancellationError();
			cancellation.onCancellationRequested(() => {
				requestHandler.isCancelled = true;
				requestCompletionSource.reject(new CancellationError());
			});
		}

		this.requestHandlers.enqueue(requestHandler);

		await this.sendMessage(request, cancellation);
		return await requestCompletionSource.promise;
	}

	private handleRequestSuccessMessage(message: SessionRequestSuccessMessage): void {
		this.invokeRequestHandler(message, undefined, undefined);
	}

	private handleRequestFailureMessage(message: SessionRequestFailureMessage): void {
		this.invokeRequestHandler(undefined, message, undefined);
	}

	private invokeRequestHandler(
		success?: SessionRequestSuccessMessage,
		failure?: SessionRequestFailureMessage,
		error?: Error,
	) {
		let requestHandler: RequestHandler | undefined;
		while ((requestHandler = this.requestHandlers.dequeue())) {
			requestHandler(error, success ?? failure);

			// An error is provided if the session is disposing. In that case,
			// all pending requests should fail with that error.
			if (!error) {
				break;
			}
		}
	}

	/**
	 * Asynchronously waits for the other side to open a channel.
	 *
	 * @returns The opened channel.
	 */
	public acceptChannel(cancellation?: CancellationToken): Promise<SshChannel>;

	/**
	 * Asynchronously waits for the other side to open a channel.
	 *
	 * @param channelType Channel type to accept. If unspecified, defaults to the standard
	 * "session" channel type. (Other channel types will not be accepted.)
	 * @returns The opened channel.
	 */
	public acceptChannel(
		channelType?: string,
		cancellation?: CancellationToken,
	): Promise<SshChannel>;

	public async acceptChannel(
		channelTypeOrCancellation?: string | CancellationToken,
		cancellation?: CancellationToken,
	): Promise<SshChannel> {
		const channelType =
			typeof channelTypeOrCancellation === 'string' ? channelTypeOrCancellation : undefined;
		if (!cancellation && typeof channelTypeOrCancellation === 'object')
			cancellation = channelTypeOrCancellation;

		this.activateService(ConnectionService);

		// Prepare to accept the channel before connecting. This ensures that if the channel
		// open request comes in immediately after connecting then the channel won't be missed
		// in case of a task scheduling delay.
		const acceptPromise = this.connectionService!.acceptChannel(
			channelType || SshChannel.sessionChannelType,
			cancellation,
		);

		return await acceptPromise;
	}

	/**
	 * Opens a channel and asynchronously waits for the other side to accept it.
	 *
	 * @returns The opened channel.
	 */
	public openChannel(cancellation?: CancellationToken): Promise<SshChannel>;

	/**
	 * Opens a channel and asynchronously waits for the other side to accept it.
	 *
	 * @param channelType Channel type to open. If unspecified, defaults to the standard
	 * "session" channel type.
	 * @returns The opened channel.
	 */
	public openChannel(
		channelType: string | null,
		cancellation?: CancellationToken,
	): Promise<SshChannel>;

	/**
	 * Opens a channel and asynchronously waits for the other side to accept it.
	 * Optionally sends an initial request and also waits for a response to that request.
	 *
	 * This uses a private extension to the SSH protocol to avoid an extra round-trip when
	 * opening a channel and sending the first channel request. If the other side doesn't
	 * support the extension, then the standard protocol is used as a fallback.
	 *
	 * @param openMessage Open message to be sent, including channel type. May be a subclass
	 * of `ChannelOpenMessage`.
	 * @param initialRequest Optional initial request sent over the channel, often used
	 * to establish the purpose of the channel.
	 * @returns The opened channel.
	 */
	public openChannel(
		openMessage: ChannelOpenMessage,
		initialRequest?: ChannelRequestMessage | null,
		cancellation?: CancellationToken,
	): Promise<SshChannel>;

	public async openChannel(
		channelTypeOrOpenMessageOrCancellation?:
			| string
			| null
			| ChannelOpenMessage
			| CancellationToken,
		initialRequestOrCancellation?: ChannelRequestMessage | null | CancellationToken,
		cancellation?: CancellationToken,
	): Promise<SshChannel> {
		let openMessage: ChannelOpenMessage;
		if (
			typeof channelTypeOrOpenMessageOrCancellation === 'string' ||
			channelTypeOrOpenMessageOrCancellation === null
		) {
			openMessage = new ChannelOpenMessage();
			openMessage.channelType =
				channelTypeOrOpenMessageOrCancellation ?? SshChannel.sessionChannelType;
		} else if (channelTypeOrOpenMessageOrCancellation instanceof ChannelOpenMessage) {
			openMessage = channelTypeOrOpenMessageOrCancellation;
		} else {
			openMessage = new ChannelOpenMessage();
			openMessage.channelType = SshChannel.sessionChannelType;
			cancellation = channelTypeOrOpenMessageOrCancellation;
		}

		if (initialRequestOrCancellation instanceof ChannelRequestMessage) {
			return await this.openChannelWithInitialRequest(
				openMessage,
				initialRequestOrCancellation,
				cancellation,
			);
		} else if (!cancellation && initialRequestOrCancellation !== null) {
			cancellation = initialRequestOrCancellation;
		}

		this.activateService(ConnectionService);

		const completionSource = new PromiseCompletionSource<SshChannel>();
		await this.connectionService!.openChannel(openMessage, completionSource, cancellation);
		return await completionSource.promise;
	}

	private async openChannelWithInitialRequest(
		openMessage: ChannelOpenMessage,
		initialRequest: ChannelRequestMessage,
		cancellation?: CancellationToken,
	): Promise<SshChannel> {
		this.activateService(ConnectionService);
		const completionSource = new PromiseCompletionSource<SshChannel>();
		const channelId = await this.connectionService!.openChannel(
			openMessage,
			completionSource,
			cancellation,
		);

		if (cancellation) {
			if (cancellation.isCancellationRequested) throw new CancellationError();
			cancellation.onCancellationRequested(() =>
				completionSource.reject(new CancellationError()),
			);
		}

		let channel: SshChannel;
		let requestResult: boolean;

		const isExtensionSupported =
			this.config.protocolExtensions.includes(SshProtocolExtensionNames.openChannelRequest) &&
			this.protocolExtensions?.has(SshProtocolExtensionNames.openChannelRequest);
		if (isExtensionSupported === false) {
			// The local or remote side definitely doesn't support this extension. Just send a
			// normal channel request after waiting for the channel open confirmation.
			channel = await completionSource.promise;
			requestResult = await channel.request(initialRequest, cancellation);
		} else {
			// The remote side does or might support this extension. If uncertain then a reply
			// is required.
			const wantReply = initialRequest.wantReply || isExtensionSupported === undefined;

			// Send the initial channel request message BEFORE waiting for the
			// channel open confirmation.
			const sessionRequest = new SessionChannelRequestMessage();
			sessionRequest.requestType = ExtensionRequestTypes.initialChannelRequest;
			sessionRequest.senderChannel = channelId;
			sessionRequest.request = initialRequest;
			sessionRequest.wantReply = wantReply;
			const requestPromise = this.request(sessionRequest, cancellation);

			// Wait for the channel open confirmation.
			channel = await completionSource.promise;

			if (!wantReply) {
				requestResult = true;
			} else {
				// Wait for the response to the initial channel request.
				requestResult = await requestPromise;
				if (!requestResult && isExtensionSupported === undefined) {
					// The initial request failed. This could be because the other side doesn't
					// support the initial-request extension or because the request was denied.
					// Try sending the request again as a regular channel request.
					requestResult = await channel.request(initialRequest);
				}
			}
		}

		if (!requestResult) {
			// The regular request still failed, so close the channel and throw.
			await channel.close();
			throw new Error('The initial channel request was denied.');
		}

		return channel;
	}

	/* @internal */
	public async handleChannelOpening(
		args: SshChannelOpeningEventArgs,
		cancellation?: CancellationToken,
		resolveService: boolean = true,
	): Promise<void> {
		if (resolveService) {
			const serviceType = findService(
				this.config.services,
				(a: ServiceActivation) =>
					a.channelType === args.channel.channelType && !a.channelRequest,
			);
			if (serviceType) {
				// A service was configured for activation via this channel type.
				const service = this.activateService(serviceType);

				// `onChannelOpening` should really be 'protected internal'.
				await (<any>service).onChannelOpening(args, cancellation);
				return;
			}
		}

		args.cancellation = cancellation ?? CancellationToken.None;
		this.channelOpeningEmitter.fire(args);
	}

	/* @internal */
	public async sendExtensionInfo(cancellation?: CancellationToken): Promise<void> {
		if (!this.protocol) return;

		const message = new ExtensionInfoMessage();
		message.extensionInfo = {};

		for (const extensionName of this.config.protocolExtensions) {
			if (extensionName === SshProtocolExtensionNames.serverSignatureAlgorithms) {
				// Send the list of enabled host key signature algorithms.
				const publicKeyAlgorithms = Array.from(
					new Set<string>(algorithmNames(this.config.publicKeyAlgorithms)),
				).join(',');
				message.extensionInfo[extensionName] = publicKeyAlgorithms;
			} else {
				message.extensionInfo[extensionName] = '';
			}
		}

		await this.protocol.sendMessage(message, cancellation);
	}

	private async handleExtensionInfoMessage(
		message: ExtensionInfoMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (!this.protocol) {
			return;
		}

		this.protocol.extensions = new Map<string, string>();

		const proposedExtensions = message.extensionInfo;
		if (!proposedExtensions) {
			return;
		}

		for (const extensionName of this.config.protocolExtensions) {
			const proposedExtension = message.extensionInfo[extensionName];
			if (typeof proposedExtension === 'string') {
				this.protocol.extensions.set(extensionName, proposedExtension);
			}
		}

		if (this.protocol.extensions.has(SshProtocolExtensionNames.sessionReconnect)) {
			await this.enableReconnect(cancellation);
		}
	}

	public async close(reason: SshDisconnectReason, message?: string, error?: Error): Promise<void> {
		if (this.disposed || !this.connected) {
			return;
		}

		this.connected = false;

		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.sessionClosing,
			`${this} Close(${SshDisconnectReason[reason]}, "${message || ''}")`,
		);

		if (reason !== SshDisconnectReason.connectionLost) {
			try {
				const disconnectMessage = new DisconnectMessage();
				disconnectMessage.reasonCode = reason;
				disconnectMessage.description = message || '';
				await this.protocol?.sendMessage(disconnectMessage);
			} catch (e) {
				// Already disconnected.
			}
		} else if (this.handleDisconnected()) {
			// Keep the session in a disconnected (but not closed) state.
			this.protocol?.dispose();

			this.trace(TraceLevel.Info, SshTraceEventIds.sessionDisconnected, `${this} disconnected.`);
			this.disconnectedEmitter.fire();
			return;
		}

		this.disposed = true;
		this.closedError = error;

		error = error ?? new SshConnectionError(message, reason);
		if (error) {
			this.connectionService?.close(error);
		}

		this.closedEmitter.fire(
			new SshSessionClosedEventArgs(reason, message || 'Disconnected.', error),
		);

		this.dispose();
	}

	/* @internal */
	public handleDisconnected(): boolean {
		this.connectPromise = undefined;
		this.kexService?.abortKeyExchange();

		if (!this.protocolExtensions?.has(SshProtocolExtensionNames.sessionReconnect)) {
			return false;
		}

		return true;
	}

	private async handleDisconnectMessage(message: DisconnectMessage): Promise<void> {
		const description = message.description || 'Received disconnect message.';
		await this.close(message.reasonCode ?? SshDisconnectReason.none, description);
	}

	public dispose(): void;

	/* @internal */
	public dispose(error?: Error): void;

	public dispose(error?: Error): void {
		const closedError =
			error ??
			(this.closedError instanceof SshConnectionError
				? this.closedError
				: new SshConnectionError(this.constructor.name + ' disposed.'));
		if (!this.disposed) {
			this.trace(TraceLevel.Info, SshTraceEventIds.sessionClosing, `${this} disposed.`);
			this.disposed = true;
			this.closedEmitter.fire(
				new SshSessionClosedEventArgs(
					SshDisconnectReason.none,
					closedError.message,
					closedError,
				),
			);
		}

		// Cancel any pending requests.
		this.invokeRequestHandler(undefined, undefined, closedError);

		this.metrics.close();

		// Dispose the connection service before other services, to ensure
		// channels are disposed before services that work with them.
		this.connectionService?.dispose();
		for (const service of this.activatedServices.values()) {
			if (service !== this.connectionService) {
				service.dispose();
			}
		}
		this.activatedServices.clear();

		this.protocol?.dispose();
		this.protocol = undefined;
	}

	/* @internal */
	public async enableReconnect(cancellation?: CancellationToken) {
		try {
			// Ensure no other messages are sent in the middle of turning this on.
			await this.blockedMessagesSemaphore.wait();

			// This should not be done during a key-exchange, however that should never
			// be the case since the EnableSessionReconnectRequest is sent in response
			// to an ExtensionInfo message which is sent in response to a NewKeys message.
			// So a key exchange just finished and won't be restarted again soon.
			if (this.kexService?.exchanging) {
				this.trace(
					TraceLevel.Error,
					SshTraceEventIds.sessionReconnectInitFailed,
					'Failed to initialize session reconnect because a key-exchange was in-progress.',
				);
			} else {
				// Send the message indicating reconnect message tracking is starting.
				const enableReconnectMessage = new SessionRequestMessage(
					ExtensionRequestTypes.enableSessionReconnect,
					false,
				);
				await this.protocol!.sendMessage(enableReconnectMessage, cancellation);

				// Start using the protocol extensions that include an extra field or two
				// with every sent message.
				if (this.protocol) {
					this.protocol.outgoingMessagesHaveReconnectInfo = true;
					this.protocol.outgoingMessagesHaveLatencyInfo = this.protocol.extensions!.has(
						SshProtocolExtensionNames.sessionLatency,
					);
				}
			}

			this.blockedMessagesSemaphore.release();
		} catch (e) {
			// This is not in a finally block because the semaphore must be released before
			// the call to close() which tries to send a message.
			this.blockedMessagesSemaphore.release();

			if (e instanceof Error) {
				await this.close(SshDisconnectReason.protocolError, undefined, e);
			}

			throw e;
		}
	}

	/* @internal */
	protected async createReconnectToken(
		previousSessionId: Buffer,
		newSessionId: Buffer,
	): Promise<Buffer> {
		// To generate the reconnect token, combine the old session ID and new (re-negotiated)
		// session ID and sign the result using the new negotiated HMAC algorithm and key. This
		// proves that the old (secret) session ID is known while not disclosing it, and also
		// prevents replay attacks.
		const reconnectToken = await this.algorithms!.signer!.sign(
			Buffer.concat([previousSessionId, newSessionId]),
		);
		return reconnectToken;
	}

	/* @internal */
	protected async verifyReconnectToken(
		previousSessionId: Buffer,
		newSessionId: Buffer,
		reconnectToken: Buffer,
	): Promise<boolean> {
		const result = await this.algorithms!.verifier!.verify(
			Buffer.concat([previousSessionId, newSessionId]),
			reconnectToken,
		);
		return result;
	}

	/**
	 * Pipes one SSH session into another, relaying all data between them.
	 *
	 * Any new channels opened from the remote side of either session will be piped into a
	 * new channel in the other session. Any channels opened before connecting the session pipe,
	 * or any channels opened from the local side, will not be piped.
	 *
	 * @param toSession Session to which the current session will be connected via the pipe.
	 * @returns A promise that resolves when the sessions are closed.
	 */
	public pipe(toSession: SshSession): Promise<void> {
		return PipeExtensions.pipeSession(this, toSession);
	}

	public toString() {
		return this.constructor.name;
	}
}
