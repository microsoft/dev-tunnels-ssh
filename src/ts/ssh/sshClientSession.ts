//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshSession, ExtensionRequestTypes } from './sshSession';
import { CancellationToken } from 'vscode-jsonrpc';
import {
	SshDisconnectReason,
	ServiceRequestMessage,
	ServiceAcceptMessage,
	SessionReconnectRequestMessage,
	SessionReconnectResponseMessage,
	SessionReconnectFailureMessage,
	SshReconnectFailureReason,
} from './messages/transportMessages';
import {
	SshAuthenticatingEventArgs,
	SshAuthenticationType,
} from './events/sshAuthenticatingEventArgs';
import { PromiseCompletionSource } from './util/promiseCompletionSource';
import { CancellationError } from './util/cancellation';
import { SshSessionConfiguration, SshProtocolExtensionNames } from './sshSessionConfiguration';
import { SshChannel } from './sshChannel';
import { ChannelOpenMessage, ChannelRequestMessage } from './messages/connectionMessages';
import { AuthenticationService } from './services/authenticationService';
import { ConnectionService } from './services/connectionService';
import { Stream } from './streams';
import { ObjectDisposedError, SshReconnectError } from './errors';
import { SshClientCredentials } from './sshCredentials';
import { TraceLevel, SshTraceEventIds } from './trace';

/**
 * The client side of an SSH session. Extends the base `SshSession` class to
 * support client authentication.
 */
export class SshClientSession extends SshSession {
	private readonly serviceRequests = new Map<string, PromiseCompletionSource<boolean>>();

	public constructor(config: SshSessionConfiguration) {
		super(config, true);
	}

	private clientAuthCompletion: PromiseCompletionSource<boolean> | null = null;

	/**
	 * Attempts to authenticate both the server and client.
	 *
	 * This method must be called only after encrypting the session. It is equivalent
	 * to calling both `authenticateServer()` and `authenticateClient()` and waiting on
	 * both results.
	 *
	 * @returns `true` if authentication succeeded, `false` if it failed.
	 */
	public async authenticate(
		clientCredentials: SshClientCredentials,
		cancellation?: CancellationToken,
	): Promise<boolean> {
		const serverAuthenticated = await this.authenticateServer(cancellation);
		if (!serverAuthenticated) {
			return false;
		}

		const clientAuthenticated = await this.authenticateClient(clientCredentials, cancellation);
		if (!clientAuthenticated) {
			return false;
		}

		return true;
	}

	/**
	 * Triggers server authentication by invoking the `authenticating` event with
	 * the verified server host key.
	 *
	 * This method must be called only after encrypting the session. It does not wait for any
	 * further message exchange with the server, since the server host key would have already
	 * been obtained during the key-exchange.
	 *
	 * @returns `true` if authentication succeeded, `false` if it failed.
	 */
	public async authenticateServer(cancellation?: CancellationToken): Promise<boolean> {
		if (!(this.kexService && this.kexService.hostKey)) {
			throw new Error('Encrypt the session before authenticating.');
		}

		try {
			// Raise an Authenticating event that allows handlers to do verification
			// of the host key and return a principal for the server.
			this.principal = await this.raiseAuthenticatingEvent(
				new SshAuthenticatingEventArgs(
					SshAuthenticationType.serverPublicKey,
					{
						publicKey: this.kexService.hostKey,
					},
					cancellation,
				),
			);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.authenticationError,
				`Error while authenticating server: ${e.message}`,
				e,
			);
			throw e;
		}

		if (!this.principal) {
			await this.close(
				SshDisconnectReason.hostKeyNotVerifiable,
				'Server authentication failed.',
			);
			this.trace(
				TraceLevel.Warning,
				SshTraceEventIds.serverAuthenticationFailed,
				`${this} server authentication failed.`,
			);
			return false;
		}

		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.sessionAuthenticated,
			`${this} server authenticated.`,
		);
		return true;
	}

	/**
	 * Performs client authentication by sending the configured public key or
	 * password credential to the server and waiting for a response.
	 *
	 * This method must be called only after encrypting the session.
	 *
	 * @returns `true` if authentication succeeded, `false` if it failed.
	 */
	public authenticateClient(
		credentials: SshClientCredentials,
		cancellation?: CancellationToken,
	): Promise<boolean>;

	/**
	 * Performs client authentication by sending the configured public key or
	 * password credential to the server. Returns the result later via a callback.
	 *
	 * This method must be called only after encrypting the session. It waits for the
	 * authentication request message to be sent, but does not directly wait for a response.
	 * In scenarios when client authentication is non-interactive, only a single credential
	 * is used, and it is expected to be always successful in non-exceptional conditions,
	 * then this method may reduce the time required to establish a secure session by not
	 * blocking on the authentication result before sending additional messages such as
	 * channel open requests. If the authentication fails then those additional requests
	 * would likely fail also, and in that case the callback may reveal the reason.
	 *
	 * @param callback Callback that will be invoked with the result of the client
	 * authentication, or with an error if the session is disconnected before
	 * authentication completed.
	 */
	public authenticateClient(
		credentials: SshClientCredentials,
		callback: (err?: Error, result?: boolean) => void,
		cancellation?: CancellationToken,
	): Promise<void>;

	/* @internal */
	public authenticateClient(
		credentials: SshClientCredentials,
		callbackOrCancellation?: ((err?: Error, result?: boolean) => void) | CancellationToken,
		cancellation?: CancellationToken,
	): Promise<any> {
		if (!credentials) {
			throw new TypeError('A credentials object is required.');
		}

		if (typeof callbackOrCancellation === 'function') {
			return this.authenticateClientWithCompletion(
				credentials,
				callbackOrCancellation,
				cancellation,
			);
		} else {
			return new Promise(async (resolve, reject) => {
				await this.authenticateClientWithCompletion(
					credentials,
					(err, result) => {
						if (err) reject(err);
						else resolve(result);
					},
					callbackOrCancellation,
				);
			});
		}
	}

	private async authenticateClientWithCompletion(
		credentials: SshClientCredentials,
		callback: (err?: Error, result?: boolean) => void,
		cancellation?: CancellationToken,
	): Promise<void> {
		this.clientAuthCompletion = new PromiseCompletionSource<boolean>();
		this.clientAuthCompletion.promise.then(
			(result) => callback(undefined, result),
			(err) => callback(err),
		);

		if (cancellation) {
			if (cancellation.isCancellationRequested) throw new CancellationError();
			cancellation.onCancellationRequested((e) => {
				if (this.clientAuthCompletion) {
					this.clientAuthCompletion.reject(new CancellationError());
				}
			});
		}

		let authService = this.getService(AuthenticationService);
		if (!authService) {
			const serviceRequestMessage = new ServiceRequestMessage();
			serviceRequestMessage.serviceName = AuthenticationService.serviceName;
			await this.sendMessage(serviceRequestMessage, cancellation);

			// Assume the service request is accepted, without waiting for an accept message.
			// (If not, the following auth requests will fail anyway.)
			authService = this.activateService(AuthenticationService);
		}

		await authService.authenticateClient(credentials, cancellation);
	}

	/* @internal */
	public onAuthenticationComplete(success: boolean): void {
		if (success) {
			this.trace(
				TraceLevel.Info,
				SshTraceEventIds.sessionAuthenticated,
				`${this} client authenticated.`,
			);
		} else {
			this.trace(
				TraceLevel.Warning,
				SshTraceEventIds.clientAuthenticationFailed,
				`${this} client authentication failed.`,
			);
		}

		if (this.clientAuthCompletion) {
			this.clientAuthCompletion.resolve(success);
			this.clientAuthCompletion = null;
		}
	}

	/**
	 * Sends a request for a service and waits for a response.
	 *
	 * @param serviceName Name of the service to be requested.
	 * @param cancellation Optional cancellation token.
	 * @returns A promise that resolves when the service request has been accepted.
	 *
	 * If the server does not accept the service request, it will disconnect the session.
	 */
	public async requestService(
		serviceName: string,
		cancellation?: CancellationToken,
	): Promise<void> {
		let sendRequest = false;

		let completion = this.serviceRequests.get(serviceName);
		if (!completion) {
			completion = new PromiseCompletionSource<boolean>();
			this.serviceRequests.set(serviceName, completion);
			sendRequest = true;
		}

		if (sendRequest) {
			const requestMessage = new ServiceRequestMessage();
			requestMessage.serviceName = serviceName;
			await this.sendMessage(requestMessage, cancellation);
		}

		await completion.promise;
	}

	/* @internal */
	protected async handleServiceAcceptMessage(
		message: ServiceAcceptMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		const completion = this.serviceRequests.get(message.serviceName!);
		completion?.resolve(true);
	}

	public async openChannel(
		channelTypeOrOpenMessageOrCancellation?:
			| string
			| null
			| ChannelOpenMessage
			| CancellationToken,
		initialRequestOrCancellation?: ChannelRequestMessage | null | CancellationToken,
		cancellation?: CancellationToken,
	): Promise<SshChannel> {
		if (!this.connectionService) {
			// Authentication must have been skipped, meaning there was no
			// connection service request sent yet. Send it now, and assume
			// it is accepted without waiting for a response.
			const serviceRequestMessage = new ServiceRequestMessage();
			serviceRequestMessage.serviceName = ConnectionService.serviceName;
			await this.sendMessage(serviceRequestMessage, cancellation);
		}

		return await super.openChannel(
			<any>channelTypeOrOpenMessageOrCancellation,
			<any>initialRequestOrCancellation,
			cancellation,
		);
	}

	/* @internal */
	public handleDisconnected(): boolean {
		if (this.reconnecting) {
			this.reconnecting = false;
			return false;
		}

		return super.handleDisconnected();
	}

	/**
	 * Call instead of `connect()` to reconnect to a prior session instead of connecting
	 * a new session.
	 * @param stream A new stream that has just (re-) connected to the server.
	 * @param cancellation Optional cancellation token.
	 * @returns True if reconnect succeeded, false if the server declined the reconnect
	 * request or reconnect session validation failed. In the case of a false return value,
	 * retrying is unlikely to succeed.
	 * @throws {SshConnectionError} There was a problem connecting to or communicating with
	 * the server; retrying may still succeed if connectivity is restored.
	 * @throws {SshReconnectError} Reconnect failed for some reason other than a communication
	 * issue: see the `failureReason` property of the error. Retrying is unlikely to succeed,
	 * unless the specific error condition can be addressed.
	 */
	public async reconnect(stream: Stream, cancellation?: CancellationToken): Promise<void> {
		this.trace(
			TraceLevel.Verbose,
			SshTraceEventIds.clientSessionReconnecting,
			'Attempting to reconnect...',
		);

		if (this.isClosed) {
			throw new ObjectDisposedError(this);
		} else if (this.isConnected) {
			throw new Error('Already connected.');
		}

		if (!this.protocol) {
			throw new Error('The session was never previously connected.');
		}

		if (this.reconnecting) {
			throw new Error('Already reconnecting.');
		}

		this.reconnecting = true;

		try {
			await this.reconnectInternal(stream, cancellation);
		} finally {
			this.reconnecting = false;
		}
	}

	private async reconnectInternal(
		stream: Stream,
		cancellation?: CancellationToken,
	): Promise<void> {
		const previousSessionId = this.sessionId;
		const previousProtocolInstance = this.protocol;
		const previousHostKey = this.kexService?.hostKey;
		if (
			!previousSessionId ||
			!previousProtocolInstance ||
			!this.kexService ||
			!previousHostKey ||
			!previousProtocolInstance!.extensions?.has(SshProtocolExtensionNames.sessionReconnect)
		) {
			throw new Error('Reconnect was not enabled for this session.');
		}

		let newSessionId: Buffer;
		try {
			// Reconnecting will temporarily create a new session ID.
			this.sessionId = null;
			await this.connect(stream, cancellation);

			if (!this.sessionId || !this.algorithms || !this.algorithms.signer) {
				throw new Error('Session is not encrypted.');
			}

			// Ensure the client is not reconnecting to a different server.
			const newHostKey = this.kexService.hostKey;
			const newHostPublicKey = !newHostKey ? null : await newHostKey.getPublicKeyBytes();
			const previousHostPublicKey = await previousHostKey.getPublicKeyBytes();
			if (
				!newHostPublicKey ||
				!previousHostPublicKey ||
				!newHostPublicKey.equals(previousHostPublicKey)
			) {
				const message = 'The server host key is different.';
				this.trace(
					TraceLevel.Error,
					SshTraceEventIds.clientSessionReconnectFailed,
					`Reconnection failed: ${message}`,
				);
				throw new SshReconnectError(message, SshReconnectFailureReason.differentServerHostKey);
			}

			newSessionId = this.sessionId;
		} catch (e) {
			// Restore the previous protocol instance so reconnect may be attempted again.
			this.protocol = previousProtocolInstance;
			super.handleDisconnected();
			throw e;
		} finally {
			// Restore the previous session ID and host key for the reconnected session.
			this.sessionId = previousSessionId;
			this.kexService.hostKey = previousHostKey;
		}

		const reconnectToken = await this.createReconnectToken(previousSessionId, newSessionId);
		const reconnectRequest = new SessionReconnectRequestMessage();
		reconnectRequest.requestType = ExtensionRequestTypes.sessionReconnect;
		reconnectRequest.clientReconnectToken = reconnectToken;
		reconnectRequest.lastReceivedSequenceNumber = previousProtocolInstance.lastIncomingSequence;
		reconnectRequest.wantReply = true;
		const response = await this.requestResponse(
			reconnectRequest,
			SessionReconnectResponseMessage,
			SessionReconnectFailureMessage,
			cancellation,
		);
		if (response instanceof SessionReconnectFailureMessage) {
			const reason = response.reasonCode ?? SshReconnectFailureReason.unknownServerFailure;
			const message = response.description ?? 'The server rejected the reconnect request.';
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.clientSessionReconnectFailed,
				`Reconnection failed: ${message}`,
			);

			// Restore the previous protocol instance so reconnect may be attempted again.
			this.protocol = previousProtocolInstance;
			throw new SshReconnectError(message, reason);
		}

		if (
			!this.verifyReconnectToken(
				previousSessionId,
				newSessionId,
				response.serverReconnectToken ?? Buffer.alloc(0),
			)
		) {
			const message = 'The reconnect token provided by the server was invalid.';
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.clientSessionReconnectFailed,
				`Reconnection failed: ${message}`,
			);
			throw new SshReconnectError(
				message,
				SshReconnectFailureReason.invalidServerReconnectToken,
			);
		}

		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.clientSessionReconnecting,
			'Reconnect request was accepted by the server.',
		);

		// Re-send lost messages.
		const messagesToResend = previousProtocolInstance.getSentMessages(
			(response.lastReceivedSequenceNumber ?? 0) + 1,
		);
		if (!messagesToResend) {
			const message = 'Client is unable to re-send messages requested by the server.';
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.clientSessionReconnectFailed,
				`Reconnection failed: ${message}`,
			);
			throw new SshReconnectError(message, SshReconnectFailureReason.clientDroppedMessages);
		}

		let count = 0;
		for (let message of messagesToResend) {
			await this.sendMessage(message, cancellation);
			count++;
		}

		// Now the session is fully reconnected!
		previousProtocolInstance.dispose();

		this.metrics.addReconnection();

		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.clientSessionReconnecting,
			`{this} reconnected. Re-sent ${count} dropped messages.`,
		);
	}

	public dispose(): void {
		if (this.clientAuthCompletion) {
			this.clientAuthCompletion.reject(new ObjectDisposedError(this));
		}

		super.dispose();
	}
}
