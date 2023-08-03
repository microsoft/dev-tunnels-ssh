//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshSession, ExtensionRequestTypes } from './sshSession';
import { CancellationToken, Emitter } from 'vscode-jsonrpc';
import {
	SshDisconnectReason,
	ServiceRequestMessage,
	ServiceAcceptMessage,
	SessionReconnectRequestMessage,
	SessionRequestFailureMessage,
	SessionReconnectResponseMessage,
	SessionRequestMessage,
	SessionReconnectFailureMessage,
	SshReconnectFailureReason,
} from './messages/transportMessages';
import { SshConnectionError } from './errors';
import { SshSessionConfiguration, SshProtocolExtensionNames } from './sshSessionConfiguration';
import { SshServerCredentials } from './sshCredentials';
import { TraceLevel, SshTraceEventIds } from './trace';

/**
 * The server side of an SSH session. Extends the base `SshSession` class
 * to support host authentication.
 */
export class SshServerSession extends SshSession {
	private readonly reconnectableSessions?: SshServerSession[];

	public constructor(config: SshSessionConfiguration, reconnectableSessions?: SshServerSession[]) {
		super(config, false);

		const enableReconnect = config.protocolExtensions.includes(
			SshProtocolExtensionNames.sessionReconnect,
		);
		if (enableReconnect && !reconnectableSessions) {
			throw new Error(
				'When reconnect is enabled, server sessions require a reference to a ' +
					'shared collection to track reconnectable sessions.',
			);
		} else if (!enableReconnect && reconnectableSessions) {
			throw new Error(
				'When reconnect is not enabled, the reconnectable sessions collection ' +
					'is not applicable.',
			);
		}

		this.reconnectableSessions = reconnectableSessions;
	}

	private readonly clientAuthenticatedEmitter = new Emitter<void>();
	public readonly onClientAuthenticated = this.clientAuthenticatedEmitter.event;

	private readonly reconnectedEmitter = new Emitter<void>();
	public readonly onReconnected = this.reconnectedEmitter.event;

	/**
	 * Gets or sets credentials and/or credential callbacks for authenticating the session.
	 */
	public credentials: SshServerCredentials = { publicKeys: [] };

	/* @internal */
	protected async handleServiceRequestMessage(
		message: ServiceRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		const service = this.activateService(message.serviceName!);
		if (service) {
			const acceptMessage = new ServiceAcceptMessage();
			acceptMessage.serviceName = message.serviceName;
			await this.sendMessage(acceptMessage, cancellation);
		} else {
			throw new SshConnectionError(
				`Service "${message.serviceName}" not available.`,
				SshDisconnectReason.serviceNotAvailable,
			);
		}
	}

	/* @internal */
	protected async handleRequestMessage(
		message: SessionRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (
			message.requestType === ExtensionRequestTypes.sessionReconnect &&
			this.config.protocolExtensions?.includes(SshProtocolExtensionNames.sessionReconnect)
		) {
			const reconnectRequest = message.convertTo(new SessionReconnectRequestMessage());
			await this.reconnect(reconnectRequest, cancellation);

			// reconnect() handles sending the response message.
			return;
		}

		await super.handleRequestMessage(message, cancellation);
	}

	/* @internal */
	public handleClientAuthenticated() {
		this.clientAuthenticatedEmitter.fire();
	}

	/* @internal */
	public async enableReconnect(cancellation?: CancellationToken) {
		await super.enableReconnect(cancellation);

		if (!this.reconnectableSessions!.includes(this)) {
			this.reconnectableSessions!.push(this);
		}
	}

	/* @internal */
	public handleDisconnected(): boolean {
		if (this.reconnecting) {
			// Prevent closing the session while reconnecting.
			return true;
		}

		return super.handleDisconnected();
	}

	/**
	 * Attempts to reconnect the client to a disconnected server session.
	 *
	 * If reconnection is successful, the current server session is disposed because the client
	 * gets reconnected to a different server session.
	 */
	/* @internal */
	public async reconnect(
		reconnectRequest: SessionReconnectRequestMessage,
		cancellation?: CancellationToken,
	) {
		if (!this.reconnectableSessions) {
			throw new Error(
				'Disconnected sessions collection ' +
					'should have been initialized when reconnect is enabled.',
			);
		}

		// Try to find the requested server session in the list of available disconnected
		// server sessions, by validating the reconnect token.
		let reconnectSession: SshServerSession | undefined;
		for (const reconnectableSession of this.reconnectableSessions) {
			if (
				reconnectableSession !== this &&
				(await this.verifyReconnectToken(
					reconnectableSession.sessionId!,
					this.sessionId!,
					reconnectRequest.clientReconnectToken ?? Buffer.alloc(0),
				))
			) {
				reconnectSession = reconnectableSession;
				this.reconnectableSessions.splice(
					this.reconnectableSessions.indexOf(reconnectSession),
					1,
				);
				break;
			}
		}

		if (!reconnectSession || reconnectSession.isClosed) {
			const message =
				'Requested reconnect session was not found or ' +
				'the reconnect token provided by the client was invalid.';
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.serverSessionReconnectFailed,
				`Reconnect failed: ${message}`,
			);
			const failure = new SessionReconnectFailureMessage();
			failure.reasonCode = SshReconnectFailureReason.sessionNotFound;
			failure.description = message;
			await this.sendMessage(failure, cancellation);
			return;
		}

		const messagesToResend = reconnectSession.protocol!.getSentMessages(
			(reconnectRequest.lastReceivedSequenceNumber ?? 0) + 1,
		);
		if (!messagesToResend) {
			// Messages are not available from requested sequence number.
			// Restore the current session protocol and put the old session back in the collection.
			this.reconnectableSessions.push(reconnectSession);

			const message = 'Server is unable to re-send messages requested by the client.';
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.serverSessionReconnectFailed,
				`Reconnect failed: ${message}`,
			);
			const failure = new SessionReconnectFailureMessage();
			failure.reasonCode = SshReconnectFailureReason.serverDroppedMessages;
			failure.description = message;
			await this.sendMessage(failure, cancellation);
			return;
		}

		const responseMessage = new SessionReconnectResponseMessage();
		responseMessage.serverReconnectToken = await this.createReconnectToken(
			reconnectSession.sessionId!,
			this.sessionId!,
		);
		responseMessage.lastReceivedSequenceNumber = reconnectSession.protocol!.lastIncomingSequence;
		await this.sendMessage(responseMessage, cancellation);

		try {
			reconnectSession.reconnecting = true;

			// Ensure the old connection is disconnected before switching over to the new one.
			reconnectSession.protocol?.dispose();
			while (reconnectSession.isConnected) {
				await new Promise<void>((resolve) => setTimeout(() => resolve(), 5));
			}

			// Move this session's protocol instance over to the reconnected session.
			reconnectSession.protocol = this.protocol;
			reconnectSession.protocol!.kexService = reconnectSession.kexService;
			this.protocol = undefined;

			// Re-send the lost messages that the client requested.
			for (const message of messagesToResend) {
				await reconnectSession.sendMessage(message, cancellation);
			}

			// Now this server session is invalid because the client reconnected to another one.
			this.dispose(new SshConnectionError('Reconnected.', SshDisconnectReason.none));
		} finally {
			reconnectSession.reconnecting = false;
		}

		this.reconnectableSessions.push(reconnectSession);

		reconnectSession.metrics.addReconnection();

		// Restart the message loop for the reconnected session.
		reconnectSession.processMessages().catch((e) => {
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.unknownError,
				`Unhandled error processing messages: ${e.message}`,
				e,
			);
		});

		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.serverSessionReconnecting,
			`${reconnectSession} reconnected. Re-sent ${messagesToResend.length} dropped messages.`,
		);

		// Notify event listeners about the successful reconnection.
		reconnectSession.reconnectedEmitter.fire();
	}

	public dispose(): void;

	/* @internal */
	public dispose(error?: Error): void;

	public dispose(error?: Error): void {
		if (this.reconnectableSessions) {
			const index = this.reconnectableSessions.indexOf(this);
			if (index >= 0) {
				this.reconnectableSessions.splice(index, 1);
			}
		}

		super.dispose(error);
	}
}
