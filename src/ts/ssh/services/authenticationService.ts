//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshService } from './sshService';
import { SshSession } from '../sshSession';
import { AuthenticationMethod } from '../messages/authenticationMethod';
import {
	AuthenticationMessage,
	AuthenticationFailureMessage,
	PasswordRequestMessage,
	AuthenticationSuccessMessage,
	PublicKeyRequestMessage,
	AuthenticationRequestMessage,
	PublicKeyOKMessage,
	AuthenticationInfoRequestMessage,
	AuthenticationInfoResponseMessage,
} from '../messages/authenticationMessages';
import { SshClientSession } from '../sshClientSession';
import { SshServerSession } from '../sshServerSession';
import { CancellationToken, CancellationTokenSource } from 'vscode-jsonrpc';
import { SshDataWriter } from '../io/sshData';
import { KeyPair, PublicKeyAlgorithm } from '../algorithms/publicKeyAlgorithm';
import { SshDisconnectReason } from '../messages/transportMessages';
import {
	SshAuthenticatingEventArgs,
	SshAuthenticationType,
} from '../events/sshAuthenticatingEventArgs';
import { ConnectionService } from './connectionService';
import { serviceActivation } from './serviceActivation';
import { SshClientCredentials } from '../sshCredentials';
import { Queue } from '../util/queue';
import { TraceLevel, SshTraceEventIds } from '../trace';
import { SshConnectionError } from '../errors';

/**
 * Handles SSH protocol messages related to client authentication.
 */
@serviceActivation({ serviceRequest: AuthenticationService.serviceName })
export class AuthenticationService extends SshService {
	public static readonly serviceName = 'ssh-userauth';

	public readonly publicKeyAlgorithmName: string;

	private clientAuthenticationMethods?: Queue<{
		method: AuthenticationMethod;
		handler: (cancellation?: CancellationToken) => Promise<void>;
	}>;
	private currentRequestMessage?: AuthenticationRequestMessage | null = null;
	private authenticationFailureCount: number = 0;
	private readonly disposeCancellationSource = new CancellationTokenSource();

	public constructor(session: SshSession) {
		super(session);

		const algorithmName = session.algorithms?.publicKeyAlgorithmName;
		if (!algorithmName) {
			throw new Error('Algorithms not initialized.');
		}
		this.publicKeyAlgorithmName = algorithmName;
	}

	public handleMessage(
		message: AuthenticationMessage,
		cancellation?: CancellationToken,
	): void | Promise<void> {
		if (message instanceof AuthenticationSuccessMessage) {
			return this.handleSuccessMessage(message);
		} else if (message instanceof AuthenticationFailureMessage) {
			return this.handleFailureMessage(message);
		} else if (message instanceof AuthenticationRequestMessage) {
			return this.handleAuthenticationRequestMessage(message, cancellation);
		} else if (message instanceof AuthenticationInfoRequestMessage) {
			return this.handleInfoRequestMessage(message, cancellation);
		} else if (message instanceof AuthenticationInfoResponseMessage) {
			return this.handleInfoResponseMessage(message, cancellation);
		} else if (message instanceof PublicKeyOKMessage) {
			// Not handled.
		} else {
			// Ignore unrecognized authentication messages.
		}
	}

	private async handleAuthenticationRequestMessage(
		message: AuthenticationRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.sessionAuthenticating,
			`Authentication request: ${message.methodName}`,
		);

		let methodName: AuthenticationMethod | null = message.methodName!;
		if (!this.session.config.authenticationMethods.includes(methodName)) {
			methodName = null;
		}

		if (
			methodName === AuthenticationMethod.publicKey ||
			methodName === AuthenticationMethod.hostBased
		) {
			const publicKeymessage = message.convertTo(new PublicKeyRequestMessage());
			this.setCurrentRequest(publicKeymessage);
			return this.handlePublicKeyRequestMessage(publicKeymessage, cancellation);
		} else if (methodName === AuthenticationMethod.password) {
			const passwordMessage = message.convertTo(new PasswordRequestMessage());
			this.setCurrentRequest(passwordMessage);
			return this.handlePasswordRequestMessage(passwordMessage, cancellation);
		} else if (methodName === AuthenticationMethod.keyboardInteractive) {
			this.setCurrentRequest(message);
			return this.beginInteractiveAuthentication(message, cancellation);
		} else if (methodName === AuthenticationMethod.none) {
			this.setCurrentRequest(message);
			return this.handleAuthenticating(
				new SshAuthenticatingEventArgs(SshAuthenticationType.clientNone, {
					username: message.username,
				}),
				cancellation,
			);
		} else {
			this.setCurrentRequest(null);
			const failureMessage = new AuthenticationFailureMessage();
			failureMessage.methodNames = [
				AuthenticationMethod.publicKey,
				AuthenticationMethod.password,
				AuthenticationMethod.hostBased,
			];
			await this.session.sendMessage(failureMessage, cancellation);
		}
	}

	private setCurrentRequest(message: AuthenticationRequestMessage | null) {
		this.currentRequestMessage = message;

		const protocol = this.session.protocol;
		if (protocol) {
			protocol.messageContext = message?.methodName ?? null;
		}
	}

	private async handlePublicKeyRequestMessage(
		message: PublicKeyRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		const publicKeyAlg = this.session.config.getPublicKeyAlgorithm(message.keyAlgorithmName!);
		if (!publicKeyAlg) {
			const failureMessage = new AuthenticationFailureMessage();
			failureMessage.methodNames = [
				AuthenticationMethod.publicKey,
				AuthenticationMethod.password,
			];
			await this.session.sendMessage(failureMessage, cancellation);
			return;
		}

		const publicKey = publicKeyAlg.createKeyPair();
		await publicKey.setPublicKeyBytes(message.publicKey!);

		let args: SshAuthenticatingEventArgs;
		if (message.methodName === AuthenticationMethod.hostBased) {
			args = new SshAuthenticatingEventArgs(SshAuthenticationType.clientHostBased, {
				username: message.username ?? '',
				publicKey: publicKey,
				clientHostname: message.clientHostname,
				clientUsername: message.clientUsername,
			});
		} else if (!message.hasSignature) {
			args = new SshAuthenticatingEventArgs(SshAuthenticationType.clientPublicKeyQuery, {
				username: message.username ?? '',
				publicKey: publicKey,
			});
		} else {
			// Verify that the signature matches the public key.
			const signature = publicKeyAlg.readSignatureData(message.signature!);

			const sessionId = this.session.sessionId;
			if (sessionId == null) {
				throw new Error('Session ID not initialized.');
			}

			const writer = new SshDataWriter(
				Buffer.alloc(sessionId.length + message.payloadWithoutSignature!.length + 20),
			);
			writer.writeBinary(sessionId);
			writer.write(message.payloadWithoutSignature!);

			const signedData = writer.toBuffer();
			const verifier = publicKeyAlg.createVerifier(publicKey);
			const verified = await verifier.verify(signedData, signature);
			if (!verified) {
				await this.handleAuthenticationFailure(
					'Public key authentication failed: invalid signature.',
					cancellation,
				);
			}

			args = new SshAuthenticatingEventArgs(SshAuthenticationType.clientPublicKey, {
				username: message.username ?? '',
				publicKey: publicKey,
			});
		}

		// Raise an Authenticating event that allows handlers to do additional verification
		// of the client's username and public key.
		await this.handleAuthenticating(args, cancellation);
	}

	private async handlePasswordRequestMessage(
		message: PasswordRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		// Raise an Authenticating event that allows handlers to do verification
		// of the client's username and password.
		const args = new SshAuthenticatingEventArgs(SshAuthenticationType.clientPassword, {
			username: message.username ?? '',
			password: message.password ?? '',
		});
		await this.handleAuthenticating(args, cancellation);
	}

	private async beginInteractiveAuthentication(
		message: AuthenticationRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		// Raise an Authenticating event that allows the server to interactively prompt for
		// information from the client.
		const args = new SshAuthenticatingEventArgs(SshAuthenticationType.clientInteractive, {
			username: message.username,
		});
		await this.handleAuthenticating(args, cancellation);
	}

	private async handleInfoRequestMessage(
		message: AuthenticationInfoRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		// Raise an Authenticating event that allows the client to respond to interactive prompts
		// and provide requested information to the server.
		const args = new SshAuthenticatingEventArgs(SshAuthenticationType.clientInteractive, {
			infoRequest: message,
		});
		await this.handleAuthenticating(args, cancellation);
	}

	private async handleInfoResponseMessage(
		message: AuthenticationInfoResponseMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		// Raise an Authenticating event that allows the server to process the client's responses
		// to interactive prompts, and request further info if necessary.
		const args = new SshAuthenticatingEventArgs(SshAuthenticationType.clientInteractive, {
			username: this.currentRequestMessage?.username,
			infoResponse: message,
		});
		await this.handleAuthenticating(args, cancellation);
	}

	private async handleAuthenticating(
		args: SshAuthenticatingEventArgs,
		cancellation?: CancellationToken,
	) {
		if (!this.currentRequestMessage) {
			throw new SshConnectionError(
				'No current authentication request.',
				SshDisconnectReason.protocolError,
			);
		}

		args.cancellation = this.disposeCancellationSource.token;

		let authenticatedPrincipal: object | null = null;
		try {
			authenticatedPrincipal = await (<any>this.session).raiseAuthenticatingEvent(args);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.authenticationError,
				`Error while authenticating client: ${e.message}`,
				e,
			);
			authenticatedPrincipal = null;
		}

		if (authenticatedPrincipal) {
			if (args.authenticationType === SshAuthenticationType.clientPublicKeyQuery) {
				const publicKeyRequest = <PublicKeyRequestMessage>this.currentRequestMessage;
				const okMessage = new PublicKeyOKMessage();
				okMessage.keyAlgorithmName = publicKeyRequest.keyAlgorithmName;
				okMessage.publicKey = publicKeyRequest.publicKey;

				this.setCurrentRequest(null);
				await this.session.sendMessage(okMessage, cancellation);
			} else {
				this.session.principal = authenticatedPrincipal;

				const serviceName = this.currentRequestMessage.serviceName;
				if (serviceName) {
					this.session.activateService(serviceName);
				}

				this.trace(
					TraceLevel.Info,
					SshTraceEventIds.sessionAuthenticated,
					`${SshAuthenticationType[args.authenticationType]} authentication succeeded.`,
				);

				this.setCurrentRequest(null);
				await this.session.sendMessage(new AuthenticationSuccessMessage(), cancellation);

				(this.session as SshServerSession)?.handleClientAuthenticated();
			}
		} else if (
			args.authenticationType === SshAuthenticationType.clientInteractive &&
			!this.session.isClientSession &&
			args.infoRequest
		) {
			// Server authenticating event-handler supplied an info request.
			await this.sendMessage(args.infoRequest, cancellation);
		} else if (
			args.authenticationType === SshAuthenticationType.clientInteractive &&
			this.session.isClientSession &&
			args.infoResponse
		) {
			// Client authenticating event-handler supplied an info response.
			await this.sendMessage(args.infoResponse, cancellation);
		} else {
			this.setCurrentRequest(null);
			await this.handleAuthenticationFailure(
				`${SshAuthenticationType[args.authenticationType]} authentication failed.`,
			);
		}
	}

	private async handleAuthenticationFailure(
		message: string,
		cancellation?: CancellationToken,
	): Promise<void> {
		this.authenticationFailureCount++;

		this.trace(TraceLevel.Warning, SshTraceEventIds.clientAuthenticationFailed, message);

		const failureMessage = new AuthenticationFailureMessage();
		failureMessage.methodNames = this.session.config.authenticationMethods;
		await this.session.sendMessage(failureMessage, cancellation);

		// Allow trying again with another authentication method. But prevent unlimited tries.
		if (this.authenticationFailureCount >= this.session.config.maxClientAuthenticationAttempts) {
			await this.session.close(
				SshDisconnectReason.noMoreAuthMethodsAvailable,
				'Authentication failed.',
			);
		}
	}

	public async authenticateClient(
		credentials: SshClientCredentials,
		cancellation?: CancellationToken,
	): Promise<void> {
		this.clientAuthenticationMethods = new Queue<{
			method: AuthenticationMethod;
			handler: (cancellation?: CancellationToken) => Promise<void>;
		}>();
		const configuredMethods = this.session.config.authenticationMethods;

		if (configuredMethods.includes(AuthenticationMethod.publicKey)) {
			for (const publicKey of credentials.publicKeys ?? []) {
				if (!publicKey) continue;

				const username = credentials.username ?? '';
				let privateKey: KeyPair | null = publicKey;
				const privateKeyProvider = credentials.privateKeyProvider;

				this.clientAuthenticationMethods.enqueue({
					method: AuthenticationMethod.publicKey,
					handler: async (cancellation2) => {
						if (!privateKey!.hasPrivateKey) {
							if (privateKeyProvider == null) {
								throw new Error('A private key provider is required.');
							}

							privateKey = await privateKeyProvider(
								publicKey,
								cancellation2 ?? CancellationToken.None,
							);
						}

						if (privateKey) {
							await this.requestPublicKeyAuthentication(username, privateKey, cancellation2);
						} else {
							await this.session.close(SshDisconnectReason.authCancelledByUser);
						}
					},
				});
			}
		}

		if (configuredMethods.includes(AuthenticationMethod.password)) {
			const passwordCredentialProvider = credentials.passwordProvider;
			if (passwordCredentialProvider) {
				this.clientAuthenticationMethods.enqueue({
					method: AuthenticationMethod.password,
					handler: async (cancellation2) => {
						const passwordCredentialPromise = passwordCredentialProvider(
							cancellation2 ?? CancellationToken.None,
						);
						const passwordCredential = passwordCredentialPromise
							? await passwordCredentialPromise
							: null;
						if (passwordCredential) {
							await this.requestPasswordAuthentication(
								passwordCredential[0] ?? '',
								passwordCredential[1],
								cancellation2,
							);
						} else {
							await this.session.close(SshDisconnectReason.authCancelledByUser);
						}
					},
				});
			} else if (credentials.password) {
				const username = credentials.username ?? '';
				const password = credentials.password;
				this.clientAuthenticationMethods.enqueue({
					method: AuthenticationMethod.password,
					handler: async (cancellation2) => {
						await this.requestPasswordAuthentication(username, password, cancellation2);
					},
				});
			}
		}

		// Only add None or Interactive methods if no client credentials were supplied.
		if (this.clientAuthenticationMethods.size === 0) {
			const username = credentials.username ?? '';

			if (configuredMethods.includes(AuthenticationMethod.none)) {
				this.clientAuthenticationMethods.enqueue({
					method: AuthenticationMethod.none,
					handler: async (cancellation2) => {
						await this.requestUsernameAuthentication(username, cancellation2);
					},
				});
			}

			if (configuredMethods.includes(AuthenticationMethod.keyboardInteractive)) {
				this.clientAuthenticationMethods.enqueue({
					method: AuthenticationMethod.keyboardInteractive,
					handler: async (cancellation2) => {
						await this.requestInteractiveAuthentication(username, cancellation2);
					},
				});
			}

			if (this.clientAuthenticationMethods.size === 0) {
				throw new Error(
					'Could not prepare request for authentication method(s): ' +
						configuredMethods.join(', ') +
						'. Supply client credentials or enable none or interactive authentication methods.',
				);
			}
		}

		// Auth request messages all include a request the for the server to activate the connection
		// service . Go ahead and activate it on the client side too; if authentication fails then
		// a following channel open request will fail anyway.
		this.session.activateService(ConnectionService);

		const firstAuthMethod = this.clientAuthenticationMethods.dequeue()!;
		await firstAuthMethod.handler(cancellation);
	}

	private async requestUsernameAuthentication(
		username: string,
		cancellation?: CancellationToken,
	): Promise<void> {
		const authMessage = new AuthenticationRequestMessage();
		authMessage.serviceName = ConnectionService.serviceName;
		authMessage.methodName = AuthenticationMethod.none;
		authMessage.username = username;
		this.setCurrentRequest(authMessage);
		await this.session.sendMessage(authMessage, cancellation);
	}

	public async requestPublicKeyAuthentication(
		username: string,
		key: KeyPair,
		cancellation?: CancellationToken,
	): Promise<void> {
		const algorithm = this.session.config.publicKeyAlgorithms.find(
			(a) => a?.keyAlgorithmName === key.keyAlgorithmName,
		);
		if (!algorithm) {
			throw new Error(
				`Public key algorithm '${key.keyAlgorithmName}' is not in session config.`,
			);
		}

		const authMessage = new PublicKeyRequestMessage();
		authMessage.serviceName = ConnectionService.serviceName;
		authMessage.username = username;
		authMessage.keyAlgorithmName = algorithm.name;
		authMessage.publicKey = (await key.getPublicKeyBytes(algorithm.name))!;
		authMessage.signature = await this.createAuthenticationSignature(authMessage, algorithm, key);
		this.setCurrentRequest(authMessage);
		await this.session.sendMessage(authMessage, cancellation);
	}

	public async requestPasswordAuthentication(
		username: string,
		password: string | null,
		cancellation?: CancellationToken,
	): Promise<void> {
		const authMessage = new PasswordRequestMessage();
		authMessage.serviceName = ConnectionService.serviceName;
		authMessage.username = username;
		authMessage.password = password;
		this.setCurrentRequest(authMessage);
		await this.session.sendMessage(authMessage, cancellation);
	}

	private async requestInteractiveAuthentication(
		username: string,
		cancellation?: CancellationToken,
	): Promise<void> {
		const authMessage = new AuthenticationRequestMessage();
		authMessage.serviceName = ConnectionService.serviceName;
		authMessage.methodName = AuthenticationMethod.keyboardInteractive;
		authMessage.username = username;
		this.setCurrentRequest(authMessage);
		await this.session.sendMessage(authMessage, cancellation);
	}

	private async handleFailureMessage(message: AuthenticationFailureMessage): Promise<void> {
		this.setCurrentRequest(null);

		while (this.clientAuthenticationMethods?.size) {
			const nextAuthMethod = this.clientAuthenticationMethods.dequeue()!;

			// Skip client auth methods that the server did not suggest.
			if (message.methodNames?.includes(nextAuthMethod.method)) {
				await nextAuthMethod.handler(this.disposeCancellationSource.token);
				return;
			}
		}

		(<SshClientSession>this.session).onAuthenticationComplete(false);
	}

	private handleSuccessMessage(message: AuthenticationSuccessMessage): void {
		this.setCurrentRequest(null);
		(<SshClientSession>this.session).onAuthenticationComplete(true);
	}

	private async createAuthenticationSignature(
		requestMessage: PublicKeyRequestMessage,
		algorithm: PublicKeyAlgorithm,
		key: KeyPair,
	): Promise<Buffer> {
		const sessionId = this.session.sessionId;
		if (sessionId == null) {
			throw new Error('Session ID not initialized.');
		}

		const writer = new SshDataWriter(
			Buffer.alloc(
				requestMessage.publicKey!.length + (requestMessage.username || '').length + 400,
			),
		);
		writer.writeBinary(sessionId);
		writer.writeByte(requestMessage.messageType);
		writer.writeString(requestMessage.username || '', 'utf8');
		writer.writeString(requestMessage.serviceName || '', 'ascii');
		writer.writeString(AuthenticationMethod.publicKey, 'ascii');
		writer.writeBoolean(true);
		writer.writeString(requestMessage.keyAlgorithmName!, 'ascii');
		writer.writeBinary(requestMessage.publicKey!);

		const signer = algorithm.createSigner(key);
		const signature = await signer.sign(writer.toBuffer());
		return algorithm.createSignatureData(signature);
	}

	public dispose() {
		try {
			this.disposeCancellationSource.cancel();
			this.disposeCancellationSource.dispose();
		} catch {}

		super.dispose();
	}
}
