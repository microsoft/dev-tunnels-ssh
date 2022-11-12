//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshService } from './sshService';
import { SshSession } from '../sshSession';
import {
	AuthenticationMessage,
	AuthenticationFailureMessage,
	PasswordRequestMessage,
	AuthenticationSuccessMessage,
	PublicKeyRequestMessage,
	AuthenticationRequestMessage,
	AuthenticationMethod,
	PublicKeyOKMessage,
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

/**
 * Handles SSH protocol messages related to client authentication.
 */
@serviceActivation({ serviceRequest: AuthenticationService.serviceName })
export class AuthenticationService extends SshService {
	public static readonly serviceName = 'ssh-userauth';

	public readonly publicKeyAlgorithmName: string;

	private clientAuthenticationMethods?: Queue<(cancellation?: CancellationToken) => Promise<void>>;
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
		} else {
			throw new Error(`Message not implemented: ${message}`);
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
		if (
			message.methodName === AuthenticationMethod.publicKey ||
			message.methodName === AuthenticationMethod.hostBased
		) {
			return this.handlePublicKeyRequestMessage(
				message.convertTo(new PublicKeyRequestMessage()),
				cancellation,
			);
		} else if (message.methodName === AuthenticationMethod.password) {
			return this.handlePasswordRequestMessage(
				message.convertTo(new PasswordRequestMessage()),
				cancellation,
			);
		} else if (message.methodName === AuthenticationMethod.none) {
			return this.handleAuthenticating(
				message,
				new SshAuthenticatingEventArgs(
					SshAuthenticationType.clientNone,
					{ username: message.username },
					cancellation,
				),
			);
		} else {
			const failureMessage = new AuthenticationFailureMessage();
			failureMessage.methodNames = [
				AuthenticationMethod.publicKey,
				AuthenticationMethod.password,
				AuthenticationMethod.hostBased,
			];
			await this.session.sendMessage(failureMessage, cancellation);
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
		await this.handleAuthenticating(message, args, cancellation);
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
		await this.handleAuthenticating(message, args, cancellation);
	}

	private async handleAuthenticating(
		requestMessage: AuthenticationRequestMessage,
		args: SshAuthenticatingEventArgs,
		cancellation?: CancellationToken,
	) {
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
				const publicKeyRequest = <PublicKeyRequestMessage>requestMessage;
				const okMessage = new PublicKeyOKMessage();
				okMessage.keyAlgorithmName = publicKeyRequest.keyAlgorithmName;
				okMessage.publicKey = publicKeyRequest.publicKey;
				await this.session.sendMessage(okMessage, cancellation);
			} else {
				this.session.principal = authenticatedPrincipal;

				if (requestMessage.serviceName) {
					this.session.activateService(requestMessage.serviceName);
				}

				this.trace(
					TraceLevel.Info,
					SshTraceEventIds.sessionAuthenticated,
					`${SshAuthenticationType[args.authenticationType]} authentication succeeded.`,
				);
				await this.session.sendMessage(new AuthenticationSuccessMessage(), cancellation);

				(this.session as SshServerSession)?.handleClientAuthenticated();
			}
		} else {
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
		failureMessage.methodNames = [
			AuthenticationMethod.publicKey,
			AuthenticationMethod.password,
			AuthenticationMethod.hostBased,
		];
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
		this.clientAuthenticationMethods = new Queue<
			(cancellation?: CancellationToken) => Promise<void>
		>();

		for (let publicKey of credentials.publicKeys ?? []) {
			if (!publicKey) continue;

			const username = credentials.username ?? '';
			let privateKey: KeyPair | null = publicKey;
			const privateKeyProvider = credentials.privateKeyProvider;

			this.clientAuthenticationMethods.enqueue(async (cancellation2) => {
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
			});
		}

		const passwordCredentialProvider = credentials.passwordProvider;
		if (passwordCredentialProvider) {
			this.clientAuthenticationMethods.enqueue(async (cancellation2) => {
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
			});
		} else if (credentials.password) {
			const username = credentials.username ?? '';
			const password = credentials.password;
			this.clientAuthenticationMethods.enqueue(async (cancellation2) => {
				await this.requestPasswordAuthentication(username, password, cancellation2);
			});
		}

		if (this.clientAuthenticationMethods.size === 0) {
			const username = credentials.username ?? '';
			this.clientAuthenticationMethods.enqueue(async (cancellation2) => {
				await this.requestUsernameAuthentication(username, cancellation2);
			});
		}

		const firstAuthMethod = this.clientAuthenticationMethods.dequeue()!;
		await firstAuthMethod(cancellation);
	}

	private async requestUsernameAuthentication(
		username: string,
		cancellation?: CancellationToken,
	): Promise<void> {
		const authMessage = new AuthenticationRequestMessage();
		authMessage.serviceName = ConnectionService.serviceName;
		authMessage.methodName = AuthenticationMethod.none;
		authMessage.username = username;
		await this.session.sendMessage(authMessage, cancellation);

		// Assume the included service request succeeds, without waiting for an auth success
		// message. If not, a following channel open request will fail anyway.
		this.session.activateService(ConnectionService);
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
		await this.session.sendMessage(authMessage, cancellation);

		if (this.clientAuthenticationMethods!.size === 0) {
			// There are no remaining auth methods. Assume the service request
			// included here succeeds, without waiting for an auth success message
			// If not, a following channel open request will fail anyway.
			this.session.activateService(ConnectionService);
		}
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
		await this.session.sendMessage(authMessage, cancellation);

		// Assume the included service request succeeds, without waiting for an auth success
		// message. If not, a following channel open request will fail anyway.
		this.session.activateService(ConnectionService);
	}

	private handleFailureMessage(message: AuthenticationFailureMessage): void {
		(<SshClientSession>this.session).onAuthenticationComplete(false);
	}

	private handleSuccessMessage(message: AuthenticationSuccessMessage): void {
		// The authentication request included the connection service name.
		// So it should be registered when authentication succeeded.
		this.session.activateService(ConnectionService);

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
