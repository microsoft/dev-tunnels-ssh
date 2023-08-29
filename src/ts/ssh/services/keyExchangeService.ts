//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { SshSession } from '../sshSession';
import { SshServerSession } from '../sshServerSession';
import { SshService } from './sshService';
import { BigInt } from '../io/bigInt';
import {
	KeyExchangeInitMessage,
	KeyExchangeMessage,
	KeyExchangeDhReplyMessage,
	KeyExchangeDhInitMessage,
	NewKeysMessage,
} from '../messages/kexMessages';
import {
	KeyExchange,
	PublicKeyAlgorithm,
	KeyPair,
	algorithmNames,
	EncryptionAlgorithm,
	HmacAlgorithm,
	HmacInfo,
	MessageSigner,
	MessageVerifier,
} from '../algorithms/sshAlgorithms';
import { SshDataWriter } from '../io/sshData';
import { SshConnectionError } from '../errors';
import { SshDisconnectReason } from '../messages/transportMessages';
import { SshSessionAlgorithms } from '../sshSessionAlgorithms';
import { CancellationToken } from 'vscode-jsonrpc';
import { ConnectionService } from './connectionService';
import { serviceActivation } from './serviceActivation';
import { SshTraceEventIds, TraceLevel } from '../trace';

class ExchangeContext {
	public discardGuessedInit?: boolean;
	public keyExchange?: string;
	public publicKey?: string;
	public clientEncryption?: string;
	public serverEncryption?: string;
	public clientHmac?: string;
	public serverHmac?: string;
	public clientCompression?: string;
	public serverCompression?: string;
	public clientKexInitPayload?: Buffer;
	public serverKexInitPayload?: Buffer;
	public exchangeValue?: Buffer;
	public exchange?: KeyExchange;
	public newAlgorithms?: SshSessionAlgorithms;
	public isExtensionInfoRequested?: boolean;
}

const serverExtensionInfoSignal = 'ext-info-s';
const clientExtensionInfoSignal = 'ext-info-c';

@serviceActivation({ serviceRequest: KeyExchangeService.serviceName })
export class KeyExchangeService extends SshService {
	public static readonly serviceName = 'ssh-keyexchange';

	private isInitialExchange: boolean = false;
	private exchangeContext: ExchangeContext | null = null;

	public constructor(session: SshSession) {
		super(session);
	}

	public get exchanging(): boolean {
		return !!this.exchangeContext;
	}

	public hostKey?: KeyPair;

	public async startKeyExchange(
		isInitialExchange: boolean,
	): Promise<[KeyExchangeInitMessage, KeyExchangeDhInitMessage | null]> {
		this.isInitialExchange = isInitialExchange;
		this.exchangeContext = new ExchangeContext();
		const kexInitMessage = this.createKeyExchangeInitMessage();
		let kexGuessMessage: KeyExchangeDhInitMessage | null = null;

		if (this.session.isClientSession) {
			if (isInitialExchange && this.session.config.enableKeyExchangeGuess) {
				kexGuessMessage = await this.createKeyExchangeGuessMessage();
				kexInitMessage.firstKexPacketFollows = !!kexGuessMessage;
			}

			this.exchangeContext.clientKexInitPayload = kexInitMessage.toBuffer();
		} else {
			this.exchangeContext.serverKexInitPayload = kexInitMessage.toBuffer();
		}

		return [kexInitMessage, kexGuessMessage];
	}

	public finishKeyExchange(): SshSessionAlgorithms {
		if (!this.exchangeContext) {
			throw new SshConnectionError(
				'Key exchange not started.',
				SshDisconnectReason.protocolError,
			);
		}

		const newAlgorithms = this.exchangeContext!.newAlgorithms;
		if (!newAlgorithms) {
			throw new SshConnectionError(
				'Key exchange not completed.',
				SshDisconnectReason.protocolError,
			);
		}

		newAlgorithms.isExtensionInfoRequested = this.exchangeContext?.isExtensionInfoRequested;
		this.exchangeContext = null;
		return newAlgorithms;
	}

	public abortKeyExchange(): void {
		this.exchangeContext = null;
	}

	private createKeyExchangeInitMessage(): KeyExchangeInitMessage {
		// Reference RFC 8308: Signaling of Extension Negotiation in Key Exchange.
		const extinfo = this.session.isClientSession ?
			clientExtensionInfoSignal : serverExtensionInfoSignal;

		const config = this.session.config;
		const message = new KeyExchangeInitMessage();
		message.keyExchangeAlgorithms = algorithmNames(config.keyExchangeAlgorithms).concat(extinfo);
		message.serverHostKeyAlgorithms = this.getPublicKeyAlgorithms();
		message.encryptionAlgorithmsClientToServer = message.encryptionAlgorithmsServerToClient =
			algorithmNames(config.encryptionAlgorithms);
		message.macAlgorithmsClientToServer = message.macAlgorithmsServerToClient = algorithmNames(
			config.hmacAlgorithms,
		);
		message.compressionAlgorithmsClientToServer = message.compressionAlgorithmsServerToClient =
			algorithmNames(config.compressionAlgorithms);
		message.languagesClientToServer = [''];
		message.languagesServerToClient = [''];
		message.firstKexPacketFollows = false;
		message.reserved = 0;

		return message;
	}

	/**
	 * Gets the list of public key algorithms that the current session can support.
	 * For a server session the list is filtered based on the available private keys.
	 */
	private getPublicKeyAlgorithms(): string[] {
		let publicKeyAlgorithms = [...this.session.config.publicKeyAlgorithms];

		if (publicKeyAlgorithms.length > 1 && !this.session.isClientSession) {
			const privateKeyAlgorithms = (<SshServerSession>this.session).credentials?.publicKeys?.map(
				(k) => k.keyAlgorithmName,
			);
			if (privateKeyAlgorithms) {
				publicKeyAlgorithms = publicKeyAlgorithms.filter(
					(a) => a && privateKeyAlgorithms.includes(a.keyAlgorithmName),
				);
			}
		}

		const publicKeyAlgorithmNames = algorithmNames(publicKeyAlgorithms);
		return publicKeyAlgorithmNames;
	}

	private async createKeyExchangeGuessMessage(): Promise<KeyExchangeDhInitMessage | null> {
		if (!this.exchangeContext) {
			throw new Error('Key exchange was not started.');
		}

		// Select the first key exchange algorithm as the "guess". (They are in preferential order.)
		const kexAlgorithm = this.session.config.keyExchangeAlgorithms[0];
		if (!kexAlgorithm) {
			return null;
		}

		this.exchangeContext.keyExchange = kexAlgorithm.name;

		this.exchangeContext.exchange = kexAlgorithm.createKeyExchange();
		this.exchangeContext.exchangeValue = await this.exchangeContext.exchange.startKeyExchange();

		const guess = new KeyExchangeDhInitMessage();
		guess.e = this.exchangeContext.exchangeValue;
		return guess;
	}

	public handleMessage(
		message: KeyExchangeMessage,
		cancellation?: CancellationToken,
	): void | Promise<void> {
		if (message instanceof KeyExchangeInitMessage) {
			return this.handleInitMessage(message, cancellation);
		} else if (message instanceof KeyExchangeDhInitMessage) {
			return this.handleDhInitMessage(message, cancellation);
		} else if (message instanceof KeyExchangeDhReplyMessage) {
			return this.handleDhReplyMessage(message, cancellation);
		} else {
			throw new Error(`Message not implemented: ${message}`);
		}
	}

	private async handleInitMessage(
		message: KeyExchangeInitMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (!this.exchangeContext) {
			throw new Error('Key exchange was not started.');
		}

		const config = this.session.config;
		this.exchangeContext.keyExchange = this.chooseAlgorithm(
			'KeyExchange',
			algorithmNames(config.keyExchangeAlgorithms),
			message.keyExchangeAlgorithms,
		);

		if (this.exchangeContext.keyExchange === 'none') {
			this.trace(
				TraceLevel.Info,
				SshTraceEventIds.algorithmNegotiation,
				'Client and server negotiated no security. Cancelling key-exchange.',
			);

			// The connection service is normally activated after authentication. But when there is
			// no key-exchange there will be no authentication, so connections must be enabled now.
			this.session.activateService(ConnectionService);

			this.exchangeContext.newAlgorithms = new SshSessionAlgorithms();
			await this.session.handleNewKeysMessage(new NewKeysMessage(), cancellation);
			return;
		}

		this.exchangeContext.publicKey = this.chooseAlgorithm(
			'PublicKey',
			this.getPublicKeyAlgorithms(),
			message.serverHostKeyAlgorithms,
		);
		this.exchangeContext.clientEncryption = this.chooseAlgorithm(
			'ClientEncryption',
			algorithmNames(config.encryptionAlgorithms),
			message.encryptionAlgorithmsClientToServer,
		);
		this.exchangeContext.serverEncryption = this.chooseAlgorithm(
			'ServerEncryption',
			algorithmNames(config.encryptionAlgorithms),
			message.encryptionAlgorithmsServerToClient,
		);
		this.exchangeContext.clientHmac = this.chooseAlgorithm(
			'ClientHmac',
			algorithmNames(config.hmacAlgorithms),
			message.macAlgorithmsClientToServer,
		);
		this.exchangeContext.serverHmac = this.chooseAlgorithm(
			'ServerHmac',
			algorithmNames(config.hmacAlgorithms),
			message.macAlgorithmsServerToClient,
		);
		this.exchangeContext.clientCompression = this.chooseAlgorithm(
			'ClientCompression',
			algorithmNames(config.compressionAlgorithms),
			message.compressionAlgorithmsClientToServer,
		);
		this.exchangeContext.serverCompression = this.chooseAlgorithm(
			'ServerCompression',
			algorithmNames(config.compressionAlgorithms),
			message.compressionAlgorithmsServerToClient,
		);

		if (this.session.isClientSession) {
			this.exchangeContext.serverKexInitPayload = message.toBuffer();

			// If the exchange value is already initialized then this side sent a guess.
			const alreadySentGuess = !!this.exchangeContext.exchangeValue;

			// Check if the negotiated algorithm is the one preferred by THIS side.
			// This means if there was a "guess" at kex initialization then it was correct.
			const negotiatedKexAlgorithmIsPreferred =
				this.exchangeContext.keyExchange === config.keyExchangeAlgorithms[0]?.name;

			// If a guess was not sent, or the guess was wrong, send the init message now.
			if (!alreadySentGuess || !negotiatedKexAlgorithmIsPreferred) {
				const kexAlgorithm = config.getKeyExchangeAlgorithm(this.exchangeContext.keyExchange!)!;
				this.exchangeContext.exchange = kexAlgorithm.createKeyExchange();
				this.exchangeContext.exchangeValue =
					await this.exchangeContext.exchange.startKeyExchange();

				const reply = new KeyExchangeDhInitMessage();
				reply.e = this.exchangeContext.exchangeValue;
				await this.session.sendMessage(reply, cancellation);
			} else {
				this.trace(
					TraceLevel.Verbose,
					SshTraceEventIds.algorithmNegotiation,
					'Already sent correct guess for key-exchange init.',
				);
			}

			this.exchangeContext.isExtensionInfoRequested =
				this.isInitialExchange &&
				message.keyExchangeAlgorithms?.includes(serverExtensionInfoSignal);
		} else {
			if (message.firstKexPacketFollows) {
				// The remote side indicated it is sending a guess immediately following.
				// Check if the negotiated algorithm is the one preferred by the OTHER side.
				// If so, the following "guess" will be correct. Otherwise it must be ignored.
				const negotiatedKexAlgorithmIsPreferred =
					this.exchangeContext.keyExchange === message.keyExchangeAlgorithms?.[0];
				const guessResult = negotiatedKexAlgorithmIsPreferred ? 'correct' : 'incorrect';
				this.trace(
					TraceLevel.Verbose,
					SshTraceEventIds.algorithmNegotiation,
					`Client's KeyExchange guess was ${guessResult}.`,
				);
				this.exchangeContext.discardGuessedInit = !negotiatedKexAlgorithmIsPreferred;
			}

			this.exchangeContext.clientKexInitPayload = message.toBuffer();
			this.exchangeContext.isExtensionInfoRequested =
				this.isInitialExchange &&
				message.keyExchangeAlgorithms?.includes(clientExtensionInfoSignal);
		}
	}

	private async handleDhInitMessage(
		message: KeyExchangeDhInitMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (this.session.isClientSession) {
			return;
		}

		const serverSession = this.session as SshServerSession;

		if (
			!this.exchangeContext ||
			!this.exchangeContext.keyExchange ||
			!this.exchangeContext.publicKey
		) {
			throw new SshConnectionError(
				'Key exchange not started.',
				SshDisconnectReason.protocolError,
			);
		}

		if (this.exchangeContext.discardGuessedInit) {
			// Algorithm negotiation determined that an incorrect guess would be received.
			this.exchangeContext.discardGuessedInit = false;
			return;
		}

		const kexAlg = this.session.config.getKeyExchangeAlgorithm(this.exchangeContext.keyExchange);
		if (!kexAlg) {
			throw new SshConnectionError(
				'Key exchange not supported for algorithm: ' + this.exchangeContext.keyExchange,
				SshDisconnectReason.keyExchangeFailed,
			);
		}

		const publicKeyAlg = this.session.config.getPublicKeyAlgorithm(
			this.exchangeContext.publicKey,
		);
		if (!publicKeyAlg) {
			throw new SshConnectionError(
				'Public key algorithm not supported: ' + this.exchangeContext.publicKey,
				SshDisconnectReason.keyExchangeFailed,
			);
		}

		let privateKey: KeyPair | null = null;
		if (serverSession.credentials?.publicKeys) {
			const publicKey = serverSession.credentials.publicKeys.find(
				(k) => k.keyAlgorithmName === publicKeyAlg.keyAlgorithmName,
			);
			privateKey = publicKey ?? null;
			if (privateKey?.hasPrivateKey === false) {
				if (!serverSession.credentials.privateKeyProvider) {
					throw new Error('A private key provider is required.');
				}

				privateKey = await serverSession.credentials.privateKeyProvider(
					publicKey!,
					cancellation ?? CancellationToken.None,
				);
			}
		}

		if (privateKey == null) {
			throw new SshConnectionError(
				'Private key not found for algorithm: ' + this.exchangeContext.publicKey,
				SshDisconnectReason.keyExchangeFailed,
			);
		}

		const clientEncryption = this.session.config.getEncryptionAlgorithm(
			this.exchangeContext.clientEncryption!,
		);
		const serverEncryption = this.session.config.getEncryptionAlgorithm(
			this.exchangeContext.serverEncryption!,
		);
		const serverHmac = this.session.config.getHmacAlgorithm(this.exchangeContext.serverHmac!);
		const clientHmac = this.session.config.getHmacAlgorithm(this.exchangeContext.clientHmac!);

		const keyExchange = kexAlg.createKeyExchange();
		const clientExchangeValue = message.e || Buffer.alloc(0);
		const serverExchangeValue = await keyExchange.startKeyExchange();
		const sharedSecret = await keyExchange.decryptKeyExchange(clientExchangeValue);
		const hostKeyAndCerts = await privateKey.getPublicKeyBytes(publicKeyAlg.name);
		if (!hostKeyAndCerts) {
			throw new SshConnectionError('Public key not set.', SshDisconnectReason.keyExchangeFailed);
		}

		const exchangeHash = await this.computeExchangeHash(
			keyExchange,
			hostKeyAndCerts,
			clientExchangeValue,
			serverExchangeValue,
			sharedSecret,
		);

		if (!this.session.sessionId) {
			this.session.sessionId = exchangeHash;
		}

		const [
			clientCipherIV,
			serverCipherIV,
			clientCipherKey,
			serverCipherKey,
			clientHmacKey,
			serverHmacKey,
		] = await this.computeKeys(
			keyExchange,
			sharedSecret,
			exchangeHash,
			clientEncryption,
			serverEncryption,
			clientHmac,
			serverHmac,
		);

		const cipher =
			(await serverEncryption?.createCipher(true, serverCipherKey!, serverCipherIV!)) ?? null;
		const decipher =
			(await clientEncryption?.createCipher(false, clientCipherKey!, clientCipherIV!)) ?? null;
		const signer = (await serverHmac?.createSigner(serverHmacKey!)) ?? null;
		const verifier = (await clientHmac?.createVerifier(clientHmacKey!)) ?? null;

		const algorithms = new SshSessionAlgorithms();
		algorithms.publicKeyAlgorithmName = this.exchangeContext.publicKey;
		algorithms.cipher = cipher;
		algorithms.decipher = decipher;
		algorithms.signer = signer;
		algorithms.verifier = verifier;
		algorithms.messageSigner = (cipher as HmacInfo)?.authenticatedEncryption
			? <MessageSigner>(<any>cipher)
			: signer;
		algorithms.messageVerifier = (decipher as HmacInfo)?.authenticatedEncryption
			? <MessageVerifier>(<any>decipher)
			: verifier;
		algorithms.compressor = this.session.config.getCompressionAlgorithm(
			this.exchangeContext.serverCompression!,
		);
		algorithms.decompressor = this.session.config.getCompressionAlgorithm(
			this.exchangeContext.clientCompression!,
		);
		this.exchangeContext.newAlgorithms = algorithms;

		// Wipe the keys from memory after they are stored in native key objects.
		if (clientCipherIV) clientCipherIV.fill(0);
		if (clientCipherKey) clientCipherKey.fill(0);
		if (clientHmacKey) clientHmacKey.fill(0);
		if (serverCipherIV) serverCipherIV.fill(0);
		if (serverCipherKey) serverCipherKey.fill(0);
		if (serverHmacKey) serverHmacKey.fill(0);

		const exchangeSigner = publicKeyAlg.createSigner(privateKey);
		let signature = await exchangeSigner.sign(exchangeHash);
		signature = publicKeyAlg.createSignatureData(signature);

		const reply = new KeyExchangeDhReplyMessage();
		reply.hostKey = hostKeyAndCerts;
		reply.f = serverExchangeValue;
		reply.signature = signature;
		await this.session.sendMessage(reply, cancellation);
		await this.session.sendMessage(new NewKeysMessage(), cancellation);
	}

	private async handleDhReplyMessage(
		message: KeyExchangeDhReplyMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (!this.session.isClientSession) {
			return;
		}

		if (!this.exchangeContext) {
			throw new SshConnectionError(
				'Key exchange was not started.',
				SshDisconnectReason.protocolError,
			);
		}

		const config = this.session.config;
		const keyExchange = this.exchangeContext.exchange;
		const publicKeyAlgorithmName = this.exchangeContext.publicKey!;
		const publicKeyAlg = config.getPublicKeyAlgorithm(publicKeyAlgorithmName)!;
		const clientEncryption = config.getEncryptionAlgorithm(
			this.exchangeContext.clientEncryption!,
		);
		const serverEncryption = config.getEncryptionAlgorithm(
			this.exchangeContext.serverEncryption!,
		);
		const serverHmac = config.getHmacAlgorithm(this.exchangeContext.serverHmac!);
		const clientHmac = config.getHmacAlgorithm(this.exchangeContext.clientHmac!);

		const clientExchangeValue = this.exchangeContext.exchangeValue;
		const serverExchangeValue = message.f!;

		if (!keyExchange || !clientExchangeValue) {
			throw new SshConnectionError(
				'Failed to initialize crypto after key exchange.',
				SshDisconnectReason.keyExchangeFailed,
			);
		}

		// Load the server's public key bytes into a key-pair instance.
		this.hostKey = publicKeyAlg.createKeyPair();
		await this.hostKey.setPublicKeyBytes(message.hostKey!);

		const sharedSecret = await keyExchange.decryptKeyExchange(serverExchangeValue);
		const hostKeyAndCerts = message.hostKey!;
		const exchangeHash = await this.computeExchangeHash(
			keyExchange,
			hostKeyAndCerts,
			clientExchangeValue,
			serverExchangeValue,
			sharedSecret,
		);

		const signature = publicKeyAlg.readSignatureData(message.signature!);
		const exchangeVerifier = publicKeyAlg.createVerifier(this.hostKey);

		let verified: boolean;
		try {
			verified = await exchangeVerifier.verify(exchangeHash, signature);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.serverAuthenticationFailed,
				`Server public key verification error: ${e.message}`,
				e,
			);
			throw new SshConnectionError(
				`Server public key verification failed: ${e.message}`,
				SshDisconnectReason.hostKeyNotVerifiable,
			);
		}

		if (verified) {
			this.trace(
				TraceLevel.Verbose,
				SshTraceEventIds.sessionAuthenticated,
				'Server public key verification succeeded.',
			);
		} else {
			this.trace(
				TraceLevel.Warning,
				SshTraceEventIds.serverAuthenticationFailed,
				'Server public key verification failed.',
			);
			throw new SshConnectionError(
				'Server public key verification failed.',
				SshDisconnectReason.hostKeyNotVerifiable,
			);
		}

		if (this.session.sessionId == null) {
			this.session.sessionId = exchangeHash;
		}

		const [
			clientCipherIV,
			serverCipherIV,
			clientCipherKey,
			serverCipherKey,
			clientHmacKey,
			serverHmacKey,
		] = await this.computeKeys(
			keyExchange,
			sharedSecret,
			exchangeHash,
			clientEncryption,
			serverEncryption,
			clientHmac,
			serverHmac,
		);

		const cipher =
			(await clientEncryption?.createCipher(true, clientCipherKey!, clientCipherIV!)) ?? null;
		const decipher =
			(await serverEncryption?.createCipher(false, serverCipherKey!, serverCipherIV!)) ?? null;
		const signer = (await clientHmac?.createSigner(clientHmacKey!)) ?? null;
		const verifier = (await serverHmac?.createVerifier(serverHmacKey!)) ?? null;

		const algorithms = new SshSessionAlgorithms();
		algorithms.publicKeyAlgorithmName = publicKeyAlgorithmName;
		algorithms.cipher = cipher;
		algorithms.decipher = decipher;
		algorithms.signer = signer;
		algorithms.verifier = verifier;
		algorithms.messageSigner = (cipher as HmacInfo)?.authenticatedEncryption
			? <MessageSigner>(<any>cipher)
			: signer;
		algorithms.messageVerifier = (decipher as HmacInfo)?.authenticatedEncryption
			? <MessageVerifier>(<any>decipher)
			: verifier;
		algorithms.compressor = config.getCompressionAlgorithm(
			this.exchangeContext.clientCompression!,
		)!;
		algorithms.decompressor = config.getCompressionAlgorithm(
			this.exchangeContext.serverCompression!,
		)!;
		this.exchangeContext.newAlgorithms = algorithms;

		// Wipe the keys from memory after they are stored in native key objects.
		if (clientCipherIV) clientCipherIV.fill(0);
		if (clientCipherKey) clientCipherKey.fill(0);
		if (clientHmacKey) clientHmacKey.fill(0);
		if (serverCipherIV) serverCipherIV.fill(0);
		if (serverCipherKey) serverCipherKey.fill(0);
		if (serverHmacKey) serverHmacKey.fill(0);

		await this.session.sendMessage(new NewKeysMessage(), cancellation);
	}

	private chooseAlgorithm(
		label: string,
		localAlgorithms: string[],
		remoteAlgorithms?: string[],
	): string {
		// Ensure consistent results if the client and server list the same algorithms
		// in different order of preference.
		let serverAlgorithms: string[];
		let clientAlgorithms: string[];
		if (this.session.isClientSession) {
			serverAlgorithms = remoteAlgorithms || [];
			clientAlgorithms = localAlgorithms;
		} else {
			serverAlgorithms = localAlgorithms;
			clientAlgorithms = remoteAlgorithms || [];
		}

		const negotiationDetail =
			`${label} negotiation: ` +
			`Server (${serverAlgorithms.join(', ')}) ` +
			`Client (${clientAlgorithms.join(', ')})`;

		for (const client of clientAlgorithms) {
			for (const server of serverAlgorithms) {
				if (server === client) {
					const result = server;
					this.trace(
						TraceLevel.Info,
						SshTraceEventIds.algorithmNegotiation,
						`${negotiationDetail} => ${result}`,
					);
					return result;
				}
			}
		}

		throw new Error(`Failed ${negotiationDetail}`);
	}

	private async computeExchangeHash(
		kex: KeyExchange,
		hostKeyAndCerts: Buffer,
		clientExchangeValue: Buffer,
		serverExchangeValue: Buffer,
		sharedSecret: Buffer,
	): Promise<Buffer> {
		if (!this.session.remoteVersion) {
			throw new Error('Key exchange not completed.');
		}

		const writer = new SshDataWriter(Buffer.alloc(2048));

		if (this.session.isClientSession) {
			writer.writeString(SshSession.localVersion.toString(), 'ascii');
			writer.writeString(this.session.remoteVersion.toString(), 'ascii');
		} else {
			writer.writeString(this.session.remoteVersion.toString(), 'ascii');
			writer.writeString(SshSession.localVersion.toString(), 'ascii');
		}

		writer.writeBinary(this.exchangeContext!.clientKexInitPayload!);
		writer.writeBinary(this.exchangeContext!.serverKexInitPayload!);
		writer.writeBinary(hostKeyAndCerts);

		// These values are formatted as bigints (with leading zeroes if the first bit is high)
		// even though they might not really be bigints, depending on the key-exchange algorithm.
		writer.writeBigInt(BigInt.fromBytes(clientExchangeValue, { unsigned: true }));
		writer.writeBigInt(BigInt.fromBytes(serverExchangeValue, { unsigned: true }));
		writer.writeBigInt(BigInt.fromBytes(sharedSecret, { unsigned: true }));

		const hash = await kex.sign(writer.toBuffer());
		return hash;
	}

	private async computeKeys(
		keyExchange: KeyExchange,
		sharedSecret: Buffer,
		exchangeHash: Buffer,
		clientEncryption: EncryptionAlgorithm | null,
		serverEncryption: EncryptionAlgorithm | null,
		clientHmac: HmacAlgorithm | null,
		serverHmac: HmacAlgorithm | null,
	): Promise<
		[Buffer | null, Buffer | null, Buffer | null, Buffer | null, Buffer | null, Buffer | null]
	> {
		const writer = new SshDataWriter(
			Buffer.alloc(
				4 /* mpint header */ +
					sharedSecret.length +
					exchangeHash.length +
					Math.max(
						1 /* letter */ + (this.session.sessionId?.length ?? 0),
						keyExchange.digestLength,
					),
			),
		);
		writer.writeBinary(sharedSecret);
		writer.write(exchangeHash);
		const offset = writer.position;

		const clientCipherIV =
			clientEncryption &&
			(await this.computeKey(keyExchange, writer, offset, clientEncryption.blockLength, 'A'));
		const serverCipherIV =
			serverEncryption &&
			(await this.computeKey(keyExchange, writer, offset, serverEncryption.blockLength, 'B'));
		const clientCipherKey =
			clientEncryption &&
			(await this.computeKey(keyExchange, writer, offset, clientEncryption.keyLength, 'C'));
		const serverCipherKey =
			serverEncryption &&
			(await this.computeKey(keyExchange, writer, offset, serverEncryption.keyLength, 'D'));
		const clientHmacKey =
			clientHmac &&
			(await this.computeKey(keyExchange, writer, offset, clientHmac.keyLength, 'E'));
		const serverHmacKey =
			serverHmac &&
			(await this.computeKey(keyExchange, writer, offset, serverHmac.keyLength, 'F'));
		return [
			clientCipherIV,
			serverCipherIV,
			clientCipherKey,
			serverCipherKey,
			clientHmacKey,
			serverHmacKey,
		];
	}

	private async computeKey(
		keyExchange: KeyExchange,
		writer: SshDataWriter,
		writerOffset: number,
		blockSize: number,
		letter: string,
	): Promise<Buffer> {
		const keyBuffer = Buffer.alloc(blockSize);
		let keyBufferIndex = 0;
		let currentHashLength = 0;
		let currentHash: Buffer | null = null;

		if (!this.session.sessionId) {
			throw new Error('Session ID not set.');
		}

		while (keyBufferIndex < blockSize) {
			writer.position = writerOffset;

			if (!currentHash) {
				writer.writeByte(letter.charCodeAt(0));
				writer.write(this.session.sessionId);
			} else {
				writer.write(currentHash);
			}

			currentHash = await keyExchange.sign(writer.toBuffer());

			currentHashLength = Math.min(currentHash.length, blockSize - keyBufferIndex);
			currentHash.copy(keyBuffer, keyBufferIndex);

			keyBufferIndex += currentHashLength;
		}

		if (currentHash) {
			currentHash.fill(0);
		}

		return keyBuffer;
	}
}
