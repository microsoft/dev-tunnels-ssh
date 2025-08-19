//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Emitter } from 'vscode-jsonrpc';
import {
	SshAlgorithm,
	SshAlgorithms,
	KeyExchangeAlgorithm,
	PublicKeyAlgorithm,
	EncryptionAlgorithm,
	HmacAlgorithm,
	CompressionAlgorithm,
} from './algorithms/sshAlgorithms';
import { SshServiceConstructor } from './services/sshService';
import { KeyExchangeService } from './services/keyExchangeService';
import { ConnectionService } from './services/connectionService';
import { AuthenticationService } from './services/authenticationService';
import { SshMessage, SshMessageConstructor } from './messages/sshMessage';
import { AuthenticationMethod } from './messages/authenticationMethod';

export enum SshProtocolExtensionNames {
	/**
	 * Lists host key signature algorithms enabled by the sender.
	 *
	 * This is a "standard" protocol extension supported by most SSH implementations.
	 */
	serverSignatureAlgorithms = 'server-sig-algs',

	/**
	 * An optimization that enables sending an initial channel request without
	 * waiting for a channel open confirmation message.
	 */
	openChannelRequest = 'open-channel-request@microsoft.com',

	/**
	 * Enables reconnecting to a session that was recently disconnected.
	 */
	sessionReconnect = 'session-reconnect@microsoft.com',

	/**
	 * Enables continual latency measurements between client and server.
	 *
	 * This extension requires that the reconnect extension is also enabled, because
	 * it leverages some of the session history info for reconnect to compute latency.
	 */
	sessionLatency = 'session-latency@microsoft.com',
}

/**
 * Specifies the sets of algorithms and other configuration for an SSH session.
 *
 * Each collection of algorithms is in order of preference. Server and client
 * negotiate the most-preferred algorithm that is supported by both.
 */
export class SshSessionConfiguration {
	public constructor(useSecurity: boolean = true) {
		this.protocolExtensions.push(SshProtocolExtensionNames.serverSignatureAlgorithms);
		this.protocolExtensions.push(SshProtocolExtensionNames.openChannelRequest);

		this.services.set(KeyExchangeService, null);
		this.services.set(ConnectionService, null);
		this.services.set(AuthenticationService, null);

		this.authenticationMethods.push(
			AuthenticationMethod.none,
			AuthenticationMethod.password,
			AuthenticationMethod.publicKey,
			AuthenticationMethod.keyboardInteractive,
		);

		for (const [messageKey, messageType] of SshMessage.index) {
			if (typeof messageKey === 'number') {
				this.messages.set(messageKey, messageType);
			} else {
				const [messageNumber, messageContext] = messageKey;
				let contextMessageTypes = this.contextualMessages.get(messageContext);
				if (!contextMessageTypes) {
					contextMessageTypes = new Map<number, SshMessageConstructor>();
					this.contextualMessages.set(messageContext, contextMessageTypes);
				}
				contextMessageTypes.set(messageNumber, messageType);
			}
		}

		if (useSecurity) {
			this.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.ecdhNistp384Sha384);
			this.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.ecdhNistp256Sha256);
			this.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.dhGroup16Sha512);
			this.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.dhGroup14Sha256);
			this.publicKeyAlgorithms.push(SshAlgorithms.publicKey.rsaWithSha512);
			this.publicKeyAlgorithms.push(SshAlgorithms.publicKey.rsaWithSha256);
			this.publicKeyAlgorithms.push(SshAlgorithms.publicKey.ecdsaSha2Nistp384);
			this.publicKeyAlgorithms.push(SshAlgorithms.publicKey.ecdsaSha2Nistp256);
			////this.encryptionAlgorithms.push(SshAlgorithms.encryption.aes256Cbc);
			this.encryptionAlgorithms.push(SshAlgorithms.encryption.aes256Gcm);
			this.encryptionAlgorithms.push(SshAlgorithms.encryption.aes256Ctr);
			this.hmacAlgorithms.push(SshAlgorithms.hmac.hmacSha512Etm);
			this.hmacAlgorithms.push(SshAlgorithms.hmac.hmacSha256Etm);
			this.hmacAlgorithms.push(SshAlgorithms.hmac.hmacSha512);
			this.hmacAlgorithms.push(SshAlgorithms.hmac.hmacSha256);
		} else {
			this.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.none);
			this.publicKeyAlgorithms.push(SshAlgorithms.publicKey.none);
			this.encryptionAlgorithms.push(SshAlgorithms.encryption.none);
			this.hmacAlgorithms.push(SshAlgorithms.hmac.none);
		}

		this.compressionAlgorithms.push(SshAlgorithms.compression.none);
	}

	/**
	 * Gets the protocol extensions that are enabled for the session.
	 */
	public readonly protocolExtensions: string[] = [];

	/**
	 * Gets a dictionary that maps from service types to service configuration objects.
	 *
	 * Service types must extend the `SshService` abstract class.
	 *
	 * The service configuration object is passed to the service constructor upon activation.
	 */
	public readonly services = new Map<SshServiceConstructor, any>();

	/**
	 * Adds a service to the configuration.
	 */
	public addService(serviceType: SshServiceConstructor, serviceConfig?: any) {
		if (this.services.has(serviceType)) {
			throw new Error('Duplicate service entry.');
		}
		this.services.set(serviceType, serviceConfig);
	}

	/**
	 * Gets the list of enabled authentication methods.
	 *
	 * Add or remove `AuthenticationMethod` constants to restrict which client authentication
	 * methods the client will try or the server will allow. In any case, the client or server must
	 * handle the `SshSession.onAuthenticating` event to perform authentication.
	 */
	public readonly authenticationMethods: AuthenticationMethod[] = [];

	/**
	 * Gets a dictionary that maps from known message numbers to message types.
	 *
	 * Message types must extend the `SshMessage` abstract class. Message subclasses that do
	 * not have a distinct message type from their base class must not be included in this map.
	 */
	public readonly messages = new Map<number, SshMessageConstructor>();

	/**
	 * Gets a dictionary that maps from message context to message type mappings for each context.
	 *
	 * Services like `AuthenticationService` may set the current message context to
	 * disambiguate when the same message number may be re-used in different contexts.
	 */
	public readonly contextualMessages = new Map<string, Map<number, SshMessageConstructor>>();

	/**
	 * Gets the collection of algorithms that are enabled for key exchange.
	 *
	 * Client and server sides negotiate which of these algorithms will be used.
	 *
	 * If this collection includes `null`, and if negotiation selects it, then the session is
	 * allowed to skip key exchange and connect with no security of any kind: No key exchange,
	 * no authentication, no encryption, no HMAC, and no compression.
	 */
	public readonly keyExchangeAlgorithms: (KeyExchangeAlgorithm | null)[] = [];

	/**
	 * Gets the collection of algorithms that are enabled for server (host) and client
	 * public-key authentication.
	 *
	 * Client and server sides negotiate which of these algorithms will be used.
	 */
	public readonly publicKeyAlgorithms: (PublicKeyAlgorithm | null)[] = [];

	/*
	 * Gets the collection of algorithms that are enabled for encryption.
	 *
	 * Client and server sides negotiate which of these algorithms will be used.
	 */
	public readonly encryptionAlgorithms: (EncryptionAlgorithm | null)[] = [];

	/**
	 * Gets the collection of algorithms that are enabled for message integrity (HMAC).
	 *
	 * Client and server sides negotiate which of these algorithms will be used.
	 */
	public readonly hmacAlgorithms: (HmacAlgorithm | null)[] = [];

	/**
	 * Gets the collection of algorithms that are enabled for message compression.
	 *
	 * Client and server sides negotiate which of these algorithms will be used.
	 */
	public readonly compressionAlgorithms: (CompressionAlgorithm | null)[] = [];

	public getKeyExchangeAlgorithm(name: string): KeyExchangeAlgorithm | null {
		return this.getAlgorithm(name, this.keyExchangeAlgorithms);
	}

	public getPublicKeyAlgorithm(name: string): PublicKeyAlgorithm | null {
		return this.getAlgorithm(name, this.publicKeyAlgorithms);
	}

	public getEncryptionAlgorithm(name: string): EncryptionAlgorithm | null {
		return this.getAlgorithm(name, this.encryptionAlgorithms);
	}

	public getHmacAlgorithm(name: string): HmacAlgorithm | null {
		return this.getAlgorithm(name, this.hmacAlgorithms);
	}

	public getCompressionAlgorithm(name: string): CompressionAlgorithm | null {
		return this.getAlgorithm(name, this.compressionAlgorithms);
	}

	private getAlgorithm<T extends SshAlgorithm>(name: string, collection: (T | null)[]): T | null {
		const algorithm = collection.find((a) => (a ? a.name === name : false));

		if (!algorithm) {
			if (name === 'none') {
				return null;
			}

			throw new Error('Algorithm not found: ' + name);
		}

		return algorithm;
	}

	private traceChannelDataValue = false;

	public get traceChannelData() {
		return this.traceChannelDataValue;
	}

	/**
	 * Enables tracing of all channel data messages.
	 *
	 * Unlike other configuration, this option may be adjusted any time while the session
	 * is active. Channel data tracing produces a large volume of trace events, so it is
	 * primarily meant only for debugging.
	 */
	public set traceChannelData(value: boolean) {
		if (value !== this.traceChannelDataValue) {
			this.traceChannelDataValue = value;
			this.configurationChangedEmitter.fire();
		}
	}

	private readonly configurationChangedEmitter = new Emitter<void>();

	/* @internal */
	public readonly onConfigurationChanged = this.configurationChangedEmitter.event;

	/**
	 * Gets or sets the number of times the server will allow a client to attempt to
	 * authenticate.
	 *
	 * The default value is 5.
	 *
	 * This setting applies only to server sessions. If the client has failed to authenticate
	 * after the maximum number of atttempts, the server will close the session.
	 *
	 * The SSH protocol allows a client to make multiple attempts to authenticate with
	 * the server, e.g. to find which public key algorithm a server will support, or to
	 * retry a mis-typed password. This maximum prevents unlimited retries, which would
	 * make it easier to "guess" a password.
	 *
	 * In certain applications the server may only support a single authentication method
	 * (which is not a typed password). Then it could be appropriate to set this value to 1.
	 */
	public maxClientAuthenticationAttempts = 5;

	/**
	 * Gets or sets whether the client sends a key-exchange "guess" message before receiving
	 * the server's key-exchange algorithm preferences, slightly reducing the time to connect.
	 *
	 * This setting only applies to client sessions. (The server always supports the option when
	 * used by a client.)
	 *
	 * The "guess" mechanism is somewhat ambiguously defined in the SSH protocol spec, and as
	 * a result is not implemented or incorrectly implemented by some server implementations,
	 * including older versions of this library. Therefore it is disabled in the default
	 * configuration, and should only be enabled when connecting to a known-good server.
	 */
	public enableKeyExchangeGuess = false;

	/**
	 * Gets or sets the keep-alive timeout in seconds.
	 * 
	 * When set to a value greater than 0, the session will send keep-alive messages
	 * at the specified interval to detect connection failures. If no response is received
	 * within the timeout period, the keep-alive failed event will be raised.
	 * 
	 * Set to 0 to disable keep-alive messages.
	 */
	private keepAliveTimeoutInSecondsValue = 0;

	public get keepAliveTimeoutInSeconds(): number {
		return this.keepAliveTimeoutInSecondsValue;
	}

	public set keepAliveTimeoutInSeconds(value: number) {
		if (this.keepAliveTimeoutInSecondsValue !== value) {
			this.keepAliveTimeoutInSecondsValue = value;
			this.configurationChangedEmitter.fire();
		}
	}

	/* @internal */
	public keyRotationThreshold = 512 * 1024 * 1024; // 0.5 GiB;
}
