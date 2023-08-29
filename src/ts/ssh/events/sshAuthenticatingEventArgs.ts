//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { KeyPair } from '../algorithms/publicKeyAlgorithm';
import { CancellationToken } from 'vscode-jsonrpc';
import {
	AuthenticationInfoRequestMessage,
	AuthenticationInfoResponseMessage,
} from '../messages/authenticationMessages';

/**
 * Indicates the type of authentication being requested by an SSH client or server when an
 * `SshSession.authenticating` event is raised.
 */
export enum SshAuthenticationType {
	/**
	 * The client is attempting to authenticate without any credentials, or with only a
	 * username, or is merely checking what authentication methods are supported by the server.
	 *
	 * This event is raised by an `SshServerSession` when the client requests authentication
	 * using the "none" method. With this method, all of the credential properties in the
	 * `SshAuthenticatingEventArgs` are null.
	 *
	 * If the server app wishes to allow the client to authenticate with only a username, it may
	 * return a principal for the user. Othwerwise, the "none" authentication method fails, and
	 * the client may make a follow-up attempt to authenticate _with_ credentials.
	 */
	clientNone = 0,

	/**
	 * The client is attempting to authenticate with a client host public key.
	 *
	 * This event is raised by an `SshServerSession` when the client requests authentication
	 * using the "hostbased" method. The authentication handler must verify that the public key
	 * actually belongs to the client host name, _and_ that the network address the client
	 * connected from matches that host name, before returning a user principal to indicate
	 * successful authentication.
	 */
	clientHostBased = 1,

	/**
	 * The client is attempting to authenticate with a username and password credential.
	 *
	 * This event is raised by an `SshServerSession` when the client requests authentication
	 * using the "password" method. The authentication handler must verify that the username
	 * and password match known credentials on the server, before returning a user principal
	 * to indicate successful authentication.
	 */
	clientPassword = 2,

	/**
	 * The client is querying whether authentication may be possible for a specified username and
	 * public key without yet proving they have the private key.
	 *
	 * This event is raised by an `SshServerSession` when the client requests authentication
	 * using the "publickey" method _without_ providing a signature. The authentication handler
	 * must verify that the username and public key match known credentials on the server. If
	 * they match, an _unauthenticated_ principal should be returned. That indicates to the
	 * client that they may proceed to actually authenticate using that username and public key.
	 */
	clientPublicKeyQuery = 3,

	/**
	 * The client is attempting to authenticate with a username and public key credential.
	 *
	 * This event is raised by an `SshServerSession` when the client requests authentication
	 * using the "publickey" method, including a signature that proves they have the private
	 * key. The authentication handler must verify that the username and public key match known
	 * credentials on the server, before returning a user principal to indicate successful
	 * authentication.
	 */
	clientPublicKey = 4,

	/**
	 * The client is attempting to authenticate with interactive prompts.
	 *
	 * This event is raised by an `SshServerSession` when the client requests authentication
	 * using the "keyboard-interactive" method. The event may be raised multiple times for the
	 * same client to facilitate multi-step authentication.
	 */
	clientInteractive = 5,

	/**
	 * The server is attempting to authenticate with a public key credential.
	 *
	 * This event is raised by an `SshClientSession` when the server requests
	 * authentication by providing a signature that proves it has the private key. The client
	 * authentication handler must verify that the public key matches known public key(s) for
	 * that server. Or if not known (often the case for the first time connecting to that server)
	 * it may prompt the user to consent, and then save the public key for later reference. To
	 * indicate successful authentication, the client authentication handler returns a principal
	 * that represents the server.
	 */
	serverPublicKey = 10,
}

/**
 * Arguments for the `SshSession.Authenticating` event that is raised when a client
 * or server is requesting authentication.
 *
 * See `SshAuthenticationType` for a description of the different authentication methods and
 * how they map to properties in this event-args object.
 *
 * After validating the credentials, the event handler must set the `authenticationPromise`
 * property to a task that resolves to a principal object to indicate successful authentication.
 * That principal will then be associated with the session as the `SshSession.principal` property.
 */
export class SshAuthenticatingEventArgs {
	public constructor(
		public readonly authenticationType: SshAuthenticationType,
		{
			username,
			password,
			publicKey,
			clientHostname,
			clientUsername,
			infoRequest,
			infoResponse,
		}: {
			username?: string;
			password?: string;
			publicKey?: KeyPair;
			clientHostname?: string;
			clientUsername?: string;
			infoRequest?: AuthenticationInfoRequestMessage;
			infoResponse?: AuthenticationInfoResponseMessage;
		},
		cancellation?: CancellationToken,
	) {
		const validate = ({
			usernameRequired,
			passwordRequired,
			publicKeyRequired,
			clientHostnameRequired,
			clientUsernameRequired,
		}: {
			usernameRequired?: boolean;
			passwordRequired?: boolean;
			publicKeyRequired?: boolean;
			clientHostnameRequired?: boolean;
			clientUsernameRequired?: boolean;
		}) => {
			// This is intentionally not checking for empty strings. The authentication handler
			// should determine whether any non-null string values are valid.
			if ((typeof username === 'string') !== !!usernameRequired) return false;
			if ((typeof password === 'string') !== !!passwordRequired) return false;
			if (!!publicKey !== !!publicKeyRequired) return false;
			if ((typeof clientHostname === 'string') !== !!clientHostnameRequired) return false;
			if ((typeof clientUsername === 'string') !== !!clientUsernameRequired) return false;
			return true;
		};

		let valid: boolean;
		switch (authenticationType) {
			case SshAuthenticationType.clientNone:
				valid = validate({ usernameRequired: true });
				break;
			case SshAuthenticationType.clientHostBased:
				valid = validate({
					usernameRequired: true,
					publicKeyRequired: true,
					clientHostnameRequired: true,
					clientUsernameRequired: true,
				});
				break;
			case SshAuthenticationType.clientPassword:
				valid = validate({ usernameRequired: true, passwordRequired: true });
				break;
			case SshAuthenticationType.clientPublicKeyQuery:
			case SshAuthenticationType.clientPublicKey:
				valid = validate({ usernameRequired: true, publicKeyRequired: true });
				break;
			case SshAuthenticationType.serverPublicKey:
				valid = validate({ publicKeyRequired: true });
				break;
			case SshAuthenticationType.clientInteractive:
				valid = true;
				break;
			default:
				throw new Error(`Invalid authentication type: ${authenticationType}`);
		}

		if (!valid) {
			throw new Error(`Invalid arguments for authentication type: ${authenticationType}`);
		}

		this.username = username ?? null;
		this.password = password ?? null;
		this.publicKey = publicKey ?? null;
		this.clientHostname = clientHostname ?? null;
		this.clientUsername = clientUsername ?? null;
		this.infoRequest = infoRequest ?? null;
		this.infoResponse = infoResponse ?? null;
		this.cancellationValue = cancellation ?? CancellationToken.None;
	}

	/**
	 * Gets the client's username on the server; valid for client password authentication, client
	 * public-key authentication, or client host-based authentication.
	 */
	public readonly username: string | null;

	/**
	 * Gets the client's password for the server; valid only for client password authentication.
	 */
	public readonly password: string | null;

	/**
	 * Gets the server or client public key; valid for server authentication, client public-key
	 * authentication, or client host-based authentication.
	 */
	public readonly publicKey: KeyPair | null;

	/**
	 * Gets the client's host name; only valid for host-based authentication.
	 */
	public readonly clientHostname: string | null;

	/**
	 * Gets the client's username on their client host; only valid for host-based authentication.
	 */
	public readonly clientUsername: string | null;

	/**
	 * Gets or sets a request for more information for interactive authentication.
	 *
	 * The server may set this property when handling an interactive authenticating event to prompt
	 * for information/credentials. The client may read this property when handling an interactive
	 * authenticating event to determine what prompts to show and what information is requested.
	 */
	public infoRequest: AuthenticationInfoRequestMessage | null = null;

	/**
	 * Gets or sets the client's responses to interactive prompts; valid only for interactive
	 * authentication when information was previously requested via `InfoRequest`.
	 */
	public infoResponse: AuthenticationInfoResponseMessage | null = null;

	/**
	 * Gets or sets a task to be filled in by the event handler to indicate whether async
	 * authentication is successful.
	 *
	 * The authentication event handler must set this value to a task that resolves to a non-null
	 * principal object to indicate successful authentication of the server or client. Either a
	 * null task or a promise that resolves to null indicates an authentication failure.
	 */
	public authenticationPromise?: Promise<object | null>;

	/**
	 * Gets a token that is cancelled if the session ends before the authentication handler
	 * completes.
	 */
	public get cancellation(): CancellationToken {
		return this.cancellationValue;
	}

	/* @internal */
	public set cancellation(value: CancellationToken) {
		this.cancellationValue = value;
	}

	private cancellationValue: CancellationToken;

	public toString() {
		if (this.infoRequest) {
			return `Info request: ${this.infoRequest.name}`;
		} else if (this.infoResponse) {
			return `"${this.username}" info response`;
		} else if (this.password) {
			return `${this.username ? '"' + this.username + '" ' : ''}[password]`;
		} else if (this.publicKey) {
			return `${this.username ? '"' + this.username + '" ' : ''}[${
				this.publicKey.keyAlgorithmName
			}]`;
		} else {
			return `"${this.username}"`;
		}
	}
}
