//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken } from 'vscode-jsonrpc';
import { KeyPair, PrivateKeyProvider } from './algorithms/publicKeyAlgorithm';

/**
 * Provides a username and password for client authentication.
 *
 * If no username/password is available or the user cancels, a null result
 * may be returned. If the session disconnects before this callback returns,
 * the cancellation token will be cancelled.
 */
type PasswordCredentialProvider = (
	cancellation: CancellationToken,
) => Promise<[string, string] | null>;

/**
 * Defines credentials and/or credential callbacks for authenticating an SSH client session.
 */
export interface SshClientCredentials {
	/**
	 * Gets or sets the username for client authentication.
	 */
	username?: string;

	/**
	 * Gets or sets the password for client authentication.
	 *
	 * A `PasswordProvider` callback may be set instead of supplying a username
	 * and password up front.
	 *
	 * If neither a password, nor public keys, nor any provider callback are specified, then
	 * the client will attempt to authenticate with only the username, which may or may not be
	 * allowed by the server.
	 *
	 * If both public key and password credentials are set, then public key authentication
	 * will be attempted first.
	 */
	password?: string;

	/**
	 * Gets or sets a callback for getting a username and password when requested.
	 */
	passwordProvider?: PasswordCredentialProvider;

	/**
	 * Gets or sets public keys for client authentication.
	 *
	 * The key pair objects may optionally include the private keys; alternatively loading of the
	 * private keys may be delayed until requested, if a `privateKeyProvider` is specified.
	 */
	publicKeys?: KeyPair[];

	/**
	 * Gets or sets a callback for loading the private keys when requested.
	 */
	privateKeyProvider?: PrivateKeyProvider;
}

/**
 * Defines credentials and/or credential callbacks for authenticating an SSH server session.
 */
export interface SshServerCredentials {
	/**
	 * Gets or sets public keys for server authentication.
	 *
	 * The key pair objects may optionally include the private keys; alternatively loading of the
	 * private keys may be delayed until requested, if a `privateKeyProvider` is specified.
	 */
	publicKeys: KeyPair[];

	/**
	 * Gets or sets a callback for loading the private keys when requested.
	 */
	privateKeyProvider?: PrivateKeyProvider;
}
