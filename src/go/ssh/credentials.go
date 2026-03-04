// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import "context"

// PasswordProvider is an optional callback that lazily provides a username and password
// during authentication. This enables interactive prompting or deferred credential loading.
// If the provider returns an error, the session is closed with DisconnectAuthCancelledByUser.
// If the provider returns empty username and password, password auth is skipped.
type PasswordProvider func(ctx context.Context) (username string, password string, err error)

// ClientCredentials defines credentials for authenticating an SSH client session.
type ClientCredentials struct {
	Username   string
	Password   string
	PublicKeys []KeyPair

	// PasswordProvider is an optional callback that lazily provides a username and
	// password during authentication. When set, it is called instead of using the
	// static Username/Password fields for password authentication. This enables
	// interactive prompting or deferred credential loading, matching C#/TS
	// PasswordCredentialProvider behavior.
	PasswordProvider PasswordProvider

	// PrivateKeyProvider is an optional callback that provides a full key pair
	// (with private key material) given a public-key-only key pair. It is called
	// during authentication when a key in PublicKeys does not have HasPrivateKey() == true.
	// This enables deferred loading of private keys from secure storage.
	PrivateKeyProvider PrivateKeyProvider
}

// ServerCredentials defines credentials for authenticating an SSH server session.
type ServerCredentials struct {
	PublicKeys []KeyPair

	// PrivateKeyProvider is an optional callback that provides a full key pair
	// (with private key material) given a public-key-only key pair. It is called
	// during key exchange when the host key does not have HasPrivateKey() == true.
	// This enables deferred loading of private keys from secure storage.
	PrivateKeyProvider PrivateKeyProvider
}
