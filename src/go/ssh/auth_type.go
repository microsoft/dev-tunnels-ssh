// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

// AuthenticationType indicates the type of authentication being requested
// by an SSH client or server.
type AuthenticationType int

const (
	// AuthClientNone indicates the client is authenticating without credentials,
	// with only a username, or is checking what methods the server supports.
	AuthClientNone AuthenticationType = 0

	// AuthClientHostBased indicates the client is authenticating with a host public key.
	AuthClientHostBased AuthenticationType = 1

	// AuthClientPassword indicates the client is authenticating with username and password.
	AuthClientPassword AuthenticationType = 2

	// AuthClientPublicKeyQuery indicates the client is querying whether a public key
	// would be accepted, without proving possession of the private key.
	AuthClientPublicKeyQuery AuthenticationType = 3

	// AuthClientPublicKey indicates the client is authenticating with a public key,
	// including a signature proving possession of the private key.
	AuthClientPublicKey AuthenticationType = 4

	// AuthClientInteractive indicates the client is authenticating via
	// keyboard-interactive prompts.
	AuthClientInteractive AuthenticationType = 5

	// AuthServerPublicKey indicates the server is authenticating with its host key.
	AuthServerPublicKey AuthenticationType = 10
)
