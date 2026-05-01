# Dev Tunnels SSH Library for Go

A Secure Shell (SSH2) client and server protocol implementation for Go.

## Feature Highlights

- SSH over any `io.ReadWriteCloser` (including but not limited to TCP sockets)
- Configurable, extensible, negotiated algorithms for key exchange, encryption,
  integrity (HMAC), and public-key authentication
- Channel multiplexing, with ability to stream data to/from channels
- Extensibility for handling custom session requests and channel requests
- Session reconnection over new connections (preserving channels and state)
- Port forwarding (local-to-remote and remote-to-local)
- Session piping for relay/proxy scenarios
- Non-blocking per-channel request dispatch
- Compatible with common SSH software (tested against OpenSSH, C#, and
  TypeScript implementations)

## Requirements

- **Go 1.17+**
- No external dependencies (standard library only)

Crypto algorithms use Go's standard `crypto/*` packages, which delegate to
platform-native implementations (OpenSSL on Linux, Security.framework on macOS,
CNG on Windows).

## Packages

| Package | Import Path | Description |
|---------|-------------|-------------|
| `ssh`   | `github.com/microsoft/dev-tunnels-ssh/src/go/ssh`  | Core SSH protocol — sessions, channels, auth, config         |
| `keys`  | `github.com/microsoft/dev-tunnels-ssh/src/go/keys` | Key import/export (PKCS#1, PKCS#8, SEC1, OpenSSH, SSH2, JWK) |
| `tcp`   | `github.com/microsoft/dev-tunnels-ssh/src/go/tcp`  | TCP client/server wrappers and port forwarding service       |

## Basic Examples

Note: the client and server examples below use the `tcp.Client` and `tcp.Server`
convenience wrappers from the `tcp` package. For SSH over non-TCP streams, use
`ssh.NewClientSession` / `ssh.NewServerSession` directly with any
`io.ReadWriteCloser`.

### Client example

This example connects to an SSH server, authenticates with a password, opens a
channel, sends a command, and reads the result.

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/tcp"
)

func main() {
	client := tcp.NewClient(ssh.NewDefaultConfig())
	defer client.Close()

	ctx := context.Background()
	session, err := client.OpenSession(ctx, "localhost", 2222)
	if err != nil {
		log.Fatal(err)
	}

	// Handle server public key verification.
	session.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		// TODO: Validate the server's public key (args.PublicKey).
		// Return nil (don't set AuthenticationResult) to reject.
		args.AuthenticationResult = struct{}{}
	}

	// Authenticate with username and password.
	authenticated, err := session.Authenticate(ctx, &ssh.ClientCredentials{
		Username: "user",
		Password: "password",
	})
	if err != nil {
		log.Fatal(err)
	}
	if !authenticated {
		log.Fatal("authentication failed")
	}

	// Open a channel, send a request, and read the response.
	channel, err := session.OpenChannel(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// Read data from the channel.
	channel.SetDataReceivedHandler(func(data []byte) {
		fmt.Printf("Received: %s\n", data)
		channel.AdjustWindow(uint32(len(data)))
	})

	// Send data.
	if err := channel.Send(ctx, []byte("hello")); err != nil {
		log.Fatal(err)
	}

	// Wait for the session to end.
	<-session.Done()
}
```

### Server example

This example runs an SSH server that authenticates clients and echoes channel
data back to them.

```go
package main

import (
	"context"
	"log"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/tcp"
)

func main() {
	server := tcp.NewServer(ssh.NewDefaultConfig())

	// Generate a host key for server authentication.
	hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	if err != nil {
		log.Fatal(err)
	}
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	// Handle client authentication.
	server.OnSessionAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		// TODO: Validate credentials based on args.AuthenticationType.
		// For password auth: check args.Username and args.Password.
		// For public key auth: check args.PublicKey.
		// Set AuthenticationResult to non-nil to approve, leave nil to reject.
		args.AuthenticationResult = struct{}{}
	}

	// Handle new sessions — set up channel echo.
	server.OnSessionOpened = func(session *ssh.ServerSession) {
		go func() {
			ctx := context.Background()
			for {
				ch, err := session.AcceptChannel(ctx)
				if err != nil {
					return // session closed
				}
				go echoChannel(ch)
			}
		}()
	}

	// Listen on port 2222 (blocks until context cancelled or Close called).
	ctx := context.Background()
	if err := server.AcceptSessions(ctx, 2222, ""); err != nil {
		log.Fatal(err)
	}
}

func echoChannel(ch *ssh.Channel) {
	ch.SetDataReceivedHandler(func(data []byte) {
		_ = ch.Send(context.Background(), data)
		ch.AdjustWindow(uint32(len(data)))
	})
}
```

### Stream-based (non-TCP) example

SSH sessions can run over any `io.ReadWriteCloser`, not just TCP:

```go
// Create sessions with no TCP involved.
clientSession := ssh.NewClientSession(ssh.NewDefaultConfig())
serverSession := ssh.NewServerSession(ssh.NewDefaultConfig())

// Connect over any bidirectional stream (pipes, WebSockets, etc.).
go serverSession.Connect(ctx, serverStream)
clientSession.Connect(ctx, clientStream)
```

## Extensibility

This library prioritizes flexibility over completeness; if something SSH-related
is not implemented directly in the library, there is generally a way to plug in
that support without changing the library itself.

### Algorithms

Algorithms for an SSH session are configured using `SessionConfig`. Algorithm
lists are in preference order — client and server negotiate the most-preferred
algorithm supported by both.

```go
config := ssh.NewDefaultConfig()

// Restrict to specific algorithms.
config.KeyExchangeAlgorithms = []string{
	ssh.AlgoKexEcdhNistp384,
	ssh.AlgoKexEcdhNistp256,
}
config.EncryptionAlgorithms = []string{
	ssh.AlgoEncAes256Gcm,
}
```

Three built-in configurations are available:
- `NewDefaultConfig()` — secure defaults, recommended for production
- `NewDefaultConfigWithReconnect()` — adds reconnection protocol extensions
- `NewNoSecurityConfig()` — all "none" algorithms, for testing only

### Authentication

Two-way authentication is supported. A server or client MUST handle the
`OnAuthenticating` callback to confirm authentication, otherwise authentication
fails. For public keys, the library verifies the cryptographic signature
automatically. The callback decides whether to accept the identity.

```go
// Server: validate client credentials.
session.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
	switch args.AuthenticationType {
	case ssh.AuthClientPassword:
		if args.Username == "admin" && args.Password == "secret" {
			args.AuthenticationResult = struct{}{}
		}
	case ssh.AuthClientPublicKey:
		// args.PublicKey contains the verified key — check against allowed keys.
		args.AuthenticationResult = struct{}{}
	}
}

// Client: authenticate with public key.
authenticated, err := session.Authenticate(ctx, &ssh.ClientCredentials{
	Username:   "admin",
	PublicKeys: []ssh.KeyPair{privateKey},
})
```

### Key Management

The library does not implement any key management scheme, though the `keys`
package can import and export RSA and ECDSA keys in many formats:

```go
import "github.com/microsoft/dev-tunnels-ssh/src/go/keys"

// Import a key from PEM data (auto-detects format).
keyPair, err := keys.ImportKey(pemBytes, "passphrase")

// Import from file.
keyPair, err := keys.ImportKeyFile("/path/to/key.pem", "")

// Export to PKCS#8 PEM.
pemData, err := keys.ExportPrivateKey(keyPair, keys.KeyFormatPkcs8, "passphrase")

// Export public key in SSH wire format.
pubData, err := keys.ExportPublicKey(keyPair, keys.KeyFormatSSH)
```

Supported formats: PKCS#1, PKCS#8, SEC1, OpenSSH, SSH2 (RFC 4716), JWK.

### Channel Requests

A client or server can handle `Channel.OnRequest` to process custom channel
requests. The request can be inspected and authorized:

```go
serverCh.SetRequestHandler(func(args *ssh.RequestEventArgs) {
	if args.RequestType == "my-custom-request" {
		args.IsAuthorized = true
		// Process the request...
	}
})

// Client sends a custom request.
success, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
	RequestType: "my-custom-request",
	WantReply:   true,
})
```

### Services

Custom services can be registered on the session configuration to be activated
automatically when matching requests or channels are received:

```go
config.AddService("my-service", ssh.ServiceActivation{
	SessionRequest: "my-service",
}, func(session *ssh.Session, cfg interface{}) ssh.Service {
	return &MyService{session: session}
}, nil)
```

The port forwarding implementation in the `tcp` package is built on this
extensibility mechanism.

### Custom Message Handlers

The Go implementation exposes `MessageHandlers` on `SessionConfig`, allowing
applications to handle arbitrary SSH message types:

```go
config.MessageHandlers = map[byte]ssh.MessageHandler{
	200: func(payload []byte) error {
		// Handle custom message type 200.
		return nil
	},
}
```

## Port Forwarding

The `tcp` package provides SSH port forwarding (RFC 4254 sections 6-7):

```go
import "github.com/microsoft/dev-tunnels-ssh/src/go/tcp"

// Register port forwarding on both client and server configs.
config := ssh.NewDefaultConfig()
tcp.AddPortForwardingService(config)

// After connecting, get the port forwarding service.
pfs := tcp.GetPortForwardingService(&session.Session)

// Stream to a remote port (direct-tcpip channel).
stream, err := pfs.StreamToRemotePort(ctx, "127.0.0.1", 8080)

// Forward a local port to a remote port.
fwd, err := pfs.ForwardToRemotePort(ctx, 3000, "127.0.0.1", 8080)
defer fwd.Close()

// Forward a remote port to a local port.
err = pfs.ForwardFromRemotePort(ctx, 8080, "127.0.0.1", 3000)
```

## Reconnection

Sessions can reconnect over a new stream after a connection loss, preserving
all channels and state:

```go
// Use reconnect-enabled config.
config := ssh.NewDefaultConfigWithReconnect()

// Server: share reconnectable sessions across connections.
server := tcp.NewServer(config)

// Client: reconnect after connection loss.
err := client.ReconnectSession(ctx, session, host, port)
```

## Piping

An SSH server can create a "pipe" between two sessions to support relay
scenarios. Once piped, messages from one client are forwarded to the other:

```go
// Pipe two sessions bidirectionally.
err := ssh.PipeSession(ctx, sessionA, sessionB)

// Or pipe individual channels.
err := channelA.Pipe(ctx, channelB)
```

Piped messages include session requests, channel open requests, channel
requests (with payloads), channel data, and channel close. Each session is
independently authenticated and encrypted — the relay decrypts and re-encrypts
when forwarding.

## Algorithms

| Category | Algorithms |
|----------|-----------|
| **Key Exchange** | ecdh-sha2-nistp521, ecdh-sha2-nistp384, ecdh-sha2-nistp256, diffie-hellman-group16-sha512, diffie-hellman-group14-sha256 |
| **Public Key**   | rsa-sha2-512, rsa-sha2-256, ecdsa-sha2-nistp521, ecdsa-sha2-nistp384, ecdsa-sha2-nistp256 |
| **Encryption**   | aes256-gcm@openssh.com, aes256-cbc, aes256-ctr |
| **HMAC**         | hmac-sha2-512-etm@openssh.com, hmac-sha2-256-etm@openssh.com, hmac-sha2-512, hmac-sha2-256 |
| **Compression**  | none |

All algorithm lists support a `"none"` entry for no-security testing.

## Cross-Implementation Compatibility

This Go library is a full-parity implementation alongside the C# and TypeScript
versions of Dev Tunnels SSH. All three share:

- Identical algorithm negotiation and preference ordering
- Same protocol extensions (`session-reconnect`, `session-latency`,
  `open-channel-request`)
- Same authentication flow and event model
- Wire-compatible port forwarding, piping, and reconnection

Cross-implementation interoperability is validated by ~48 E2E tests that run
Go, C#, and TypeScript clients and servers against each other over real TCP.

## Future Work

### Compression
Currently only the "none" compression algorithm is implemented. Adding "zlib"
support would be straightforward, though compression at the SSH protocol level
is generally considered to have limited value in most scenarios.

### Shell / Terminal Support
The library doesn't currently offer built-in support for executing commands or
starting a persistent shell in the host OS on the server side, or for
integrating with a terminal on the client side.
