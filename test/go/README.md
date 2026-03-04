# Dev Tunnels SSH — Go Integration Tests

Integration tests for the Go SSH library that exercise the public API through
realistic client/server scenarios. These complement the ~679 unit tests colocated
with the source in `src/go/ssh/`.

## Directory Layout

```
test/go/
├── ssh-test/                          # Integration test suite (16 files, ~158 tests)
│   ├── go.mod                         # Separate module — imports SSH library as a dependency
│   ├── helpers/                       # Test infrastructure
│   │   ├── session_pair.go            # Connected client/server pair
│   │   ├── duplex_stream.go           # In-memory bidirectional streams
│   │   ├── mock_network_stream.go     # Network failure injection
│   │   ├── mock_random.go             # Deterministic RNG for reproducible tests
│   │   └── test_keys.go              # RSA/ECDSA key generation utilities
│   ├── auth_test.go                   # Password, none-method, failure, callback panic
│   ├── auth_pubkey_test.go            # Public key auth (RSA, ECDSA P-256/384/521)
│   ├── channel_test.go               # Channel open/close, data send/receive
│   ├── channel_flow_test.go           # EOF, window adjustments, flow control
│   ├── channel_request_test.go        # Custom requests, subsystem, shell, exec
│   ├── interop_test.go               # Cross-language tests (Go ↔ C#, TS, OpenSSH)
│   ├── keep_alive_test.go            # Ping/pong keep-alive messages
│   ├── key_exchange_test.go          # KEX negotiation (ECDH, DH, none)
│   ├── metrics_test.go              # Bytes sent/received tracking
│   ├── multi_channel_stream_test.go   # Multiple concurrent channels, isolation
│   ├── port_forwarding_test.go        # Remote/local port forwarding via SSH tunnels
│   ├── secure_stream_test.go          # Encrypted streams, algorithm variants
│   ├── service_test.go               # Service activation and lifecycle
│   ├── session_request_test.go        # Global session requests
│   ├── ssh_test.go                   # Core infrastructure, duplex streams, errors
│   └── stream_test.go               # Stream operations, disconnection handling
└── interop/                           # E2E helper binaries (also used by test/e2e/)
    ├── go/                            # Go interop helper (all modes)
    │   ├── go.mod
    │   └── main.go
    ├── ts/                            # TypeScript interop helper (echo only)
    │   └── interop-helper.js
    └── cs/                            # C# interop helper (echo only)
        ├── InteropHelper.csproj
        └── Program.cs
```

## Prerequisites

- **Go 1.21+**
- **testify** (`github.com/stretchr/testify`) — assertions and requirements
- For interop tests: `dotnet` (C#), `node` (TypeScript), or `ssh` (OpenSSH) on PATH

## Running Tests

```bash
# Run all integration tests (excluding interop)
cd test/go/ssh-test
go test -race -v ./...

# Run interop tests (requires external tool availability)
cd test/go/ssh-test
go test -race -v -tags=interop ./...

# Run a specific test file
go test -race -v -run TestForwardFromRemotePort ./...

# Run with short flag (skip slow tests)
go test -race -short ./...
```

The `-race` flag is recommended — all tests are race-detector clean.

## Test Infrastructure

### SessionPair — In-Memory Client/Server

The core testing pattern creates a connected client/server pair over in-memory
streams (no TCP, no flakiness, fast feedback):

```go
func TestExample(t *testing.T) {
    pair := helpers.NewSessionPair(t)
    defer pair.Close()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    pair.Connect(ctx)

    clientCh, serverCh := pair.OpenChannel(ctx)
    // ... test channel operations ...
}
```

`NewSessionPair` creates both sessions with no-security configuration (no
encryption overhead) and auto-approval authentication. For custom algorithms:

```go
pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
    ServerConfig: ssh.NewDefaultConfig(),
    ClientConfig: ssh.NewDefaultConfig(),
})
```

### MockNetworkStream — Failure Injection

Wraps any stream to simulate network failures:

```go
// Simulate immediate disconnect
pair.Disconnect(nil)

// Simulate partial message loss (50 bytes dropped before error)
pair.DisconnectWithDrop(errors.New("network failure"), 50)
```

### Authentication Patterns

```go
// Password authentication
pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
    if args.Username == "testuser" && args.Password == "s3cret!" {
        args.AuthenticationResult = struct{}{} // non-nil = approve
    }
    // leaving AuthenticationResult nil = reject
}

authenticated, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
    Username: "testuser",
    Password: "s3cret!",
})
```

```go
// Public key authentication
pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
    if args.AuthenticationType == ssh.AuthClientPublicKey {
        args.AuthenticationResult = struct{}{}
    }
}

authenticated, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
    Username:   "testuser",
    PublicKeys: []crypto.Signer{privateKey},
})
```

### Channel Data

```go
clientCh, serverCh := pair.OpenChannel(ctx)

// Set up receiver
received := make(chan []byte, 1)
serverCh.OnDataReceived = func(data []byte) {
    buf := make([]byte, len(data))
    copy(buf, data)
    received <- buf
    serverCh.AdjustWindow(uint32(len(data)))
}

// Send data
clientCh.Send(ctx, []byte("hello"))

// Wait for data
select {
case data := <-received:
    // verify data
case <-time.After(5 * time.Second):
    t.Fatal("timed out")
}
```

### Channel Requests

```go
clientCh, serverCh := pair.OpenChannel(ctx)

// Server handles requests
serverCh.OnRequest = func(args *ssh.RequestEventArgs) {
    if args.RequestType == "custom-type" {
        args.IsAuthorized = true
    }
}

// Client sends request
success, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
    RequestType: "custom-type",
    WantReply:   true,
})
```

### Port Forwarding

```go
// Register port forwarding service on both sides
serverConfig := ssh.NewNoSecurityConfig()
tcp.AddPortForwardingService(serverConfig)

clientConfig := ssh.NewNoSecurityConfig()
tcp.AddPortForwardingService(clientConfig)

pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
    ServerConfig: serverConfig,
    ClientConfig: clientConfig,
})
pair.Connect(ctx)

// Stream to a remote port through the SSH tunnel
pfs := tcp.GetPortForwardingService(&pair.ClientSession.Session)
stream, err := pfs.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
```

## Test Coverage by Feature

| File | Tests | What It Covers |
|------|-------|---------------|
| `auth_test.go` | 5 | None method, password, failure, callback panic, connection loss |
| `auth_pubkey_test.go` | 9 | RSA-SHA256/512, ECDSA P-256/384/521, key mismatch, failure |
| `channel_test.go` | 9 | Open (client/server), custom type, close lifecycle, data send |
| `channel_flow_test.go` | 6 | EOF, window adjust, bidirectional flow |
| `channel_request_test.go` | 17 | Custom types, subsystem, shell, exec, success/failure/no-reply |
| `interop_test.go` | 11 | Go↔C#, Go↔TS, Go↔OpenSSH interop over TCP |
| `keep_alive_test.go` | 4 | Ping/pong, idle timeout |
| `key_exchange_test.go` | 10 | ECDH (P-256/384/521), DH group14/16, none, renegotiation |
| `metrics_test.go` | 8 | Bytes sent/received, per-channel statistics |
| `multi_channel_stream_test.go` | 10 | 3+ concurrent channels, data isolation, close independence |
| `port_forwarding_test.go` | 16 | Remote forward, local forward, direct-tcpip, cancel, multi-hop |
| `secure_stream_test.go` | 8 | AES-GCM, AES-CTR, AES-CBC, HMAC variants, encrypted channels |
| `service_test.go` | 7 | Service registration, activation, lifecycle |
| `session_request_test.go` | 8 | Global requests, environment variables |
| `ssh_test.go` | 22 | DuplexStream infra, version exchange, error handling |
| `stream_test.go` | 8 | Stream read/write, disconnection detection |

## Relationship to Other Test Suites

These integration tests sit between two other test layers:

| Layer | Location | Count | Scope |
|-------|----------|-------|-------|
| **Unit tests** | `src/go/ssh/**/*_test.go` | ~679 | Individual functions, message serialization, edge cases |
| **Integration tests** | `test/go/ssh-test/` (this directory) | ~158 | Full client/server API scenarios over in-memory streams |
| **E2E tests** | `test/e2e/*.sh` | ~48 | Real TCP, real crypto, cross-implementation interop |

The integration tests mirror the C# (`test/cs/Ssh.Test/`) and TypeScript
(`test/ts/ssh-test/`) test suites for parity validation. Test names and
structure are aligned across all three implementations where possible.

## Interop Helpers

The `interop/` directory contains small CLI programs that wrap each SSH
implementation for cross-language E2E testing. These are used by both:
- **Integration tests** (`interop_test.go`) — launches helpers as subprocesses
- **E2E shell scripts** (`test/e2e/*.sh`) — orchestrates real TCP sessions

See `test/e2e/README.md` for full interop helper documentation and CLI interface.

### Go Helper Modes

The Go interop helper (`interop/go/main.go`) supports 8 test modes:

| Mode | Description |
|------|-------------|
| *(default)* | Echo — send data, verify server echoes it back |
| `large` | 1 MB transfer with SHA-256 hash verification |
| `multi` | 3 concurrent channels with isolated data streams |
| `pkauth` | Public key authentication (no password) |
| `portfwd` | SSH port forwarding (direct-tcpip) |
| `reconnect` | Session reconnection after simulated network failure |
| `concurrent-requests` | Non-blocking request dispatch verification |
| `pipe-request` | Channel request forwarding through piped sessions |

```bash
# Build the Go interop helper
cd test/go/interop/go
go build -o go-ssh-interop .

# Run a manual echo test
./go-ssh-interop server 9876 ecdh-sha2-nistp384 ecdsa-sha2-nistp384 \
    aes256-gcm@openssh.com hmac-sha2-256 &
./go-ssh-interop client 9876 ecdh-sha2-nistp384 ecdsa-sha2-nistp384 \
    aes256-gcm@openssh.com hmac-sha2-256
```
