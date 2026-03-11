# Dev Tunnels SSH — Test Guide

This directory contains all tests for the Dev Tunnels SSH library across three
implementations (C#, TypeScript, Go) plus cross-implementation E2E validation.

## Directory Layout

```
test/
├── cs/                     # C# unit tests (xUnit)
│   └── Ssh.Test/           # 16 test files, ~185 tests
├── ts/                     # TypeScript unit tests (Mocha + @testdeck)
│   └── ssh-test/           # 18 test files, ~178 tests
├── go/                     # Go integration tests + interop helpers
│   ├── ssh-test/           # 16 integration test files, ~158 tests
│   └── interop/            # E2E helper binaries (Go, TS, C#)
│       ├── go/             # Go interop helper (all modes)
│       ├── ts/             # TS interop helper (echo only)
│       └── cs/             # C# interop helper (echo only)
├── e2e/                    # E2E shell scripts (~48 tests)
│   └── README.md           # Detailed E2E documentation
├── data/                   # Shared test keys (RSA, ECDSA, various formats)
└── README.md               # This file
```

Go unit tests (~679 tests) live alongside source in `src/go/ssh/**/*_test.go`,
not in this directory.

## Test Counts

| Platform    | Unit Tests | Integration | E2E  | Total   |
|-------------|-----------|-------------|------|---------|
| C#          | 185       | —           | 3    | 188     |
| TypeScript  | 178       | —           | 3    | 181     |
| Go          | 679       | 158         | 15   | 852     |
| Cross-impl  | —         | —           | 24   | 24      |
| **Total**   | **1,042** | **158**     | **48** | **1,248** |

## Running Tests

### C# (`test/cs/`)

```bash
# Prerequisites: .NET SDK 8.0+
dotnet test test/cs/Ssh.Test/Ssh.Test.csproj
```

- Framework: **xUnit** with `[Fact]` / `[Theory]` attributes
- Test helper: `SessionPair.cs` — creates in-memory client/server pairs
- Config: `xunit.runner.json`

### TypeScript (`test/ts/`)

```bash
# Prerequisites: Node.js 20+, built libraries
node build.js build   # Build everything first
node build.js test    # Run TS tests
```

- Framework: **Mocha** with `@testdeck/mocha` decorators (`@test`, `@slow`)
- Test helper: `sessionPair.ts` — creates in-memory client/server pairs
- Config: `tsconfig.json`, `package.json`
- Browser tests: `browserTests.ts` + `test.html` for Web Crypto validation

### Go Unit Tests (`src/go/ssh/`)

```bash
# Prerequisites: Go 1.21+
cd src/go
go test -race ./ssh/...
```

- Framework: **testing** (standard library)
- Test helper: `session_test.go` — `createSessionPair()` for in-memory pairs
- Tests are colocated with source (`*_test.go` files in each package)
- `-race` flag recommended — all tests are race-detector clean

### Go Integration Tests (`test/go/ssh-test/`)

```bash
cd test/go/ssh-test
go test -race -v ./...
```

- Larger integration-style tests that exercise the public API
- Separate `go.mod` — imports the SSH library as a dependency
- Tests mirror the C#/TS test files for parity validation

### E2E Tests (`test/e2e/`)

```bash
# Run everything (~48 tests, ~2 minutes)
./test/e2e/e2e-validate.sh

# See test/e2e/README.md for detailed documentation
```

- Real TCP sockets, real algorithm negotiation, real authentication
- Cross-implementation: Go↔C#, Go↔TS in both client/server directions
- 5 algorithm combinations covering all KEX/encryption/HMAC/pubkey families

## Feature Coverage Matrix

Features tested by each platform. **Unit** = unit/integration tests,
**E2E** = end-to-end over TCP.

| Feature                        | C# Unit | TS Unit | Go Unit | E2E           |
|--------------------------------|---------|---------|---------|---------------|
| **Session & Handshake**        |         |         |         |               |
| Key exchange (ECDH, DH)        | 22      | 17      | 37      | 5 combos      |
| Algorithm negotiation           | 4       | 4       | 29      | 5 combos      |
| Session lifecycle               | 22      | 17      | 36      | All tests     |
| **Authentication**             |         |         |         |               |
| Password                        | 22      | 17      | 52      | All tests     |
| Public key                      | 13      | 10      | 61      | pkauth mode   |
| Host-based (RFC 4252 §9)       | —       | —       | 9       | —             |
| **Channels**                   |         |         |         |               |
| Open / close lifecycle          | 35      | 18      | 34      | All tests     |
| Data send / receive             | 35      | 23      | 42      | All tests     |
| Channel requests & replies      | 35      | 18      | 46      | pipe-request  |
| Extended data (stderr)          | 35      | 18      | 9       | —             |
| Window / flow control           | 9       | 5       | 37      | large mode    |
| Signals (exit-status, etc.)     | 35      | 18      | 4       | —             |
| **Advanced Features**          |         |         |         |               |
| Non-blocking request dispatch   | —       | —       | 11      | concurrent    |
| Port forwarding                 | 31      | 28      | 16      | portfwd mode  |
| Reconnection                    | 18      | 18      | 90      | reconnect     |
| Channel.Pipe / PipeSession      | 13      | 14      | 35      | pipe-request  |
| Service activation              | 7       | 7       | 18      | All tests     |
| Extensible messages             | —       | —       | 4       | —             |
| Keep-alive                      | —       | —       | 7       | —             |
| **Crypto & Keys**              |         |         |         |               |
| Encryption (AES-GCM, CTR, CBC) | 4       | 4       | 24      | 5 combos      |
| HMAC (SHA2-256, SHA2-512, ETM) | 4       | 4       | 10      | 5 combos      |
| Key import/export               | —       | 10      | 22      | —             |
| **Infrastructure**             |         |         |         |               |
| Metrics                         | 8       | 8       | 21      | —             |
| Multi-channel isolation          | 9       | 5       | 22      | multi mode    |
| Large data (1 MB+)             | —       | —       | 6       | large mode    |
| Secure stream                   | 6       | 6       | 16      | All tests     |
| Wire format / serialization     | —       | —       | 160     | —             |
| **Cross-Implementation**       |         |         |         |               |
| Interop (Go↔C#, Go↔TS)        | —       | 2       | 16      | 24 tests      |
| Parity (matching C#/TS behavior)| —       | —       | 40      | —             |

### Reading the Matrix

- **Numbers** = approximate test count for that feature area
- **—** = no dedicated tests (may still be exercised incidentally)
- **E2E column** describes which mode/script covers the feature
- Go counts include both `src/go/ssh/` unit tests and `test/go/ssh-test/` integration tests

### Platform Strengths

- **C#** — Mature reference implementation. Strong channel, port forwarding,
  and reconnection coverage. Test patterns establish the behavioral contract
  that Go and TS implementations must match.

- **TypeScript** — Parallel to C# with near-identical test structure. Adds
  browser crypto validation and key import/export coverage. Port forwarding
  tests are the most thorough (28 tests).

- **Go** — Most comprehensive test suite (837 tests). Unique coverage areas:
  host-based auth, non-blocking request dispatch, extensible messages,
  keep-alive, wire format serialization (160 tests), and 40 explicit parity
  tests that validate behavioral alignment with C#/TS.

## Test Helpers & Shared Infrastructure

### In-Memory Session Pairs

All three platforms share the same testing pattern — an in-memory
client/server session pair connected by a duplex stream (no TCP):

| Platform | Helper                  | File                              |
|----------|-------------------------|-----------------------------------|
| C#       | `SessionPair`           | `test/cs/Ssh.Test/SessionPair.cs` |
| TypeScript | `createSessionPair()` | `test/ts/ssh-test/sessionPair.ts` |
| Go       | `createSessionPair()`   | `src/go/ssh/session_test.go`      |

### Test Keys (`test/data/`)

Shared key material used across all platforms:

| Key Type      | Formats Available                              |
|---------------|------------------------------------------------|
| RSA 2048-bit  | PKCS#1, PKCS#8, SSH2, OpenSSH, JWK (+ password-protected variants) |
| RSA 4096-bit  | PKCS#1, PKCS#8, SSH2, JWK                     |
| ECDSA P-384   | SEC1, PKCS#8, OpenSSH, JWK (+ password-protected variants) |
| ECDSA P-521   | SEC1, PKCS#8                                   |

Generated by `New-TestKeys.ps1`. Not all platforms support all formats — C#
supports SSH2/OpenSSH formats, TS supports JWK, Go supports PKCS#8/SEC1.

### Interop Helpers (`test/go/interop/`)

Small CLI programs wrapping each implementation for E2E tests:

| Helper | Language | Modes Supported |
|--------|----------|-----------------|
| `go-ssh-interop` | Go | default, large, multi, pkauth, portfwd, reconnect, concurrent-requests, pipe-request |
| `interop-helper.js` | TS | default (echo only) |
| `InteropHelper.csproj` | C# | default (echo only) |

All share the same CLI interface:
```
<binary> <server|client> <port> <kex> <pk> <enc> <hmac> [mode] [extra]
```

## Feature Parity Notes

The Go implementation was built to achieve full feature parity with C# and TS.
Key differences in test coverage reflect implementation differences:

| Feature | C# | TS | Go | Notes |
|---------|----|----|-----|-------|
| Host-based auth | Impl only | Impl only | Impl + tests | Go added tests as part of gap-filling |
| Non-blocking dispatch | Implicit (async/await) | Implicit (async/await) | Explicit (goroutines) | Go needs dedicated tests because the mechanism is different |
| Extensible messages | Not public API | Not public API | Public + tested | Go exposes `MessageHandlers` on config |
| Keep-alive | Tested elsewhere | Tested elsewhere | Dedicated tests | Go has standalone keep-alive test coverage |
| Wire format | No dedicated tests | No dedicated tests | 160 tests | Go validates serialization of every message type |
| Parity tests | — | — | 40 tests | Go explicitly validates it matches C#/TS behavior |
| Browser crypto | — | 2 tests | — | TS-only: Web Crypto API validation |
| Key format: JWK | — | 10 tests | — | TS-only format |
| Key format: SSH2/OpenSSH | Implicit | — | — | C#-only formats |

## Adding New Tests

When adding a feature or fixing a bug:

1. **Start with unit tests** in the implementation's test file. Use the
   in-memory session pair — no TCP, no flakiness, fast feedback.

2. **Add parity tests** (Go only) if the behavior must match C#/TS. Name
   the file `*_parity_test.go` and reference the C#/TS test being matched.

3. **Add E2E tests** only if the feature affects the wire protocol or
   cross-implementation interop. Add a mode to the Go interop helper and a
   new script in `test/e2e/`, then register it in `e2e-validate.sh`.

4. **Run the full suite** before submitting:
   ```bash
   # Go
   cd src/go && go test -race ./ssh/...

   # E2E (includes Go vet + unit tests as gate check)
   ./test/e2e/e2e-validate.sh
   ```
