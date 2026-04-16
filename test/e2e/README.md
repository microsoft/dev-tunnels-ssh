# Dev Tunnels SSH — E2E Test Guide

End-to-end tests that validate the Go, TypeScript, and C# SSH implementations
work correctly — both independently and when talking to each other.

## Why These Tests Exist

Unit tests verify individual components in isolation. These E2E tests prove
that a **real SSH session** over **real TCP sockets** can:

- Negotiate algorithms (key exchange, encryption, HMAC, public key)
- Authenticate a client to a server
- Open channels and transfer data
- Handle advanced features: reconnection, port forwarding, large transfers,
  multi-channel isolation, public key authentication, non-blocking request
  dispatch, and channel pipe request forwarding
- **Interoperate across implementations** — a Go client can talk to a C# server,
  a TS server can talk to a Go client, etc.

This catches protocol-level bugs that unit tests miss: wrong packet framing,
algorithm negotiation mismatches, endianness issues, and subtle timing problems.

## Quick Start

```bash
# Run the full suite (~48 tests, ~2 minutes)
./test/e2e/e2e-validate.sh

# Run a single suite
./test/e2e/e2e-go-selftest.sh
./test/e2e/e2e-ts-selftest.sh
./test/e2e/e2e-cs-selftest.sh
./test/e2e/e2e-go-reconnect.sh
./test/e2e/e2e-go-portfwd.sh
./test/e2e/e2e-go-concurrent-requests.sh
./test/e2e/e2e-go-pipe-request.sh
./test/e2e/e2e-interop.sh
```

## Prerequisites

| Requirement     | Version   | Required? | Notes                                          |
|-----------------|-----------|-----------|------------------------------------------------|
| Go              | 1.21+     | Yes       | Core implementation                            |
| Node.js         | 20.x+     | Yes       | TS implementation                              |
| .NET SDK        | 8.0+      | Optional  | C# tests skipped gracefully if missing         |
| Python 3        | Any       | Yes       | Used by `find_free_port()` utility             |
| bash            | 4.0+      | Yes       | Scripts use arrays, traps, process management  |

The orchestrator (`e2e-validate.sh`) builds everything automatically before
running tests, so you don't need to build manually.

## Test Suite Overview

| Script                           | What It Tests                        | Tests | Timeout    |
|----------------------------------|--------------------------------------|-------|------------|
| `e2e-validate.sh`                | Orchestrator — runs everything       | ~48   | 10 min     |
| `e2e-go-selftest.sh`             | Go client ↔ Go server                | 8     | 15s/test   |
| `e2e-ts-selftest.sh`             | TS client ↔ TS server                | 3     | 15s/test   |
| `e2e-cs-selftest.sh`             | C# client ↔ C# server                | 3     | 15s/test   |
| `e2e-go-reconnect.sh`            | Session reconnection                 | 3     | 15s/test   |
| `e2e-go-portfwd.sh`              | SSH port forwarding                  | 3     | 15s/test   |
| `e2e-go-concurrent-requests.sh`  | Non-blocking request dispatch        | 3     | 15s/test   |
| `e2e-go-pipe-request.sh`         | Channel.Pipe request forwarding      | 1     | 15s/test   |
| `e2e-interop.sh`                 | Cross-implementation interop         | 24    | 15s/test   |

---

## Algorithm Combinations

Tests exercise different cryptographic algorithm combinations to ensure the
implementations handle the full negotiation matrix. There are 5 standard
combinations used across the suite:

| # | Key Exchange                    | Public Key            | Encryption                    | HMAC                          |
|---|---------------------------------|-----------------------|-------------------------------|-------------------------------|
| 1 | ecdh-sha2-nistp384              | ecdsa-sha2-nistp384   | aes256-gcm@openssh.com        | hmac-sha2-256                 |
| 2 | ecdh-sha2-nistp256              | ecdsa-sha2-nistp256   | aes256-ctr                    | hmac-sha2-256-etm@openssh.com |
| 3 | diffie-hellman-group14-sha256   | rsa-sha2-256          | aes256-cbc                    | hmac-sha2-512                 |
| 4 | ecdh-sha2-nistp521              | ecdsa-sha2-nistp521   | aes256-gcm@openssh.com        | hmac-sha2-512-etm@openssh.com |
| 5 | diffie-hellman-group16-sha512   | rsa-sha2-512          | aes256-ctr                    | hmac-sha2-512-etm@openssh.com |

**TS limitation:** TypeScript does not support AES-CBC. When TS is involved,
combo 3 substitutes `aes256-ctr` for `aes256-cbc`.

Not every suite uses all 5 combos — the self-tests and feature scripts use 3
(a representative subset), while the interop tests use all 5.

---

## How the Tests Work

### Marker-Based Verification

Each test starts a **server** process and a **client** process. Both print
text markers to stdout as they reach key milestones. The test script captures
the output and greps for expected markers to determine pass/fail.

#### Client Markers

| Marker                    | Meaning                                  | Used In                    |
|---------------------------|------------------------------------------|----------------------------|
| `AUTHENTICATED`           | Client authenticated to server           | All modes                  |
| `CHANNEL_OPEN`            | SSH channel opened                       | Default, large, multi, pkauth |
| `ECHO_OK`                 | Echo data matched                        | Default, pkauth            |
| `LARGE_DATA_OK`           | 1 MB transferred, SHA-256 hash matched   | Large mode                 |
| `MULTI_CHANNEL_OK`        | All 3 channels echoed correctly          | Multi mode                 |
| `PK_AUTH_OK`              | Public key auth succeeded                | Pkauth mode                |
| `PORT_FORWARD_OK`         | Echo through forwarded port succeeded    | Portfwd mode               |
| `DISCONNECTED`            | Client detected TCP disconnect           | Reconnect mode             |
| `RECONNECT_OK`            | Session reconnected successfully         | Reconnect mode             |
| `ECHO_AFTER_RECONNECT_OK` | Echo works after reconnection            | Reconnect mode             |
| `CONCURRENT_REQUEST_OK`   | Non-blocking dispatch verified           | Concurrent-requests mode   |
| `PIPE_REQUEST_FORWARDED`  | Request forwarded through pipe           | Pipe-request mode          |
| `DONE`                    | Test completed                           | All modes                  |

#### Server Markers

| Marker                          | Meaning                              | Used In          |
|---------------------------------|--------------------------------------|------------------|
| `LISTENING`                     | Server ready, accepting connections  | All modes        |
| `LISTENING <ssh_port> <echo_port>` | Two ports ready (SSH + echo)      | Portfwd mode     |
| `RECONNECTED`                   | Server detected client reconnection  | Reconnect mode   |

### Test Execution Pattern

Every test follows the same basic flow:

```
1. Find a free TCP port
2. Start server in background, redirect output to temp log
3. Wait up to 15s for LISTENING marker in server log
4. Run client with 15s timeout, redirect output to temp log
5. Grep client log for expected markers
6. (For reconnect) Also grep server log for RECONNECTED
7. Record pass/fail, clean up processes and temp files
```

### Portable Timeout

The scripts use a portable timeout function that works on both macOS and Linux
(GNU `timeout` is not available on macOS by default):

```bash
run_with_timeout() {
  local secs="$1"; shift
  "$@" &
  local cmd_pid=$!
  ( sleep "$secs" && kill "$cmd_pid" 2>/dev/null ) &
  local timer_pid=$!
  wait "$cmd_pid" 2>/dev/null
  local exit_code=$?
  kill "$timer_pid" 2>/dev/null || true
  wait "$timer_pid" 2>/dev/null || true
  return "$exit_code"
}
```

---

## Individual Test Details

### Go Self-Test (`e2e-go-selftest.sh`)

**8 tests**: 5 algorithm combos + 3 feature modes.

The 5 algo combo tests each run a basic echo test — send `INTEROP_TEST_DATA`,
verify the server echoes it back. The 3 feature mode tests exercise:

| Mode     | Algo Combo | What It Tests                                               |
|----------|------------|-------------------------------------------------------------|
| `large`  | #1         | 1 MB deterministic data, SHA-256 hash verification          |
| `multi`  | #2         | 3 concurrent channels with isolated data streams            |
| `pkauth` | #4         | Public key authentication (no password)                     |

### TypeScript Self-Test (`e2e-ts-selftest.sh`)

**3 tests**: 3 algorithm combos (basic echo only).

Uses `node interop-helper.js` from `test/interop/ts/`. The TS helper
supports only the default echo mode — no feature modes.

Requires `NODE_PATH` pointing to built TS libraries at `out/lib/node_modules`.

### C# Self-Test (`e2e-cs-selftest.sh`)

**3 tests**: 3 algorithm combos (basic echo only).

Uses `dotnet run --project InteropHelper.csproj` from `test/interop/cs/`.
The C# helper supports only the default echo mode.

**Skipped automatically** if `dotnet` is not on PATH.

### Go Reconnect Test (`e2e-go-reconnect.sh`)

**3 tests**: 3 algorithm combos, all in `reconnect` mode.

Tests the session reconnection protocol extension:

1. Connect and authenticate
2. Open a channel, send data, verify echo
3. **Kill the TCP connection** (simulate network failure)
4. Open a new TCP connection to the same server
5. Reconnect the SSH session over the new connection
6. Send data on the **same channel**, verify echo still works

Checks 7 client markers + server `RECONNECTED` marker.

### Go Port Forwarding Test (`e2e-go-portfwd.sh`)

**3 tests**: 3 algorithm combos, all in `portfwd` mode.

Tests SSH direct-tcpip port forwarding:

1. Server starts an embedded TCP echo server on a random port
2. Server prints `LISTENING <ssh_port> <echo_port>` (test script parses both)
3. Client connects to SSH server, opens a forwarded stream to the echo port
4. Client sends data through the forwarded stream, verifies echo

The server outputs **two ports** on the `LISTENING` line — this is unique to
port forwarding mode and why it has its own script.

### Go Concurrent Requests Test (`e2e-go-concurrent-requests.sh`)

**3 tests**: 3 algorithm combos, all in `concurrent-requests` mode.

Tests the non-blocking request dispatch (per-channel goroutine model):

1. Server opens 2 channels
2. Channel 1 has a request handler that **blocks for 1 second**
3. Channel 2 echoes data normally
4. Client sends a blocking request on channel 1, then immediately sends data on channel 2
5. Channel 2 echo must arrive **within 500ms** — proving the dispatch loop is not blocked

This validates that the per-channel request goroutine model works over real TCP,
not just in-memory test streams.

### Go Pipe Request Test (`e2e-go-pipe-request.sh`)

**1 test**: 1 algorithm combo, in `pipe-request` mode.

Tests Channel.Pipe request forwarding through a PipeSession:

1. Server A accepts a connection and pipes it to an internal server B
2. Client sends a channel request to server A
3. The request is forwarded through the pipe to server B
4. Server B processes the request and sends a reply
5. The reply propagates back through the pipe to the client

Validates that channel requests (including reply propagation) work correctly
through piped sessions over real TCP.

### Cross-Implementation Interop (`e2e-interop.sh`)

**Up to 24 tests**: server/client pairings across Go, TS, C#.

#### Algorithm Combo Tests (20 tests)

4 pairings, each with 5 algorithm combos:

| Server | Client | Combos | Notes                                  |
|--------|--------|--------|----------------------------------------|
| C#     | Go     | 5      | Uses full combo set (with CBC)         |
| Go     | C#     | 5      | Uses full combo set (with CBC)         |
| TS     | Go     | 5      | Uses TS combo set (CTR instead of CBC) |
| Go     | TS     | 5      | Uses TS combo set (CTR instead of CBC) |

If C# is unavailable, only the TS↔Go pairings run (10 tests).

#### Feature Mode Tests (4 tests)

Go client feature modes tested against non-Go servers. The server just echoes
data — only the Go client has feature-specific logic.

| Server | Client | Mode    | Expected Marker      |
|--------|--------|---------|----------------------|
| TS     | Go     | `large` | `LARGE_DATA_OK`      |
| TS     | Go     | `multi` | `MULTI_CHANNEL_OK`   |
| C#     | Go     | `large` | `LARGE_DATA_OK`      |
| C#     | Go     | `multi` | `MULTI_CHANNEL_OK`   |

C# feature tests are skipped if dotnet is unavailable.

**Why only Go client?** The `large` and `multi` modes are client-side behaviors
(generating 1 MB data, opening 3 channels). The server only needs to echo,
which all implementations do by default.

**Why not `pkauth`/`portfwd`/`reconnect` cross-impl?** These require both
client and server to support the mode, which currently only the Go helper
implements.

---

## Interop Helper Binaries

The E2E scripts don't run the SSH libraries directly — they use small helper
programs that wrap each implementation into a consistent CLI interface.

### Go Helper (`test/interop/go/main.go`)

```bash
go-ssh-interop <role> <port> <kex> <pk> <enc> <hmac> [mode] [extra_arg]
```

- **Roles:** `server`, `client`
- **Modes:** (none), `large`, `multi`, `pkauth`, `portfwd`, `reconnect`,
  `concurrent-requests`, `pipe-request`
- **Extra arg:** echo port (portfwd client mode only)
- **Build:** `cd test/interop/go && go build -o go-ssh-interop .`

### TS Helper (`test/interop/ts/interop-helper.js`)

```bash
node interop-helper.js <role> <port> <kex> <pk> <enc> <hmac>
```

- **Roles:** `server`, `client`
- **Modes:** Default echo only (no feature modes)
- **Requires:** `NODE_PATH` set to `out/lib/node_modules`

### C# Helper (`test/interop/cs/Program.cs`)

```bash
dotnet run --project InteropHelper.csproj -c Release --no-build -- \
  <role> <port> <kex> <pk> <enc> <hmac>
```

- **Roles:** `server`, `client`
- **Modes:** Default echo only (no feature modes)
- **Build:** `dotnet build InteropHelper.csproj -c Release`

---

## The Orchestrator (`e2e-validate.sh`)

Runs the full pipeline in order:

1. **Build all implementations** — Go library, Go interop binary, TS library,
   C# interop helper
2. **Go unit tests** — gate check (`go vet` + `go test -race -short`).
   If these fail, E2E tests are aborted.
3. **C# self-test** (3 tests, skipped if dotnet unavailable)
4. **TS self-test** (3 tests)
5. **Go self-test** (8 tests)
6. **Go reconnect test** (3 tests)
7. **Go port forwarding test** (3 tests)
8. **Go concurrent requests test** (3 tests)
9. **Go pipe request test** (1 test)
10. **Cross-implementation interop** (up to 24 tests)
11. **Print summary** — pass/fail per suite + overall total

The orchestrator captures each suite's `X/Y passed` output line and aggregates
them into a final summary. It exits 0 only if all tests pass.

A 10-minute overall timeout kills the entire pipeline if it hangs (useful in CI).

---

## Debugging Failures

### View full output

```bash
./test/e2e/e2e-go-selftest.sh 2>&1 | tee /tmp/e2e.log
```

Failed tests print both client and server logs inline:

```
--- Test: ecdh-sha2-nistp384 / ecdsa-sha2-nistp384 / aes256-gcm@openssh.com / hmac-sha2-256 ---
  FAIL: Client missing marker: ECHO_OK
  Client output:
    AUTHENTICATED
    CHANNEL_OPEN
    ERROR: read timeout
  Server output:
    LISTENING
    ECHOED 18
```

### Run a test manually

```bash
# Pick a free port
PORT=9876

# Terminal 1: start server
./test/interop/go/go-ssh-interop server $PORT \
  ecdh-sha2-nistp384 ecdsa-sha2-nistp384 \
  aes256-gcm@openssh.com hmac-sha2-256

# Terminal 2: run client
./test/interop/go/go-ssh-interop client $PORT \
  ecdh-sha2-nistp384 ecdsa-sha2-nistp384 \
  aes256-gcm@openssh.com hmac-sha2-256
```

Watch both terminals for markers and error messages.

### Common issues

| Symptom                              | Likely Cause                              |
|--------------------------------------|-------------------------------------------|
| Server never prints `LISTENING`      | Port conflict, build failure, missing dep |
| Client missing `AUTHENTICATED`       | Algorithm mismatch, auth handler bug      |
| Client missing `ECHO_OK`             | Channel data framing bug, window sizing   |
| Timeout (no markers at all)          | Server crashed, wrong port, firewall      |
| C# tests skipped                     | `dotnet` not on PATH                      |
| TS build fails                       | Missing `node_modules`, run `npm install` |

---

## CI Integration

```yaml
- name: E2E Tests
  run: ./test/e2e/e2e-validate.sh
  timeout-minutes: 15
```

The script's built-in 10-minute timeout provides a safety net. Exit code 0
means all tests passed.

C# tests are automatically skipped if the .NET SDK isn't installed in the CI
environment — no configuration needed.
