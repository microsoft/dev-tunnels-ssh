# Dev Tunnels SSH — E2E Test Guide

End-to-end tests that validate the TypeScript and C# SSH implementations
work correctly over real TCP sockets.

## Why These Tests Exist

Unit tests verify individual components in isolation. These E2E tests prove
that a **real SSH session** over **real TCP sockets** can:

- Negotiate algorithms (key exchange, encryption, HMAC, public key)
- Authenticate a client to a server
- Open channels and transfer data

This catches protocol-level bugs that unit tests miss: wrong packet framing,
algorithm negotiation mismatches, endianness issues, and subtle timing problems.

## Quick Start

```bash
# Run the full suite (6 tests)
./test/e2e/e2e-validate.sh

# Run a single suite
./test/e2e/e2e-ts-selftest.sh
./test/e2e/e2e-cs-selftest.sh
```

## Prerequisites

| Requirement     | Version   | Required? | Notes                                          |
|-----------------|-----------|-----------|------------------------------------------------|
| Node.js         | 20.x+     | Yes       | TS implementation                              |
| .NET SDK        | 8.0+      | Optional  | C# tests skipped gracefully if missing         |
| Python 3        | Any       | Yes       | Used by `find_free_port()` utility             |
| bash            | 4.0+      | Yes       | Scripts use arrays, traps, process management  |

The orchestrator (`e2e-validate.sh`) builds everything automatically before
running tests, so you don't need to build manually.

## Test Suite Overview

| Script                           | What It Tests                        | Tests | Timeout    |
|----------------------------------|--------------------------------------|-------|------------|
| `e2e-validate.sh`                | Orchestrator — runs everything       | 6     | 10 min     |
| `e2e-ts-selftest.sh`             | TS client ↔ TS server                | 3     | 15s/test   |
| `e2e-cs-selftest.sh`             | C# client ↔ C# server                | 3     | 15s/test   |

---

## Algorithm Combinations

Tests exercise different cryptographic algorithm combinations to ensure the
implementations handle the negotiation matrix. The self-tests use 3
representative combinations:

| # | Key Exchange                    | Public Key            | Encryption                    | HMAC                          |
|---|---------------------------------|-----------------------|-------------------------------|-------------------------------|
| 1 | ecdh-sha2-nistp384              | ecdsa-sha2-nistp384   | aes256-gcm@openssh.com        | hmac-sha2-256                 |
| 2 | ecdh-sha2-nistp256              | ecdsa-sha2-nistp256   | aes256-ctr                    | hmac-sha2-256-etm@openssh.com |
| 3 | diffie-hellman-group14-sha256   | rsa-sha2-256          | aes256-cbc (C#) / aes256-ctr (TS) | hmac-sha2-512             |

**TS limitation:** TypeScript does not support AES-CBC, so combo 3 substitutes
`aes256-ctr` for `aes256-cbc`.

---

## How the Tests Work

### Marker-Based Verification

Each test starts a **server** process and a **client** process. Both print
text markers to stdout as they reach key milestones. The test script captures
the output and greps for expected markers to determine pass/fail.

#### Client Markers

| Marker          | Meaning                        |
|-----------------|--------------------------------|
| `AUTHENTICATED` | Client authenticated to server |
| `CHANNEL_OPEN`  | SSH channel opened             |
| `ECHO_OK`       | Echo data matched              |
| `DONE`          | Test completed                 |

#### Server Markers

| Marker      | Meaning                             |
|-------------|-------------------------------------|
| `LISTENING` | Server ready, accepting connections |

### Test Execution Pattern

Every test follows the same basic flow:

```
1. Find a free TCP port
2. Start server in background, redirect output to temp log
3. Wait up to 15s for LISTENING marker in server log
4. Run client with 15s timeout, redirect output to temp log
5. Grep client log for expected markers
6. Record pass/fail, clean up processes and temp files
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

---

## Interop Helper Programs

The E2E scripts don't run the SSH libraries directly — they use small helper
programs that wrap each implementation into a consistent CLI interface.

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

1. **Build all implementations** — TS library, C# interop helper
2. **C# self-test** (3 tests, skipped if dotnet unavailable)
3. **TS self-test** (3 tests)
4. **Print summary** — pass/fail per suite + overall total

The orchestrator captures each suite's `X/Y passed` output line and aggregates
them into a final summary. It exits 0 only if all tests pass.

A 10-minute overall timeout kills the entire pipeline if it hangs (useful in CI).

---

## Debugging Failures

### View full output

```bash
./test/e2e/e2e-ts-selftest.sh 2>&1 | tee /tmp/e2e.log
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
export NODE_PATH=out/lib/node_modules

# Terminal 1: start server
node test/interop/ts/interop-helper.js server $PORT \
  ecdh-sha2-nistp384 ecdsa-sha2-nistp384 \
  aes256-gcm@openssh.com hmac-sha2-256

# Terminal 2: run client
node test/interop/ts/interop-helper.js client $PORT \
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
