#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# E2E cross-implementation interop tests over real TCP sockets.
# Tests 4 server/client combinations x 5 algorithm sets = 20 tests.
# Combinations: C# server <-> Go client, Go server <-> C# client,
#               TS server <-> Go client, Go server <-> TS client.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GO_BINARY="$REPO_ROOT/test/interop/go/go-ssh-interop"
TS_SCRIPT="$REPO_ROOT/test/interop/ts/interop-helper.js"
CS_PROJ="$REPO_ROOT/test/interop/cs/InteropHelper.csproj"
TIMEOUT=15
CS_AVAILABLE=false

export NODE_PATH="$REPO_ROOT/out/lib/node_modules"

# Global tracking for trap cleanup.
SERVER_LOG=""
CLIENT_LOG=""
server_pid=""

cleanup_all() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -f "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null || true
}

trap cleanup_all EXIT INT TERM

# Verify Go binary exists.
if [ ! -f "$GO_BINARY" ]; then
  echo "ERROR: Go interop binary not found at $GO_BINARY"
  echo "Build it first: cd $(dirname "$GO_BINARY") && go build -o $(basename "$GO_BINARY") ."
  echo "Or run e2e-validate.sh which builds it automatically."
  exit 1
fi

# Check if dotnet is available for C# tests.
if command -v dotnet &>/dev/null; then
  CS_AVAILABLE=true
fi

# Algorithm combinations: kex pk enc hmac
# Standard combos (used for Go-only and C#-only pairs):
COMBOS_FULL=(
  "ecdh-sha2-nistp384 ecdsa-sha2-nistp384 aes256-gcm@openssh.com hmac-sha2-256"
  "ecdh-sha2-nistp256 ecdsa-sha2-nistp256 aes256-ctr hmac-sha2-256-etm@openssh.com"
  "diffie-hellman-group14-sha256 rsa-sha2-256 aes256-cbc hmac-sha2-512"
  "ecdh-sha2-nistp521 ecdsa-sha2-nistp521 aes256-gcm@openssh.com hmac-sha2-512-etm@openssh.com"
  "diffie-hellman-group16-sha512 rsa-sha2-512 aes256-ctr hmac-sha2-512-etm@openssh.com"
)

# TS-involved combos (TS does not support aes256-cbc):
COMBOS_TS=(
  "ecdh-sha2-nistp384 ecdsa-sha2-nistp384 aes256-gcm@openssh.com hmac-sha2-256"
  "ecdh-sha2-nistp256 ecdsa-sha2-nistp256 aes256-ctr hmac-sha2-256-etm@openssh.com"
  "diffie-hellman-group14-sha256 rsa-sha2-256 aes256-ctr hmac-sha2-512"
  "ecdh-sha2-nistp521 ecdsa-sha2-nistp521 aes256-gcm@openssh.com hmac-sha2-512-etm@openssh.com"
  "diffie-hellman-group16-sha512 rsa-sha2-512 aes256-ctr hmac-sha2-512-etm@openssh.com"
)

PASSED=0
FAILED=0
TOTAL=0

find_free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}

# Portable timeout: run a command with a timeout (works on macOS and Linux).
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

cleanup() {
  local pids="$1"
  for pid in $pids; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -f "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null || true
}

# Start a server process. Sets server_pid and SERVER_LOG.
start_server() {
  local impl="$1" port="$2" kex="$3" pk="$4" enc="$5" hmac="$6"
  SERVER_LOG=$(mktemp)
  case "$impl" in
    go)
      "$GO_BINARY" server "$port" "$kex" "$pk" "$enc" "$hmac" \
        >"$SERVER_LOG" 2>&1 &
      server_pid=$!
      ;;
    ts)
      node "$TS_SCRIPT" server "$port" "$kex" "$pk" "$enc" "$hmac" \
        >"$SERVER_LOG" 2>&1 &
      server_pid=$!
      ;;
    cs)
      dotnet run --project "$CS_PROJ" -c Release --no-build -- \
        server "$port" "$kex" "$pk" "$enc" "$hmac" \
        >"$SERVER_LOG" 2>&1 &
      server_pid=$!
      ;;
  esac
}

# Run a client process. Sets CLIENT_LOG.
run_client() {
  local impl="$1" port="$2" kex="$3" pk="$4" enc="$5" hmac="$6"
  CLIENT_LOG=$(mktemp)
  case "$impl" in
    go)
      run_with_timeout "$TIMEOUT" "$GO_BINARY" \
        client "$port" "$kex" "$pk" "$enc" "$hmac" \
        >"$CLIENT_LOG" 2>&1 || true
      ;;
    ts)
      run_with_timeout "$TIMEOUT" node "$TS_SCRIPT" \
        client "$port" "$kex" "$pk" "$enc" "$hmac" \
        >"$CLIENT_LOG" 2>&1 || true
      ;;
    cs)
      run_with_timeout "$TIMEOUT" dotnet run --project "$CS_PROJ" -c Release --no-build -- \
        client "$port" "$kex" "$pk" "$enc" "$hmac" \
        >"$CLIENT_LOG" 2>&1 || true
      ;;
  esac
}

# Run a single interop test: server_impl client_impl kex pk enc hmac
run_test() {
  local server_impl="$1" client_impl="$2" kex="$3" pk="$4" enc="$5" hmac="$6"
  local port
  port=$(find_free_port)
  TOTAL=$((TOTAL + 1))

  echo "--- Test: ${server_impl}-server <-> ${client_impl}-client | $kex / $enc ---"

  server_pid=""
  SERVER_LOG=""
  CLIENT_LOG=""

  start_server "$server_impl" "$port" "$kex" "$pk" "$enc" "$hmac"

  # Wait for LISTENING marker (up to TIMEOUT seconds).
  local started=false
  for i in $(seq 1 $((TIMEOUT * 10))); do
    if grep -q "LISTENING" "$SERVER_LOG" 2>/dev/null; then
      started=true
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  if ! $started; then
    echo "  FAIL: Server ($server_impl) did not print LISTENING within ${TIMEOUT}s"
    echo "  Server output:"
    sed 's/^/    /' "$SERVER_LOG" 2>/dev/null
    cleanup "$server_pid"
    FAILED=$((FAILED + 1))
    echo ""
    return
  fi

  run_client "$client_impl" "$port" "$kex" "$pk" "$enc" "$hmac"

  # Verify client markers.
  local ok=true
  for marker in AUTHENTICATED CHANNEL_OPEN ECHO_OK DONE; do
    if ! grep -q "$marker" "$CLIENT_LOG" 2>/dev/null; then
      echo "  FAIL: Client ($client_impl) missing marker: $marker"
      ok=false
    fi
  done

  if $ok; then
    echo "  PASS"
    PASSED=$((PASSED + 1))
  else
    echo "  Client output:"
    sed 's/^/    /' "$CLIENT_LOG" 2>/dev/null
    echo "  Server output:"
    sed 's/^/    /' "$SERVER_LOG" 2>/dev/null
    FAILED=$((FAILED + 1))
  fi

  cleanup "$server_pid"
  echo ""
}

echo "=========================================="
echo "  Cross-Implementation Interop Tests"
echo "=========================================="
echo ""

# --- C# server <-> Go client (3 tests) ---
if [ "$CS_AVAILABLE" = true ]; then
  echo "=== C# server <-> Go client ==="
  for combo in "${COMBOS_FULL[@]}"; do
    read -r kex pk enc hmac <<< "$combo"
    run_test cs go "$kex" "$pk" "$enc" "$hmac"
  done
else
  echo "=== C# server <-> Go client (SKIPPED - dotnet not available) ==="
  echo ""
fi

# --- Go server <-> C# client (3 tests) ---
if [ "$CS_AVAILABLE" = true ]; then
  echo "=== Go server <-> C# client ==="
  for combo in "${COMBOS_FULL[@]}"; do
    read -r kex pk enc hmac <<< "$combo"
    run_test go cs "$kex" "$pk" "$enc" "$hmac"
  done
else
  echo "=== Go server <-> C# client (SKIPPED - dotnet not available) ==="
  echo ""
fi

# --- TS server <-> Go client (3 tests, TS combos) ---
echo "=== TS server <-> Go client ==="
for combo in "${COMBOS_TS[@]}"; do
  read -r kex pk enc hmac <<< "$combo"
  run_test ts go "$kex" "$pk" "$enc" "$hmac"
done

# --- Go server <-> TS client (3 tests, TS combos) ---
echo "=== Go server <-> TS client ==="
for combo in "${COMBOS_TS[@]}"; do
  read -r kex pk enc hmac <<< "$combo"
  run_test go ts "$kex" "$pk" "$enc" "$hmac"
done

# --- Feature mode interop tests ---
# large and multi modes only require the Go client to use the mode flag;
# the server uses default echo behavior. So we can test Go client feature
# modes against TS and C# server implementations.

FEATURE_INTEROP_KEX="ecdh-sha2-nistp384"
FEATURE_INTEROP_PK="ecdsa-sha2-nistp384"
FEATURE_INTEROP_ENC="aes256-gcm@openssh.com"
FEATURE_INTEROP_HMAC="hmac-sha2-256"

# run_feature_test: server_impl mode expected_marker
run_feature_test() {
  local server_impl="$1" mode="$2" expected_marker="$3"
  local port
  port=$(find_free_port)
  TOTAL=$((TOTAL + 1))

  echo "--- Test: ${server_impl}-server <-> go-client ($mode) | $FEATURE_INTEROP_KEX / $FEATURE_INTEROP_ENC ---"

  server_pid=""
  SERVER_LOG=""
  CLIENT_LOG=""

  start_server "$server_impl" "$port" "$FEATURE_INTEROP_KEX" "$FEATURE_INTEROP_PK" "$FEATURE_INTEROP_ENC" "$FEATURE_INTEROP_HMAC"

  # Wait for LISTENING marker.
  local started=false
  for i in $(seq 1 $((TIMEOUT * 10))); do
    if grep -q "LISTENING" "$SERVER_LOG" 2>/dev/null; then
      started=true
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  if ! $started; then
    echo "  FAIL: Server ($server_impl) did not print LISTENING within ${TIMEOUT}s"
    echo "  Server output:"
    sed 's/^/    /' "$SERVER_LOG" 2>/dev/null
    cleanup "$server_pid"
    FAILED=$((FAILED + 1))
    echo ""
    return
  fi

  # Run Go client with mode.
  CLIENT_LOG=$(mktemp)
  run_with_timeout "$TIMEOUT" "$GO_BINARY" \
    client "$port" "$FEATURE_INTEROP_KEX" "$FEATURE_INTEROP_PK" "$FEATURE_INTEROP_ENC" "$FEATURE_INTEROP_HMAC" "$mode" \
    >"$CLIENT_LOG" 2>&1 || true

  # Verify expected marker.
  local ok=true
  if ! grep -q "$expected_marker" "$CLIENT_LOG" 2>/dev/null; then
    echo "  FAIL: Client (go) missing marker: $expected_marker"
    ok=false
  fi

  if $ok; then
    echo "  PASS"
    PASSED=$((PASSED + 1))
  else
    echo "  Client output:"
    sed 's/^/    /' "$CLIENT_LOG" 2>/dev/null
    echo "  Server output:"
    sed 's/^/    /' "$SERVER_LOG" 2>/dev/null
    FAILED=$((FAILED + 1))
  fi

  cleanup "$server_pid"
  echo ""
}

echo "=== Feature Mode Interop Tests ==="
echo ""

# TS server with Go client feature modes.
echo "=== TS server <-> Go client (feature modes) ==="
run_feature_test ts large LARGE_DATA_OK
run_feature_test ts multi MULTI_CHANNEL_OK

# C# server with Go client feature modes.
if [ "$CS_AVAILABLE" = true ]; then
  echo "=== C# server <-> Go client (feature modes) ==="
  run_feature_test cs large LARGE_DATA_OK
  run_feature_test cs multi MULTI_CHANNEL_OK
else
  echo "=== C# server <-> Go client feature modes (SKIPPED - dotnet not available) ==="
  echo ""
fi

echo "=== Cross-Implementation Interop Results: $PASSED/$TOTAL passed ==="

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
