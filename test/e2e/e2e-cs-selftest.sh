#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# E2E self-test: C# client <-> C# server over real TCP sockets.
# Tests 3 algorithm combinations.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INTEROP_PROJ="$REPO_ROOT/test/interop/cs/InteropHelper.csproj"
TIMEOUT=15

# Global tracking for trap cleanup.
SERVER_LOG=""
CLIENT_LOG=""
PIDS=""

cleanup_all() {
  for pid in $PIDS; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -f "$SERVER_LOG" "$CLIENT_LOG" 2>/dev/null || true
}

trap cleanup_all EXIT INT TERM

# Algorithm combinations: kex pk enc hmac
COMBOS=(
  "ecdh-sha2-nistp384 ecdsa-sha2-nistp384 aes256-gcm@openssh.com hmac-sha2-256"
  "ecdh-sha2-nistp256 ecdsa-sha2-nistp256 aes256-ctr hmac-sha2-256-etm@openssh.com"
  "diffie-hellman-group14-sha256 rsa-sha2-256 aes256-cbc hmac-sha2-512"
)

PASSED=0
FAILED=0
TOTAL=${#COMBOS[@]}

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

# Build the C# interop helper once.
echo "=== Building C# interop helper ==="
dotnet build "$INTEROP_PROJ" -c Release --nologo -v q || {
  echo "FAIL: C# interop helper build failed"
  exit 1
}
echo "Build OK"
echo ""

for combo in "${COMBOS[@]}"; do
  read -r kex pk enc hmac <<< "$combo"
  port=$(find_free_port)

  echo "--- Test: $kex / $enc ---"

  SERVER_LOG=$(mktemp)
  CLIENT_LOG=$(mktemp)
  PIDS=""

  # Start server in background.
  dotnet run --project "$INTEROP_PROJ" -c Release --no-build -- \
    server "$port" "$kex" "$pk" "$enc" "$hmac" \
    >"$SERVER_LOG" 2>&1 &
  server_pid=$!
  PIDS="$server_pid"

  # Wait for LISTENING marker (up to TIMEOUT seconds).
  started=false
  for i in $(seq 1 $((TIMEOUT * 10))); do
    if grep -q "LISTENING" "$SERVER_LOG" 2>/dev/null; then
      started=true
      break
    fi
    # Check if server process died.
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  if ! $started; then
    echo "  FAIL: Server did not print LISTENING within ${TIMEOUT}s"
    echo "  Server output:"
    sed 's/^/    /' "$SERVER_LOG" 2>/dev/null
    cleanup "$PIDS"
    FAILED=$((FAILED + 1))
    echo ""
    continue
  fi

  # Run client with timeout.
  run_with_timeout "$TIMEOUT" dotnet run --project "$INTEROP_PROJ" -c Release --no-build -- \
    client "$port" "$kex" "$pk" "$enc" "$hmac" \
    >"$CLIENT_LOG" 2>&1 || true

  # Verify client markers.
  ok=true
  for marker in AUTHENTICATED CHANNEL_OPEN ECHO_OK DONE; do
    if ! grep -q "$marker" "$CLIENT_LOG" 2>/dev/null; then
      echo "  FAIL: Client missing marker: $marker"
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

  cleanup "$PIDS"
  echo ""
done

echo "=== C# Self-Test Results: $PASSED/$TOTAL passed ==="

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
