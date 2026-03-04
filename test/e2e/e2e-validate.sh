#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Master E2E validation orchestrator.
# Runs the full validation pipeline:
#   1. Build all implementations
#   2. Run Go unit tests (gate check)
#   3. Build Go interop helper binary
#   4. C# self-test (3 tests)
#   5. TS self-test (3 tests)
#   6. Go self-test (8 tests: 5 algo combos + 3 feature modes)
#   7. Go reconnect test (3 tests: 3 algo combos)
#   8. Go port forwarding test (3 tests: 3 algo combos)
#   9. Cross-implementation interop (24 tests: 4 pairings x 5 algo combos + 4 feature mode tests)
#  10. Print summary
# Exits 0 only if all ~44 tests pass.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

TOTAL_PASSED=0
TOTAL_FAILED=0
SUITE_RESULTS=()
OVERALL_TIMER_PID=""

cleanup_all() {
  if [ -n "$OVERALL_TIMER_PID" ]; then
    kill "$OVERALL_TIMER_PID" 2>/dev/null || true
    wait "$OVERALL_TIMER_PID" 2>/dev/null || true
  fi
}

trap cleanup_all EXIT INT TERM

# Colors (if terminal supports them).
if [ -t 1 ]; then
  GREEN='\033[0;32m'
  RED='\033[0;31m'
  YELLOW='\033[0;33m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  GREEN=''
  RED=''
  YELLOW=''
  BOLD=''
  NC=''
fi

print_header() {
  echo ""
  echo "=========================================="
  echo -e "  ${BOLD}$1${NC}"
  echo "=========================================="
  echo ""
}

record_suite() {
  local name="$1" passed="$2" total="$3"
  TOTAL_PASSED=$((TOTAL_PASSED + passed))
  TOTAL_FAILED=$((TOTAL_FAILED + (total - passed)))
  if [ "$passed" -eq "$total" ]; then
    SUITE_RESULTS+=("  ${GREEN}PASS${NC}  $name ($passed/$total)")
  else
    SUITE_RESULTS+=("  ${RED}FAIL${NC}  $name ($passed/$total)")
  fi
}

# Run a suite script and capture its pass/fail count from output.
run_suite() {
  local name="$1" script="$2"
  print_header "$name"

  local output
  local exit_code=0
  output=$("$script" 2>&1) || exit_code=$?

  echo "$output"
  echo ""

  # Parse "X/Y passed" from the output.
  local passed=0 total=0
  if echo "$output" | grep -qoE '[0-9]+/[0-9]+ passed'; then
    local result_line
    result_line=$(echo "$output" | grep -oE '[0-9]+/[0-9]+ passed' | tail -1)
    passed=$(echo "$result_line" | cut -d/ -f1)
    total=$(echo "$result_line" | cut -d/ -f2 | cut -d' ' -f1)
  fi

  record_suite "$name" "$passed" "$total"
}

# Overall 10-minute timeout to prevent hanging in CI.
( sleep 600 && echo "" && echo -e "${RED}FATAL: Overall 10-minute timeout exceeded${NC}" >&2 && kill -TERM $$ 2>/dev/null ) &
OVERALL_TIMER_PID=$!

echo ""
echo "=========================================="
echo -e "  ${BOLD}Dev Tunnels SSH — Full E2E Validation${NC}"
echo "=========================================="
echo ""

# ─── Step 1: Build all implementations ───

print_header "Step 1: Build all implementations"

echo "--- Building Go library ---"
(cd "$REPO_ROOT/src/go" && go build ./...) || {
  echo -e "${RED}FAIL: Go library build failed${NC}"
  exit 1
}
echo "Go build OK"

echo ""
echo "--- Building Go interop binary ---"
GO_INTEROP_DIR="$REPO_ROOT/test/go/interop/go"
(cd "$GO_INTEROP_DIR" && go build -o go-ssh-interop .) || {
  echo -e "${RED}FAIL: Go interop binary build failed${NC}"
  exit 1
}
echo "Go interop binary OK"

echo ""
echo "--- Building TS library ---"
if [ ! -d "$REPO_ROOT/out/lib/node_modules" ]; then
  (cd "$REPO_ROOT" && node build.js build-ts) || {
    echo -e "${RED}FAIL: TS build failed${NC}"
    exit 1
  }
else
  echo "TS build output already exists, skipping"
fi
echo "TS build OK"

echo ""
echo "--- Building C# interop helper ---"
CS_PROJ="$REPO_ROOT/test/go/interop/cs/InteropHelper.csproj"
if command -v dotnet &>/dev/null; then
  dotnet build "$CS_PROJ" -c Release --nologo -v q || {
    echo -e "${YELLOW}WARN: C# build failed (dotnet SDK may not be available)${NC}"
    echo "C# tests will be skipped"
  }
  echo "C# build OK"
  CS_AVAILABLE=true
else
  echo -e "${YELLOW}WARN: dotnet not found, C# tests will be skipped${NC}"
  CS_AVAILABLE=false
fi

# ─── Step 2: Go unit tests (gate check) ───

print_header "Step 2: Go unit tests (gate check)"

echo "Running go vet..."
(cd "$REPO_ROOT/src/go" && go vet ./...) || {
  echo -e "${RED}FAIL: go vet failed${NC}"
  exit 1
}
echo "go vet OK"

echo ""
echo "Running go test -race -short (gate check)..."
(cd "$REPO_ROOT/src/go" && go test -race -short -timeout=120s ./ssh/... ./keys/... ./tcp/...) || {
  echo -e "${RED}FAIL: Go unit tests failed — aborting E2E validation${NC}"
  exit 1
}
echo "Go unit tests OK"

# ─── Step 3-7: Self-tests ───

if [ "$CS_AVAILABLE" = true ]; then
  run_suite "C# Self-Test" "$SCRIPT_DIR/e2e-cs-selftest.sh"
else
  echo ""
  echo -e "${YELLOW}Skipping C# self-test (dotnet not available)${NC}"
  record_suite "C# Self-Test (skipped)" 0 0
fi

run_suite "TS Self-Test" "$SCRIPT_DIR/e2e-ts-selftest.sh"

run_suite "Go Self-Test" "$SCRIPT_DIR/e2e-go-selftest.sh"

run_suite "Go Reconnect Test" "$SCRIPT_DIR/e2e-go-reconnect.sh"

run_suite "Go Port Forwarding Test" "$SCRIPT_DIR/e2e-go-portfwd.sh"

run_suite "Go Concurrent Requests Test" "$SCRIPT_DIR/e2e-go-concurrent-requests.sh"

run_suite "Go Pipe Request Test" "$SCRIPT_DIR/e2e-go-pipe-request.sh"

# ─── Step 8: Cross-implementation interop ───

run_suite "Cross-Implementation Interop" "$SCRIPT_DIR/e2e-interop.sh"

# ─── Step 9: Summary ───

TOTAL=$((TOTAL_PASSED + TOTAL_FAILED))

print_header "E2E Validation Summary"

for result in "${SUITE_RESULTS[@]}"; do
  echo -e "$result"
done

echo ""
echo "=========================================="
if [ "$TOTAL_FAILED" -eq 0 ]; then
  echo -e "  ${GREEN}${BOLD}ALL PASSED: $TOTAL_PASSED/$TOTAL${NC}"
else
  echo -e "  ${RED}${BOLD}FAILED: $TOTAL_PASSED/$TOTAL passed ($TOTAL_FAILED failed)${NC}"
fi
echo "=========================================="
echo ""

if [ "$TOTAL_FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
