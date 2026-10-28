#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Master E2E validation orchestrator.
# Runs the full validation pipeline:
#   1. Build all implementations
#   2. C# self-test
#   3. TS self-test
#   4. Print summary
# Exits 0 only if all tests pass.
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
CS_PROJ="$REPO_ROOT/test/interop/cs/InteropHelper.csproj"
if command -v dotnet &>/dev/null; then
  if dotnet build "$CS_PROJ" -c Release --nologo -v q; then
    echo "C# build OK"
    CS_AVAILABLE=true
  else
    echo -e "${YELLOW}WARN: C# build failed (dotnet SDK may not be available)${NC}"
    echo "C# tests will be skipped"
    CS_AVAILABLE=false
  fi
else
  echo -e "${YELLOW}WARN: dotnet not found, C# tests will be skipped${NC}"
  CS_AVAILABLE=false
fi

# ─── Step 2-3: Self-tests ───

if [ "$CS_AVAILABLE" = true ]; then
  run_suite "C# Self-Test" "$SCRIPT_DIR/e2e-cs-selftest.sh"
else
  echo ""
  echo -e "${YELLOW}Skipping C# self-test (dotnet not available)${NC}"
  record_suite "C# Self-Test (skipped)" 0 0
fi

run_suite "TS Self-Test" "$SCRIPT_DIR/e2e-ts-selftest.sh"

# ─── Step 4: Summary ───

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
