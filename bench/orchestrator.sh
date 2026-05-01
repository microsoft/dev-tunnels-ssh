#!/usr/bin/env bash
#
# Benchmark orchestrator: builds platforms, runs benchmarks, generates report.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Ensure dotnet is on PATH (common install location on macOS/Linux)
if ! command -v dotnet &>/dev/null && [[ -x "$HOME/.dotnet/dotnet" ]]; then
    export PATH="$HOME/.dotnet:$PATH"
fi

# Defaults
RUNS=20
PLATFORMS="cs,ts,go"
REPORT=false
VERIFY=false

usage() {
    echo "Usage: $0 [--runs <N>] [--platforms <cs,ts,go>] [--report]"
    echo ""
    echo "Options:"
    echo "  --runs <N>          Number of timed iterations per scenario (default: 7)"
    echo "  --platforms <list>  Comma-separated platforms to run (default: cs,ts,go)"
    echo "  --report            Generate markdown comparison report"
    echo "  --verify            Run correctness verification after each benchmark"
    echo "  --help              Show this help message"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs)
            RUNS="$2"
            shift 2
            ;;
        --runs=*)
            RUNS="${1#--runs=}"
            shift
            ;;
        --platforms)
            PLATFORMS="$2"
            shift 2
            ;;
        --platforms=*)
            PLATFORMS="${1#--platforms=}"
            shift
            ;;
        --report)
            REPORT=true
            shift
            ;;
        --verify)
            VERIFY=true
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Create output directory with timestamp
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTDIR="$PROJECT_ROOT/out/benchmarks/$TIMESTAMP"
mkdir -p "$OUTDIR"

echo "=== Benchmark Orchestrator ==="
echo "Runs:      $RUNS"
echo "Platforms: $PLATFORMS"
echo "Report:    $REPORT"
echo "Verify:    $VERIFY"
echo "Output:    $OUTDIR"
echo ""

# Split platforms into array
IFS=',' read -ra PLATFORM_LIST <<< "$PLATFORMS"

# Build each selected platform
for platform in "${PLATFORM_LIST[@]}"; do
    echo "--- Building $platform ---"
    node "$PROJECT_ROOT/build.js" "build-$platform" --release
    echo ""
done

# Run benchmarks for each platform
# Calls runners directly to pass --json and --runs args correctly.
BIN_DIR="$PROJECT_ROOT/out/bin"
LIB_DIR="$PROJECT_ROOT/out/lib"

for platform in "${PLATFORM_LIST[@]}"; do
    echo "--- Running $platform benchmarks ---"
    JSON_OUT="$OUTDIR/${platform}-results.json"

    VERIFY_FLAG=""
    if [ "$VERIFY" = true ]; then
        VERIFY_FLAG="--verify"
    fi

    case "$platform" in
        cs)
            # On macOS with Homebrew, libssl is in /opt/homebrew/lib which is not
            # in .NET's default search path. ECDH benchmarks need it.
            if [[ "$(uname)" == "Darwin" ]] && [[ -d "/opt/homebrew/lib" ]]; then
                export DYLD_FALLBACK_LIBRARY_PATH="/opt/homebrew/lib:${DYLD_FALLBACK_LIBRARY_PATH:-}"
            fi
            CS_ASSEMBLY="$BIN_DIR/Release/Ssh.Benchmark/net8.0/Microsoft.DevTunnels.Ssh.Benchmark.dll"
            dotnet "$CS_ASSEMBLY" "--json=$JSON_OUT" $VERIFY_FLAG "$RUNS"
            ;;
        ts)
            TS_MAIN="$LIB_DIR/ssh-bench/main.js"
            node "$TS_MAIN" "--json=$JSON_OUT" $VERIFY_FLAG "$RUNS"
            ;;
        go)
            (cd "$PROJECT_ROOT/bench/go/cmd/bench" && go run . "--json=$JSON_OUT" "--runs=$RUNS" $VERIFY_FLAG)
            ;;
        *)
            echo "Unknown platform: $platform"
            exit 1
            ;;
    esac
    echo ""
done

# Generate report if requested
if [ "$REPORT" = true ]; then
    echo "--- Generating comparison report ---"
    REPORT_FILE="$OUTDIR/report.md"
    node "$PROJECT_ROOT/bench/common/report-generator.js" --input "$OUTDIR" --output "$REPORT_FILE"
    echo "Report written to $REPORT_FILE"
    echo ""
fi

# Print summary
echo "=== Complete ==="
echo "Output directory: $OUTDIR"
echo "Files:"
ls -1 "$OUTDIR"
