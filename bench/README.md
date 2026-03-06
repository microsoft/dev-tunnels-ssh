# Dev Tunnels SSH - Cross-Platform Benchmark Suite

This directory contains a cross-platform benchmark suite that measures the performance of the Dev Tunnels SSH library across its three implementations: **C#**, **TypeScript**, and **Go**.

## Quick Start

Run all benchmarks across all platforms and generate a comparison report:

```bash
bash bench/orchestrator.sh --runs=20 --report
```

Results are written to `out/benchmarks/<timestamp>/` containing per-platform JSON files and an optional Markdown report.

## Directory Structure

```
bench/
├── orchestrator.sh          # Main entry point — builds, runs, reports
├── common/
│   └── report-generator.js  # Generates Markdown comparison report from JSON
├── cs/
│   └── Ssh.Benchmark/       # C# benchmark harness (.NET 8)
├── ts/
│   └── ssh-bench/           # TypeScript benchmark harness (Node.js)
└── go/
    └── cmd/bench/           # Go benchmark harness
```

## What's Being Tested

The suite covers 12 benchmark categories, each testing a specific layer of the SSH implementation:

### Algorithm Benchmarks (isolated from SSH protocol)

| Category | What It Measures | Scenarios |
|----------|-----------------|-----------|
| **Encryption** | Encrypt + decrypt round-trip time and throughput | AES-256-GCM (1KB, 32KB, 64KB), AES-256-CTR (32KB) |
| **HMAC** | Sign + verify time per MAC algorithm | SHA-256, SHA-512, SHA-256-ETM, SHA-512-ETM |
| **Key Exchange** | Single DH/ECDH key exchange operation | ECDH P-256, P-384, P-521; DH Group14, Group16 |
| **Key Generation** | Key pair generation time | RSA 2048/4096, ECDSA P-256/P-384/P-521 |
| **Signature** | Sign + verify round-trip | RSA SHA-256/SHA-512, ECDSA P-256/P-384/P-521 |

### Protocol Benchmarks

| Category | What It Measures | Scenarios |
|----------|-----------------|-----------|
| **Serialization** | Serialize + deserialize round-trip (1000 iterations batched) | ChannelData, ChannelOpen, KeyExchangeInit |
| **KEX Cycle** | Full key exchange between two in-process sessions | ECDH P-384 (both sides, including new-keys) |

### Session Benchmarks

| Category | What It Measures | Scenarios |
|----------|-----------------|-----------|
| **Session Setup** | Full session establishment broken into sub-phases (connect, encrypt, auth, channel open) | With and without 100ms simulated latency |
| **Throughput** | Messages/sec and MB/sec over an established session | 10B, 200B, 50KB, 1MB payloads; encrypted and unencrypted |
| **Multi-Channel** | Aggregate throughput across concurrent channels | 10 parallel channels |

### End-to-End Benchmarks

| Category | What It Measures | Scenarios |
|----------|-----------------|-----------|
| **Port Forwarding** | TCP port-forwarding through SSH tunnel (connect time + throughput) | IPv4, IPv6, localhost resolution |
| **Reconnect** | Session reconnect after transport interruption | Reconnect time with state restoration |

## How It Works

### Orchestrator (`orchestrator.sh`)

The orchestrator coordinates the full benchmark run:

1. **Build** — Calls `node build.js build-<platform> --release` for each selected platform
2. **Run** — Executes each platform's benchmark binary, passing `--json=<path>` and run count
3. **Report** — Optionally runs `report-generator.js` to produce a Markdown comparison table

```
orchestrator.sh
  ├─ build.js build-cs --release    → out/bin/Release/Ssh.Benchmark/
  ├─ build.js build-ts --release    → out/lib/ssh-bench/
  ├─ build.js build-go --release    → bench/go/cmd/bench/ (go run)
  ├─ dotnet Ssh.Benchmark.dll       → <outdir>/cs-results.json
  ├─ node main.js                   → <outdir>/ts-results.json
  ├─ go run .                       → <outdir>/go-results.json
  └─ report-generator.js            → <outdir>/report.md
```

### CLI Options

```
--runs <N>          Number of timed iterations per scenario (default: 20)
--platforms <list>  Comma-separated platforms to run (default: cs,ts,go)
--report            Generate Markdown comparison report
```

Examples:
```bash
# Run only C# and Go with 10 iterations
bash bench/orchestrator.sh --runs=10 --platforms=cs,go --report

# Quick TS-only run
bash bench/orchestrator.sh --runs=5 --platforms=ts
```

### Measurement Methodology

Each benchmark scenario follows this pattern:

1. **Warmup** — One iteration is run and its results discarded (warms JIT, CPU caches, connection pools)
2. **Timed iterations** — N iterations are run, each recording one or more metrics
3. **Trimmed mean** — The report generator sorts values, discards the min and max, and averages the rest

For sub-millisecond operations (serialization), benchmarks batch **1000 iterations** per timed sample and divide the elapsed time, avoiding timer resolution limits.

### JSON Result Format

Each platform writes a JSON file with this structure:

```json
{
  "metadata": {
    "platform": "cs",
    "platformVersion": ".NET 8.0.12",
    "os": "darwin-arm64",
    "timestamp": "2026-03-05T15:12:00Z",
    "runCount": 20,
    "gitCommit": "abc1234"
  },
  "suites": [
    {
      "category": "algorithm-encryption",
      "name": "Encryption - AES-256-GCM (32768 bytes)",
      "tags": { "algorithm": "aes-256-gcm", "size": "32768" },
      "metrics": [
        {
          "name": "Encrypt+Decrypt time",
          "unit": "ms",
          "values": [0.045, 0.043, 0.044, ...],
          "higherIsBetter": false
        }
      ]
    }
  ]
}
```

The `category` and `tags` fields are used by the report generator to match equivalent benchmarks across platforms. The `name` field is used for display.

### Report Generator (`common/report-generator.js`)

Reads all `*-results.json` files from a directory and produces a Markdown report with:

- Per-category tables showing each platform's results side by side
- **Bold** highlighting for the best-performing platform per metric
- Direction indicators (higher/lower is better)
- Values displayed as `trimmed_mean ± stddev (n)`

## Running Platforms Independently

### C# (.NET 8)

```bash
# Build
node build.js build-cs --release

# Run all benchmarks
dotnet out/bin/Release/Ssh.Benchmark/net8.0/Microsoft.DevTunnels.Ssh.Benchmark.dll \
  --json=results.json 20

# Run specific benchmarks by name
dotnet out/bin/Release/Ssh.Benchmark/net8.0/Microsoft.DevTunnels.Ssh.Benchmark.dll \
  session encrypted-200
```

The C# harness accepts:
- `--json=<path>` — Write JSON results to file
- Numeric argument — Number of timed iterations (default: 7)
- Named arguments — Benchmark names to run (default: all)

### TypeScript (Node.js)

```bash
# Build
node build.js build-ts --release

# Run all benchmarks
node out/lib/ssh-bench/main.js --json=results.json 20

# Run specific benchmarks
node out/lib/ssh-bench/main.js session encrypted-200
```

The TS harness accepts the same argument pattern as C#.

### Go

```bash
# Run all benchmarks
cd bench/go/cmd/bench && go run . --json=results.json --runs=20

# Run specific benchmarks
cd bench/go/cmd/bench && go run . --runs=20 --scenarios=session,session-with-latency
```

The Go harness uses flag-style arguments:
- `--json <path>` — Write JSON results to file
- `--runs <N>` — Number of timed iterations (default: 7)
- `--scenarios <list>` — Comma-separated scenario names to run (default: all)

## Platform Differences

| Aspect | C# | TypeScript | Go |
|--------|-----|-----------|-----|
| Runtime | .NET 8 | Node.js 20 | Go (compiled) |
| Session transport | TCP (loopback) | TCP (loopback) | In-process pipes |
| AES-GCM | Conditional (`SSH_ENABLE_AESGCM`) | Always available | Always available |
| ECDH | Conditional (`SSH_ENABLE_ECDH`) | Always available | Always available |
| AES-CBC | Available | Not available | Not available |
| Port forwarding | Full `PortForwardingService` | Full `PortForwardingService` | `tcp.ForwardPort()` |

## Troubleshooting

- **`dotnet: command not found`** — The orchestrator auto-detects `~/.dotnet/dotnet`. Ensure .NET 8 SDK is installed.
- **ECDH failures on macOS** — The orchestrator sets `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` for Homebrew's libssl. Ensure OpenSSL is installed via `brew install openssl`.
- **Stale results** — Always use `--release` builds (the orchestrator does this automatically). Debug builds have significantly different performance characteristics.
