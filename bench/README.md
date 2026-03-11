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
--verify            Run correctness checks after each benchmark (see Verification below)
```

Examples:
```bash
# Run only C# and Go with 10 iterations
bash bench/orchestrator.sh --runs=10 --platforms=cs,go --report

# Quick TS-only run
bash bench/orchestrator.sh --runs=5 --platforms=ts

# Run with verification enabled
bash bench/orchestrator.sh --runs=10 --report --verify
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
      ],
      "verification": {
        "passed": true
      }
    }
  ]
}
```

The `category` and `tags` fields are used by the report generator to match equivalent benchmarks across platforms. The `name` field is used for display. The `verification` field is present only when `--verify` was used and is omitted otherwise.

### Report Generator (`common/report-generator.js`)

Reads all `*-results.json` files from a directory and produces a Markdown report with:

- Per-category tables showing each platform's results side by side
- **Bold** highlighting for the best-performing platform per metric
- Direction indicators (higher/lower is better)
- Values displayed as `trimmed_mean ± stddev (n)`
- Verification results table (when `--verify` was used) showing pass/fail per benchmark per platform
- Validation warnings flagging zero/negative metrics or >10x cross-platform differences

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

## Verification (`--verify`)

The `--verify` flag runs a correctness check after each benchmark to prove the operation actually did what it claims. These checks are separate from timing — they run once after all timed iterations complete and do not affect performance numbers.

When enabled, verification results are included in the JSON output (as a `verification` field per suite) and displayed in the Markdown report as a summary table.

### What each category verifies

#### Algorithm: Encryption

1. Generate a random key and IV for the algorithm
2. Encrypt a plaintext buffer in-place
3. **Check:** ciphertext differs from original plaintext (encryption actually happened)
4. Decrypt the ciphertext back in-place
5. **Check:** decrypted output matches the original plaintext (round-trip succeeded)

For GCM mode, the authentication tag is transferred from encryptor to decryptor between steps.

#### Algorithm: HMAC

1. Generate a random key and a 256-byte data payload
2. Create signer and verifier from the same key
3. Sign the data
4. **Check:** verifier accepts the signature for the original data (positive test)
5. Tamper with the data (XOR first byte with 0xFF)
6. **Check:** verifier rejects the signature for the tampered data (negative test)

#### Algorithm: Key Exchange

1. Create two KEX instances (client and server)
2. Both start key exchange, producing ephemeral public values
3. Each side decrypts using the other's public value to derive a shared secret
4. **Check:** both sides derive the same shared secret
5. **Check:** the shared secret is not empty

#### Algorithm: Key Generation

1. Generate a key pair for the specified algorithm and key size
2. **Check:** the generated key has the expected bit size (RSA modulus length, ECDSA curve size) — this prevents silent key size mismatches across platforms
3. Sign test data with the generated key
4. **Check:** the generated key can verify its own signature (key pair is valid and usable)

#### Algorithm: Signature

1. Generate a key pair with the specified key size
2. **Check:** the generated key has the expected bit size (same key size validation as keygen)
3. Sign test data
4. **Check:** verifier accepts the signature for the correct data (positive test)
5. **Check:** verifier rejects the signature for different data (negative test)

#### Protocol: Serialization (ChannelData, ChannelOpen, KexInit)

1. Create a message with known field values
2. Serialize the message to a binary buffer
3. Deserialize the buffer back into a message object
4. **Check:** all fields on the deserialized message match the original values

Specific fields checked per message type:
- **ChannelData:** RecipientChannel, Data content
- **ChannelOpen:** ChannelType (`"session"`), SenderChannel, MaxWindowSize
- **KexInit:** KeyExchangeAlgorithms list, HostKeyAlgorithms list, EncryptionAlgorithms list

#### Session: Setup

1. Create a full encrypted session pair (client + server over TCP loopback)
2. Open a channel between them
3. Send test data through the channel
4. **Check:** server receives the exact data that was sent (end-to-end data flow works)

#### Session: Throughput

1. Create a session pair and open a channel
2. Send a known number of bytes through the channel
3. Count bytes received on the server side (with timeout)
4. **Check:** total bytes received equals total bytes sent

#### E2E: Multi-Channel (Go only)

1. Create an unencrypted session pair
2. Open a channel and send test data
3. **Check:** server receives the exact data sent

#### E2E: Port Forward (Go only)

1. Start a local TCP echo server
2. Create a session pair with port forwarding enabled
3. Request a remote port forward through the SSH tunnel
4. Connect to the forwarded port via TCP
5. Send test data through the forwarded connection
6. **Check:** echo server returns the exact data sent (full tunnel round-trip)

#### E2E: Reconnect (Go only)

1. Create an initial session pair with reconnect protocol extension enabled
2. Open a channel, send data, confirm it works
3. Force-disconnect by closing the underlying TCP streams
4. Create new TCP streams and reconnect (client reconnects, server accepts)
5. Open a new channel on the reconnected session
6. Send test data through the new channel
7. **Check:** data is received correctly after reconnection (session state restored)

### Verification coverage by platform

| Category | C# | TypeScript | Go |
|----------|-----|-----------|-----|
| Encryption | Yes | Yes | Yes |
| HMAC | Yes | Yes | Yes |
| Key Exchange | Yes | Yes | Yes |
| Key Generation | Yes | Yes | Yes |
| Signature | Yes | Yes | Yes |
| Serialization | Yes | Yes | Yes |
| KEX Cycle | — | — | — |
| Session Setup | Yes | Yes | Yes |
| Throughput | Yes | Yes | Yes |
| Multi-Channel | — | — | Yes |
| Port Forward | — | — | Yes |
| Reconnect | — | — | Yes |

All algorithm, protocol serialization, and session benchmarks have consistent verification across all three platforms. The E2E benchmarks (multi-channel, port forward, reconnect) currently have verification only in Go.

## Platform Differences

| Aspect | C# | TypeScript | Go |
|--------|-----|-----------|-----|
| Runtime | .NET 8 | Node.js 20 | Go (compiled) |
| Session transport | TCP (loopback) | TCP (loopback) | TCP (loopback) |
| AES-GCM | Conditional (`SSH_ENABLE_AESGCM`) | Always available | Always available |
| ECDH | Conditional (`SSH_ENABLE_ECDH`) | Always available | Always available |
| AES-CBC | Available | Not available | Not available |
| Port forwarding | Full `PortForwardingService` | Full `PortForwardingService` | `tcp.ForwardPort()` |

### Expected Performance Differences

Go will often appear **significantly faster** (10–100x) in algorithm-level and serialization benchmarks. This is expected and reflects real differences in the underlying crypto and runtime implementations — not a bug in the benchmarks.

**Why Go's algorithm benchmarks are faster:**

- **Crypto primitives use hand-written assembly.** Go's standard library includes assembly-optimized implementations for common architectures (amd64, arm64). AES-GCM uses [AES-NI + CLMUL hardware instructions](https://pkg.go.dev/crypto/aes) directly via [dedicated assembly](https://github.com/golang/go/blob/2ebe77a2fda1ee9ff6fd9a3e08933ad1ebaea039/src/crypto/aes/gcm_amd64.s); SHA-256/SHA-512 use [platform-specific assembly](https://github.com/golang/go/blob/master/src/crypto/sha256/sha256block_amd64.s) with AVX2 and SHA-NI instructions (see [issue #50543](https://github.com/golang/go/issues/50543)); elliptic curve P-256 uses [optimized field arithmetic in assembly](https://github.com/golang/go/blob/master/src/crypto/internal/fips140/nistec/p256_asm_amd64.s) based on work by Gueron and Krasnov (see [Cloudflare's analysis](https://blog.cloudflare.com/go-crypto-bridging-the-performance-gap/) showing 21–30x speedups). C# and TypeScript rely on their respective runtimes' managed crypto, which generally cannot match hand-tuned assembly for raw throughput.

- **Sub-microsecond operations amplify fixed overhead.** Many algorithm benchmarks (HMAC on 256 bytes, ECDSA P-256 keygen, small-buffer encryption) complete in under 1 microsecond in Go. At these scales, the fixed per-operation overhead in managed runtimes (GC barriers, JIT compilation artifacts, Node.js event loop scheduling) becomes a large fraction of the total time, making Go appear disproportionately faster than it would be for larger workloads.

- **Serialization benchmarks measure runtime overhead, not SSH logic.** Protocol message serialization (ChannelData, ChannelOpen, KexInit) involves allocating small buffers and writing a few fields. Go's zero-overhead memory model (no GC pauses during allocation, stack-allocated small structs) makes these operations extremely fast compared to managed runtimes with heap allocation and garbage collection.

**Where performance is comparable across platforms:**

- **Session setup** — Dominated by network round-trips (TCP + SSH handshake), so all three platforms produce similar numbers.
- **Throughput** — Measures sustained data transfer over an established SSH session. The SSH protocol framing and TCP stack dominate, so differences are modest (typically < 3x).
- **RSA key generation** — Depends on probabilistic prime-number finding, which is comparable across platforms.
- **KEX cycle** — A full key exchange between two in-process sessions involves multiple round-trips, amortizing the per-operation crypto advantage.

**What the report does about this:**

The report generator uses a **200x ratio threshold** for algorithm and serialization categories (vs 10x for session/E2E categories) before flagging cross-platform differences as suspicious. This prevents the expected Go advantages from generating false-positive warnings while still catching genuine methodology mismatches in session-level benchmarks.

## Troubleshooting

- **`dotnet: command not found`** — The orchestrator auto-detects `~/.dotnet/dotnet`. Ensure .NET 8 SDK is installed.
- **ECDH failures on macOS** — The orchestrator sets `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` for Homebrew's libssl. Ensure OpenSSL is installed via `brew install openssl`.
- **Stale results** — Always use `--release` builds (the orchestrator does this automatically). Debug builds have significantly different performance characteristics.
