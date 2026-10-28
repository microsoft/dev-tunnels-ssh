# Dev Tunnels SSH — Cross-Platform Feature Matrix

The Dev Tunnels SSH library is implemented across two platforms: **C#** and
**TypeScript**. Both share the same SSH2 protocol, the same algorithm negotiation, the
same protocol extensions, and the same event-driven API shape — so a client built with
either implementation can talk to a server built with the other.

This document maps every feature and algorithm to the platforms that support it.

## Platform Overview

| | C# | TypeScript |
|---|---|---|
| **Module** | `Microsoft.DevTunnels.Ssh` | `@microsoft/dev-tunnels-ssh` |
| **Runtime** | .NET 4.8 / .NET 6+ / .NET 8+ | Node.js 20+ / Browser |
| **Crypto backend** | CNG (Windows), OpenSSL (Mac/Linux) | Node.js `crypto` / Web Crypto API |
| **Async model** | async/await (Tasks) | async/await (Promises) |
| **API style** | Events (`EventHandler<T>`) | Events (vscode-jsonrpc `Emitter`) |
| **Naming** | PascalCase | camelCase |
| **Version string** | `SSH-2.0-dev-tunnels-ssh_x.y` | `SSH-2.0-dev-tunnels-ssh-ts_x.y` |

## Algorithm Support

### Key Exchange (KEX)

| Algorithm | C# | TypeScript |
|---|---|---|
| `ecdh-sha2-nistp521` | Yes | Yes |
| `ecdh-sha2-nistp384` | Yes | Yes |
| `ecdh-sha2-nistp256` | Yes | Yes |
| `diffie-hellman-group16-sha512` | Yes | Yes |
| `diffie-hellman-group14-sha256` | Yes | Yes |
| `none` | Yes | Yes |

**Default preference** (all platforms): ecdh-sha2-nistp384 > ecdh-sha2-nistp256 >
diffie-hellman-group16-sha512 > diffie-hellman-group14-sha256

**Platform notes:**
- C#: ECDH requires Windows 10+ (auto-falls back to DH on older Windows).
  Enabled via `SSH_ENABLE_ECDH` conditional compilation.

### Public Key

| Algorithm | C# | TypeScript |
|---|---|---|
| `rsa-sha2-512` | Yes | Yes |
| `rsa-sha2-256` | Yes | Yes |
| `ecdsa-sha2-nistp521` | Yes | Yes |
| `ecdsa-sha2-nistp384` | Yes | Yes |
| `ecdsa-sha2-nistp256` | Yes | Yes |
| `none` | Yes | Yes |

**Default preference** (all platforms): rsa-sha2-512 > rsa-sha2-256 >
ecdsa-sha2-nistp384 > ecdsa-sha2-nistp256

### Encryption

| Algorithm | C# | TypeScript |
|---|---|---|
| `aes256-gcm@openssh.com` | Yes | Yes |
| `aes256-cbc` | Yes | Node.js only |
| `aes256-ctr` | Yes | Yes |
| `none` | Yes | Yes |

**Default preference** (all platforms): aes256-gcm > aes256-cbc > aes256-ctr

**Platform notes:**
- C#: AES-GCM requires .NET Standard 2.1+ (not available on .NET Framework 4.8).
  Enabled via `SSH_ENABLE_AESGCM` conditional compilation.
- TypeScript: AES-CBC not supported in browser (Web Crypto padding incompatible
  with SSH). Not included in default config even on Node.js.

### HMAC (Integrity)

| Algorithm | C# | TypeScript |
|---|---|---|
| `hmac-sha2-512-etm@openssh.com` | Yes | Yes |
| `hmac-sha2-256-etm@openssh.com` | Yes | Yes |
| `hmac-sha2-512` | Yes | Yes |
| `hmac-sha2-256` | Yes | Yes |
| `none` | Yes | Yes |

**Default preference** (all platforms): hmac-sha2-512-etm > hmac-sha2-256-etm >
hmac-sha2-512 > hmac-sha2-256

### Compression

| Algorithm | C# | TypeScript |
|---|---|---|
| `none` | Yes | Yes |

No implementation currently supports zlib compression.

## Authentication Methods

| Method | C# | TypeScript |
|---|---|---|
| `none` | Yes | Yes |
| `password` | Yes | Yes |
| `publickey` | Yes | Yes |
| `publickey` (query-only) | Yes | Yes |
| `hostbased` | Yes | Yes |
| `keyboard-interactive` | Yes | Yes |
| Server public key verification | Yes | Yes |

All five client authentication methods and server host-key verification are
supported and enabled by default on all platforms.

## Key Formats (Import / Export)

| Format | C# | TypeScript |
|---|---|---|
| **SSH** (RFC 4253 wire format) | Import + Export | Import + Export |
| **SSH2** (RFC 4716) | Import + Export | — |
| **PKCS#1** (RSA PEM) | Import + Export | Import + Export |
| **SEC1** (EC PEM) | Import + Export | Import + Export |
| **PKCS#8** (universal PEM) | Import + Export | Import + Export |
| **OpenSSH** (proprietary) | Import + Export | — |
| **JWK** (RFC 7517) | Import + Export | Import + Export |

**Key types** supported on all platforms: RSA (2048, 4096-bit) and ECDSA (P-256, P-384, P-521).

**Password-protected keys**: All platforms support encrypted import/export for
PKCS#8 and OpenSSH formats. PKCS#1/SEC1 password protection is supported but
uses weaker encryption (not recommended).

## Protocol Extensions (RFC 8308)

| Extension | C# | TypeScript |
|---|---|---|
| `server-sig-algs` | Yes (default) | Yes (default) |
| `open-channel-request@microsoft.com` | Yes (default) | Yes (default) |
| `session-reconnect@microsoft.com` | Yes (opt-in) | Yes (opt-in) |
| `session-latency@microsoft.com` | Yes (opt-in) | Yes (opt-in) |

Reconnection and latency extensions are enabled via `DefaultWithReconnect` config.

## Core Features

### Session & Channel

| Feature | C# | TypeScript |
|---|---|---|
| SSH over any stream | Yes | Yes |
| Channel multiplexing | Yes | Yes |
| Channel types (session, direct-tcpip, forwarded-tcpip, custom) | Yes | Yes |
| Channel data (send/receive) | Yes | Yes |
| Extended data (stderr) | Yes | Yes |
| Channel requests (exec, shell, subsystem, custom) | Yes | Yes |
| Channel signals (exit-status, exit-signal) | Yes | Yes |
| Window-based flow control | Yes | Yes |
| Session-level requests | Yes | Yes |
| Stream wrapper (`SshStream` / `Stream`) | Yes | Yes |
| Session metrics (bytes, messages, latency) | Yes | Yes |

### Advanced Features

| Feature | C# | TypeScript |
|---|---|---|
| Session reconnection | Yes | Yes |
| Session piping (relay) | Yes | Yes |
| Channel piping | Yes | Yes |
| Port forwarding (local → remote) | Yes | Yes |
| Port forwarding (remote → local) | Yes | Yes |
| Stream-based port forwarding (no TCP listener) | Yes | Yes |
| Keep-alive (`keepalive@openssh.com`) | Yes | Yes |
| Key rotation (rekey after threshold) | Yes | Yes |
| Service activation pattern | Yes | Yes |
| Custom services | Yes | Yes |

### Platform-Specific Features

| Feature | C# | TypeScript |
|---|---|---|
| Browser support (Web Crypto) | — | Yes |
| Config immutability (`Lock()`) | Yes | — |
| Conditional compilation flags | Yes | — |

**Non-blocking dispatch**: Both platforms ensure a slow channel request handler
doesn't block other channels, using async/await to yield the thread.

## Configuration Presets

| Preset | C# | TypeScript |
|---|---|---|
| Default (secure) | `SshSessionConfiguration.Default` | `new SshSessionConfiguration()` |
| Default + reconnect | `SshSessionConfiguration.DefaultWithReconnect` | `new SshSessionConfiguration(true)` |
| No security (testing) | `new SshSessionConfiguration(false)` | `new SshSessionConfiguration(false)` |

All presets produce identical algorithm preference orders across platforms.

## Package Structure

Each platform ships three packages with the same functional split:

| Purpose | C# (NuGet) | TypeScript (npm) |
|---------|-----------|-----------------|
| Core SSH | `Microsoft.DevTunnels.Ssh` | `@microsoft/dev-tunnels-ssh` |
| Key import/export | `Microsoft.DevTunnels.Ssh.Keys` | `@microsoft/dev-tunnels-ssh-keys` |
| TCP + port forwarding | `Microsoft.DevTunnels.Ssh.Tcp` | `@microsoft/dev-tunnels-ssh-tcp` |

## Platform Requirements & Limitations

### C#

| Requirement | Details |
|---|---|
| .NET Framework 4.8 | Windows only. No AES-GCM, no `Span<T>` optimization. |
| .NET Standard 2.1 / .NET 6+ | Cross-platform. Full feature support. |
| .NET 8+ | Cross-platform. Trimming support, OpenSSL v3. |
| ECDH on Windows | Requires Windows 10+ (`BCRYPT_KDF_RAW_SECRET`). Auto-disabled on older. |
| AES-GCM | Requires .NET Standard 2.1+. Falls back to CBC/CTR on .NET Framework. |
| macOS/Linux crypto | Requires OpenSSL installed. |

### TypeScript

| Requirement | Details |
|---|---|
| Node.js 20+ | Full feature support including AES-CBC and TCP listeners. |
| Browser | Web Crypto API required. No AES-CBC, no TCP listeners. Stream-based port forwarding works. |

## Cross-Implementation Interop

Both implementations are wire-compatible. Each is covered by self-test scenarios
over real TCP sockets:

- **Algorithm combos**: 3 different KEX/encryption/HMAC/pubkey combinations tested
- **Feature modes**: echo, large data (1 MB), multi-channel, public key auth

See `test/e2e/README.md` for detailed end-to-end test documentation.
