// Copyright (c) Microsoft Corporation. All rights reserved.

// Package algorithms provides cryptographic algorithm implementations for
// SSH key exchange, encryption, and message authentication.
//
// This package defines the interfaces and concrete implementations for:
//   - Key exchange algorithms (ECDH, DH) via [KeyExchangeAlgorithm]
//   - Symmetric encryption (AES-GCM, AES-CTR, AES-CBC) via [EncryptionAlgorithm]
//   - Message authentication codes (HMAC-SHA2) via [HmacAlgorithm]
//
// Algorithms are configured in [ssh.SessionConfig] and negotiated during
// the SSH key exchange handshake (RFC 4253). Each algorithm type has a
// factory that creates stateful instances for the duration of a session.
//
// The "none" algorithm (represented by a nil entry in algorithm lists) disables
// the corresponding security layer, which is useful for testing.
package algorithms
