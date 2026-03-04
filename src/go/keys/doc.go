// Copyright (c) Microsoft Corporation. All rights reserved.

// Package keys provides SSH key generation, import, and export for Dev Tunnels.
//
// Supported key types include RSA and ECDSA (P-256, P-384, P-521). Keys can be
// imported from and exported to multiple formats:
//   - SSH public key format (RFC 4253)
//   - PKCS#1 (RSA keys, PEM-encoded)
//   - PKCS#8 (generic private keys, PEM-encoded, with optional encryption)
//   - SEC1 (EC keys, PEM-encoded)
//   - OpenSSH private key format (with optional bcrypt/aes-256-ctr encryption)
//   - SSH2 public key format (RFC 4716)
//   - JWK (JSON Web Key, RFC 7517)
//
// Use [GenerateKeyPair] to create new keys and [ImportKeyBytes] / [ExportKeyBytes]
// for format conversion. The [KeyPair] type from the ssh package represents
// the in-memory key, while this package handles serialization.
package keys
