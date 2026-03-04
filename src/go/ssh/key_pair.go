// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"crypto"
	"fmt"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// PrivateKeyProvider is a callback that provides a full key pair (with private key)
// given a public-key-only key pair. It is called during authentication or key exchange
// when a key in the credentials list does not have private key material loaded.
// This enables deferred/lazy loading of private keys from secure storage (e.g., HSMs,
// key vaults, or encrypted files) rather than requiring all private keys in memory upfront.
type PrivateKeyProvider func(ctx context.Context, publicKey KeyPair) (KeyPair, error)

// KeyAlgorithmName constants for SSH key types.
const (
	// AlgoKeyRsa is the SSH key algorithm name for RSA keys.
	AlgoKeyRsa = "ssh-rsa"
)

// KeyPair represents an SSH key pair with optional private key for signing.
type KeyPair interface {
	// KeyAlgorithmName returns the SSH key algorithm name
	// (e.g., "ssh-rsa", "ecdsa-sha2-nistp256").
	KeyAlgorithmName() string

	// HasPrivateKey returns true if the key pair includes a private key for signing.
	HasPrivateKey() bool

	// GetPublicKeyBytes returns the public key in SSH wire format.
	// The format is: [string algorithm-name][key-type-specific data].
	GetPublicKeyBytes() ([]byte, error)

	// SetPublicKeyBytes imports a public key from SSH wire format bytes.
	// After calling this, HasPrivateKey returns false.
	SetPublicKeyBytes(data []byte) error

	// Comment returns the key comment string.
	Comment() string

	// SetComment sets the key comment string.
	SetComment(comment string)
}

// GenerateKeyPair generates a new key pair for the specified algorithm.
// Supported algorithm names:
//   - "rsa-sha2-256": RSA 2048-bit with SHA-256 signing
//   - "rsa-sha2-512": RSA 4096-bit with SHA-512 signing
//   - "ecdsa-sha2-nistp256": ECDSA with P-256 curve
//   - "ecdsa-sha2-nistp384": ECDSA with P-384 curve
//   - "ecdsa-sha2-nistp521": ECDSA with P-521 curve
func GenerateKeyPair(algorithmName string) (KeyPair, error) {
	switch algorithmName {
	case AlgoPKRsaSha256:
		return generateRsaKeyPair(2048, algorithmName)
	case AlgoPKRsaSha512:
		return generateRsaKeyPair(4096, algorithmName)
	case AlgoPKEcdsaSha2P256, AlgoPKEcdsaSha2P384, AlgoPKEcdsaSha2P521:
		return generateEcdsaKeyPair(algorithmName)
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algorithmName)
	}
}

// KeyPairFromPublicKeyBytes creates a KeyPair from SSH wire-format public key bytes.
// The algorithm name is read from the beginning of the data.
func KeyPairFromPublicKeyBytes(data []byte) (KeyPair, error) {
	reader := sshio.NewSSHDataReader(data)
	algorithmName, err := reader.ReadString()
	if err != nil {
		return nil, fmt.Errorf("failed to read algorithm from key bytes: %w", err)
	}

	switch algorithmName {
	case AlgoPKRsaSha256, AlgoPKRsaSha512, AlgoKeyRsa:
		kp := &RsaKeyPair{}
		if err := kp.SetPublicKeyBytes(data); err != nil {
			return nil, err
		}
		if algorithmName == AlgoPKRsaSha512 {
			kp.hashAlgo = crypto.SHA512
		} else {
			kp.hashAlgo = crypto.SHA256
		}
		return kp, nil
	case AlgoPKEcdsaSha2P256, AlgoPKEcdsaSha2P384, AlgoPKEcdsaSha2P521:
		kp := &EcdsaKeyPair{}
		if err := kp.SetPublicKeyBytes(data); err != nil {
			return nil, err
		}
		return kp, nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algorithmName)
	}
}
