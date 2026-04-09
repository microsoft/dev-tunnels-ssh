// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// NewECDHP256SHA256 creates an ECDH key exchange algorithm with P-256 and SHA-256.
func NewECDHP256SHA256() *KeyExchangeAlgorithm {
	return &KeyExchangeAlgorithm{
		Name:              "ecdh-sha2-nistp256",
		KeySizeInBits:     256,
		HashAlgorithmName: "SHA-256",
		HashDigestLength:  32,
		createFunc: func() (KeyExchange, error) {
			return newECDHKeyExchange(ecdh.P256(), sha256.New)
		},
	}
}

// NewECDHP384SHA384 creates an ECDH key exchange algorithm with P-384 and SHA-384.
func NewECDHP384SHA384() *KeyExchangeAlgorithm {
	return &KeyExchangeAlgorithm{
		Name:              "ecdh-sha2-nistp384",
		KeySizeInBits:     384,
		HashAlgorithmName: "SHA-384",
		HashDigestLength:  48,
		createFunc: func() (KeyExchange, error) {
			return newECDHKeyExchange(ecdh.P384(), sha512.New384)
		},
	}
}

// NewECDHP521SHA512 creates an ECDH key exchange algorithm with P-521 and SHA-512.
func NewECDHP521SHA512() *KeyExchangeAlgorithm {
	return &KeyExchangeAlgorithm{
		Name:              "ecdh-sha2-nistp521",
		KeySizeInBits:     521,
		HashAlgorithmName: "SHA-512",
		HashDigestLength:  64,
		createFunc: func() (KeyExchange, error) {
			return newECDHKeyExchange(ecdh.P521(), sha512.New)
		},
	}
}

// ecdhKeyExchange is a stateful ECDH key exchange instance.
// Uses crypto/ecdh for constant-time operations on all curves.
type ecdhKeyExchange struct {
	curve      ecdh.Curve
	privateKey *ecdh.PrivateKey
	hash       hash.Hash
}

func newECDHKeyExchange(curve ecdh.Curve, hashFunc func() hash.Hash) (*ecdhKeyExchange, error) {
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH key: %w", err)
	}

	return &ecdhKeyExchange{
		curve:      curve,
		privateKey: privateKey,
		hash:       hashFunc(),
	}, nil
}

func (kex *ecdhKeyExchange) DigestLength() int {
	return kex.hash.Size()
}

func (kex *ecdhKeyExchange) StartKeyExchange() ([]byte, error) {
	// Returns SEC 1 uncompressed point format: 0x04 || X || Y (for NIST curves).
	return kex.privateKey.PublicKey().Bytes(), nil
}

func (kex *ecdhKeyExchange) DecryptKeyExchange(exchangeValue []byte) ([]byte, error) {
	// Parse and validate the remote party's public key.
	// NewPublicKey validates that the point is on the expected curve.
	remoteKey, err := kex.curve.NewPublicKey(exchangeValue)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDH public key: %w", err)
	}

	// Compute the shared secret (x-coordinate of the resulting point).
	// crypto/ecdh provides constant-time guarantees on all curves.
	sharedBytes, err := kex.privateKey.ECDH(remoteKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}

	// Convert to SSH mpint format (unsigned big-endian with sign padding).
	result := sshio.BigIntToSSHBytes(new(big.Int).SetBytes(sharedBytes))

	// Zero the intermediate shared secret.
	for i := range sharedBytes {
		sharedBytes[i] = 0
	}

	return result, nil
}

func (kex *ecdhKeyExchange) Sign(data []byte) ([]byte, error) {
	kex.hash.Reset()
	kex.hash.Write(data)
	return kex.hash.Sum(nil), nil
}
