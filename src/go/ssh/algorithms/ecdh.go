// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"crypto/elliptic"
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
			return newECDHKeyExchange(elliptic.P256(), sha256.New)
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
			return newECDHKeyExchange(elliptic.P384(), sha512.New384)
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
			return newECDHKeyExchange(elliptic.P521(), sha512.New)
		},
	}
}

// ecdhKeyExchange is a stateful ECDH key exchange instance.
type ecdhKeyExchange struct {
	curve      elliptic.Curve
	privateKey []byte   // scalar d
	publicX    *big.Int // public key X coordinate
	publicY    *big.Int // public key Y coordinate
	hash       hash.Hash
}

func newECDHKeyExchange(curve elliptic.Curve, hashFunc func() hash.Hash) (*ecdhKeyExchange, error) {
	privateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH key: %w", err)
	}

	return &ecdhKeyExchange{
		curve:      curve,
		privateKey: privateKey,
		publicX:    x,
		publicY:    y,
		hash:       hashFunc(),
	}, nil
}

func (kex *ecdhKeyExchange) DigestLength() int {
	return kex.hash.Size()
}

func (kex *ecdhKeyExchange) StartKeyExchange() ([]byte, error) {
	// Return uncompressed point format: 0x04 || X || Y
	return elliptic.Marshal(kex.curve, kex.publicX, kex.publicY), nil
}

func (kex *ecdhKeyExchange) DecryptKeyExchange(exchangeValue []byte) ([]byte, error) {
	// Parse the remote party's public key from uncompressed point bytes.
	otherX, otherY := elliptic.Unmarshal(kex.curve, exchangeValue)
	if otherX == nil {
		return nil, fmt.Errorf("failed to parse ECDH public key: invalid point encoding")
	}

	// Compute the shared secret (x-coordinate of the resulting point).
	sharedX, _ := kex.curve.ScalarMult(otherX, otherY, kex.privateKey)

	// Convert to SSH mpint format (unsigned big-endian with sign padding).
	return sshio.BigIntToSSHBytes(sharedX), nil
}

func (kex *ecdhKeyExchange) Sign(data []byte) ([]byte, error) {
	kex.hash.Reset()
	kex.hash.Write(data)
	return kex.hash.Sum(nil), nil
}
