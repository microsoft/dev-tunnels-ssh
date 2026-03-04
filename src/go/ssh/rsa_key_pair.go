// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// RsaKeyPair implements KeyPair for RSA keys.
// It supports signing with SHA-256 (rsa-sha2-256) or SHA-512 (rsa-sha2-512).
type RsaKeyPair struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	comment    string
	hashAlgo   crypto.Hash // SHA-256 or SHA-512, determined by algorithm name
}

// generateRsaKeyPair generates a new RSA key pair with the specified key size.
func generateRsaKeyPair(keySize int, algorithmName string) (*RsaKeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return newRsaKeyPairFromPrivateKey(key, algorithmName)
}

// NewRsaKeyPair creates a new RsaKeyPair from an existing crypto/rsa private key.
// algorithmName should be "rsa-sha2-256" or "rsa-sha2-512" to determine the hash.
func NewRsaKeyPair(privateKey *rsa.PrivateKey, algorithmName string) (*RsaKeyPair, error) {
	return newRsaKeyPairFromPrivateKey(privateKey, algorithmName)
}

func newRsaKeyPairFromPrivateKey(key *rsa.PrivateKey, algorithmName string) (*RsaKeyPair, error) {
	hashAlgo, err := rsaHashAlgorithm(algorithmName)
	if err != nil {
		return nil, err
	}
	return &RsaKeyPair{
		privateKey: key,
		publicKey:  &key.PublicKey,
		hashAlgo:   hashAlgo,
	}, nil
}

// NewRsaKeyPairFromPublicKey creates a public-key-only RsaKeyPair from a crypto/rsa public key.
func NewRsaKeyPairFromPublicKey(pubKey *rsa.PublicKey) *RsaKeyPair {
	return &RsaKeyPair{
		publicKey: pubKey,
		hashAlgo:  crypto.SHA256,
	}
}

func rsaHashAlgorithm(algorithmName string) (crypto.Hash, error) {
	switch algorithmName {
	case AlgoPKRsaSha256:
		return crypto.SHA256, nil
	case AlgoPKRsaSha512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported RSA algorithm: %s", algorithmName)
	}
}

// KeyAlgorithmName returns "ssh-rsa", the SSH key algorithm identifier for RSA.
func (k *RsaKeyPair) KeyAlgorithmName() string {
	return AlgoKeyRsa
}

// HasPrivateKey returns true if this key pair includes a private key.
func (k *RsaKeyPair) HasPrivateKey() bool {
	return k.privateKey != nil
}

// Comment returns the key comment.
func (k *RsaKeyPair) Comment() string {
	return k.comment
}

// SetComment sets the key comment.
func (k *RsaKeyPair) SetComment(comment string) {
	k.comment = comment
}

// GetPublicKeyBytes returns the RSA public key in SSH wire format.
// Format: [string "ssh-rsa"][mpint e][mpint n]
func (k *RsaKeyPair) GetPublicKeyBytes() ([]byte, error) {
	if k.publicKey == nil {
		return nil, fmt.Errorf("key is not present")
	}

	writer := sshio.NewSSHDataWriter(make([]byte, 0))
	writer.WriteString(AlgoKeyRsa)
	writer.WriteBigInt(big.NewInt(int64(k.publicKey.E)))
	writer.WriteBigInt(k.publicKey.N)
	return writer.ToBuffer(), nil
}

// SetPublicKeyBytes imports an RSA public key from SSH wire format bytes.
// Accepts algorithm names: "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512".
func (k *RsaKeyPair) SetPublicKeyBytes(data []byte) error {
	reader := sshio.NewSSHDataReader(data)

	algorithmName, err := reader.ReadString()
	if err != nil {
		return fmt.Errorf("failed to read algorithm name: %w", err)
	}
	if algorithmName != AlgoKeyRsa &&
		algorithmName != AlgoPKRsaSha256 &&
		algorithmName != AlgoPKRsaSha512 {
		return fmt.Errorf("invalid RSA key algorithm: %s", algorithmName)
	}

	e, err := reader.ReadBigInt()
	if err != nil {
		return fmt.Errorf("failed to read exponent: %w", err)
	}

	n, err := reader.ReadBigInt()
	if err != nil {
		return fmt.Errorf("failed to read modulus: %w", err)
	}

	k.publicKey = &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}
	k.privateKey = nil
	return nil
}

// Sign signs data using the RSA private key with PKCS#1 v1.5 padding.
// The hash algorithm (SHA-256 or SHA-512) is determined by the algorithm name
// used when creating the key pair.
func (k *RsaKeyPair) Sign(data []byte) ([]byte, error) {
	if k.privateKey == nil {
		return nil, fmt.Errorf("private key is required for signing")
	}

	h := k.hashAlgo.New()
	h.Write(data)
	digest := h.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, k.privateKey, k.hashAlgo, digest)
}

// Verify verifies an RSA PKCS#1 v1.5 signature over data.
func (k *RsaKeyPair) Verify(data, signature []byte) (bool, error) {
	if k.publicKey == nil {
		return false, fmt.Errorf("public key is required for verification")
	}

	h := k.hashAlgo.New()
	h.Write(data)
	digest := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(k.publicKey, k.hashAlgo, digest, signature)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// PublicKey returns the underlying crypto/rsa public key.
func (k *RsaKeyPair) PublicKey() *rsa.PublicKey {
	return k.publicKey
}

// PrivateKey returns the underlying crypto/rsa private key, or nil.
func (k *RsaKeyPair) PrivateKey() *rsa.PrivateKey {
	return k.privateKey
}
