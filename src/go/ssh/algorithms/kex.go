// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

// KeyExchange represents a stateful key exchange instance that generates
// ephemeral keys and derives shared secrets.
type KeyExchange interface {
	// DigestLength returns the hash digest length in bytes.
	DigestLength() int

	// StartKeyExchange generates ephemeral keys and returns the public
	// exchange value.
	// For DH: returns SSH mpint-format value bytes.
	// For ECDH: returns uncompressed point bytes (0x04 || X || Y).
	StartKeyExchange() ([]byte, error)

	// DecryptKeyExchange takes the remote party's exchange value and
	// returns the shared secret in SSH mpint-format value bytes.
	DecryptKeyExchange(exchangeValue []byte) ([]byte, error)

	// Sign hashes the given data using this algorithm's hash function
	// and returns the digest.
	Sign(data []byte) ([]byte, error)
}

// KeyExchangeAlgorithm describes a key exchange algorithm and creates
// stateful KeyExchange instances for performing actual exchanges.
type KeyExchangeAlgorithm struct {
	// Name is the SSH algorithm name (e.g., "diffie-hellman-group14-sha256").
	Name string

	// KeySizeInBits is the key size in bits.
	KeySizeInBits int

	// HashAlgorithmName is the hash algorithm name (e.g., "SHA-256").
	HashAlgorithmName string

	// HashDigestLength is the hash digest length in bytes.
	HashDigestLength int

	// createFunc is the factory function for creating key exchange instances.
	createFunc func() (KeyExchange, error)
}

// CreateKeyExchange creates a new stateful key exchange instance.
func (a *KeyExchangeAlgorithm) CreateKeyExchange() (KeyExchange, error) {
	return a.createFunc()
}
