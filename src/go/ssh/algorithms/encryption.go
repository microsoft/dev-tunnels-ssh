// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// Cipher provides symmetric encryption and decryption of SSH packets.
type Cipher interface {
	// BlockLength returns the cipher block size in bytes.
	BlockLength() int

	// Transform encrypts or decrypts the data in-place.
	// Returns an error if authenticated decryption fails (e.g., GCM tag mismatch).
	Transform(data []byte) error
}

// EncryptionAlgorithm describes a symmetric encryption algorithm and creates
// Cipher instances for encrypting or decrypting data.
type EncryptionAlgorithm struct {
	// Name is the SSH algorithm name (e.g., "aes256-ctr").
	Name string

	// KeyLength is the key size in bytes.
	KeyLength int

	// BlockLength is the cipher block size in bytes.
	blockLength int

	// IsAead indicates this is an Authenticated Encryption with Associated Data cipher.
	IsAead bool

	// createFunc is the factory function for creating cipher instances.
	createFunc func(isEncryption bool, key, iv []byte) (Cipher, error)
}

// CreateCipher creates a new cipher instance.
// isEncryption is true for encryption, false for decryption.
func (a *EncryptionAlgorithm) CreateCipher(isEncryption bool, key, iv []byte) (Cipher, error) {
	return a.createFunc(isEncryption, key, iv)
}

// IVLength returns the IV/nonce length required by this algorithm.
func (a *EncryptionAlgorithm) IVLength() int {
	return a.blockLength
}

// --- AES-256-CBC ---

// NewAes256Cbc creates an AES-256-CBC encryption algorithm descriptor.
func NewAes256Cbc() *EncryptionAlgorithm {
	return &EncryptionAlgorithm{
		Name:        "aes256-cbc",
		KeyLength:   32,
		blockLength: aes.BlockSize,
		IsAead:      false,
		createFunc: func(isEncryption bool, key, iv []byte) (Cipher, error) {
			return newAesCbcCipher(isEncryption, key, iv)
		},
	}
}

type aesCbcCipher struct {
	blockSize    int
	isEncryption bool
	encrypter    cipher.BlockMode
	decrypter    cipher.BlockMode
}

func newAesCbcCipher(isEncryption bool, key, iv []byte) (*aesCbcCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-cbc: %w", err)
	}

	c := &aesCbcCipher{
		blockSize:    block.BlockSize(),
		isEncryption: isEncryption,
	}

	if isEncryption {
		c.encrypter = cipher.NewCBCEncrypter(block, iv)
	} else {
		c.decrypter = cipher.NewCBCDecrypter(block, iv)
	}

	return c, nil
}

func (c *aesCbcCipher) BlockLength() int {
	return c.blockSize
}

func (c *aesCbcCipher) Transform(data []byte) error {
	if c.isEncryption {
		c.encrypter.CryptBlocks(data, data)
	} else {
		c.decrypter.CryptBlocks(data, data)
	}
	return nil
}

// --- AES-256-CTR ---

// NewAes256Ctr creates an AES-256-CTR encryption algorithm descriptor.
func NewAes256Ctr() *EncryptionAlgorithm {
	return &EncryptionAlgorithm{
		Name:        "aes256-ctr",
		KeyLength:   32,
		blockLength: aes.BlockSize,
		IsAead:      false,
		createFunc: func(isEncryption bool, key, iv []byte) (Cipher, error) {
			return newAesCtrCipher(key, iv)
		},
	}
}

type aesCtrCipher struct {
	blockSize int
	stream    cipher.Stream
}

func newAesCtrCipher(key, iv []byte) (*aesCtrCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-ctr: %w", err)
	}

	return &aesCtrCipher{
		blockSize: block.BlockSize(),
		stream:    cipher.NewCTR(block, iv),
	}, nil
}

func (c *aesCtrCipher) BlockLength() int {
	return c.blockSize
}

func (c *aesCtrCipher) Transform(data []byte) error {
	c.stream.XORKeyStream(data, data)
	return nil
}

// --- AES-256-GCM ---

const (
	gcmNonceSize = 12
	gcmTagSize   = 16
)

// NewAes256Gcm creates an AES-256-GCM encryption algorithm descriptor.
func NewAes256Gcm() *EncryptionAlgorithm {
	return &EncryptionAlgorithm{
		Name:        "aes256-gcm@openssh.com",
		KeyLength:   32,
		blockLength: aes.BlockSize,
		IsAead:      true,
		createFunc: func(isEncryption bool, key, iv []byte) (Cipher, error) {
			return newAesGcmCipher(isEncryption, key, iv)
		},
	}
}

// AesGcmCipher implements Cipher for AES-256-GCM authenticated encryption.
// It also serves as both MessageSigner and MessageVerifier since GCM provides
// built-in authentication.
type AesGcmCipher struct {
	aead         cipher.AEAD
	nonce        []byte
	isEncryption bool
	tag          []byte   // last tag produced (encryption) or to verify (decryption)
	aadBuf       [4]byte  // reusable AAD buffer (avoids per-operation allocation)
	sealBuf      []byte   // reusable buffer for Seal/Open output
}

func newAesGcmCipher(isEncryption bool, key, iv []byte) (*AesGcmCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}

	// Use the first 12 bytes of the IV as the initial nonce.
	nonce := make([]byte, gcmNonceSize)
	copy(nonce, iv[:gcmNonceSize])

	return &AesGcmCipher{
		aead:         aead,
		nonce:        nonce,
		isEncryption: isEncryption,
		tag:          make([]byte, gcmTagSize),
		sealBuf:      make([]byte, 0, 1024+gcmTagSize),
	}, nil
}

func (c *AesGcmCipher) BlockLength() int {
	return aes.BlockSize
}

// Transform encrypts or decrypts data in-place.
// For encryption: the tag is stored internally and can be retrieved via Sign().
// For decryption: the tag must be set via SetTag() before calling Transform.
// Returns an error if GCM authentication fails during decryption.
func (c *AesGcmCipher) Transform(data []byte) error {
	if c.isEncryption {
		c.transformEncrypt(data)
		return nil
	}
	return c.transformDecrypt(data)
}

func (c *AesGcmCipher) transformEncrypt(data []byte) {
	// Associated data is the 32-bit packet length (= data length).
	aad := c.makeAAD(uint32(len(data)))

	// Seal into reusable buffer: ciphertext + tag.
	needed := len(data) + gcmTagSize
	if cap(c.sealBuf) < needed {
		c.sealBuf = make([]byte, 0, needed)
	}
	c.sealBuf = c.aead.Seal(c.sealBuf[:0], c.nonce, data, aad)
	copy(data, c.sealBuf[:len(data)])
	copy(c.tag, c.sealBuf[len(data):])
	c.incrementNonce()
}

func (c *AesGcmCipher) transformDecrypt(data []byte) error {
	// Associated data is the 32-bit packet length (= data length).
	aad := c.makeAAD(uint32(len(data)))

	// Build ciphertext+tag in reusable buffer.
	needed := len(data) + gcmTagSize
	if cap(c.sealBuf) < needed {
		c.sealBuf = make([]byte, needed)
	}
	c.sealBuf = c.sealBuf[:needed]
	copy(c.sealBuf, data)
	copy(c.sealBuf[len(data):], c.tag)

	// Open into data buffer directly (data and sealBuf don't overlap).
	plaintext, err := c.aead.Open(data[:0], c.nonce, c.sealBuf, aad)
	if err != nil {
		return fmt.Errorf("gcm authentication failed: %w", err)
	}
	if len(plaintext) != len(data) {
		copy(data, plaintext)
	}
	c.incrementNonce()
	return nil
}

// makeAAD creates the Associated Authenticated Data for GCM operations.
// Per the SSH GCM spec, the AAD is the 4-byte big-endian packet length.
func (c *AesGcmCipher) makeAAD(packetLength uint32) []byte {
	binary.BigEndian.PutUint32(c.aadBuf[:], packetLength)
	return c.aadBuf[:]
}

// Sign retrieves the authentication tag produced by the last encryption.
// For GCM, this is the AEAD tag, not a separate HMAC.
//
// The returned slice aliases internal state and is valid only until the next
// call to Transform. Callers must not modify the returned slice.
func (c *AesGcmCipher) Sign(data []byte) []byte {
	return c.tag
}

// DigestLength returns the GCM tag size.
func (c *AesGcmCipher) DigestLength() int {
	return gcmTagSize
}

// EncryptThenMac returns false for GCM (it uses authenticated encryption, not EtM).
func (c *AesGcmCipher) EncryptThenMac() bool {
	return false
}

// AuthenticatedEncryption returns true for GCM.
func (c *AesGcmCipher) AuthenticatedEncryption() bool {
	return true
}

// SetTag sets the authentication tag for decryption verification.
func (c *AesGcmCipher) SetTag(tag []byte) {
	copy(c.tag, tag)
}

// Verify sets the authentication tag for subsequent decryption verification.
// For GCM, the actual verification happens during Transform (Open).
// This method stores the tag so Transform can use it.
func (c *AesGcmCipher) Verify(data, signature []byte) bool {
	c.SetTag(signature)
	return true
}

// incrementNonce increments the GCM nonce as a big-endian counter.
// The counter is in the last 8 bytes of the nonce (bytes 4-11).
func (c *AesGcmCipher) incrementNonce() {
	// Increment the nonce as a big-endian 64-bit counter in bytes 4-11.
	counter := binary.BigEndian.Uint64(c.nonce[4:])
	counter++
	binary.BigEndian.PutUint64(c.nonce[4:], counter)
}
