// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// MessageSigner computes authentication tags for SSH messages.
type MessageSigner interface {
	// DigestLength returns the MAC tag size in bytes.
	DigestLength() int

	// Sign computes the MAC tag for the given data.
	Sign(data []byte) []byte

	// EncryptThenMac returns true if the MAC should be computed over
	// ciphertext rather than plaintext.
	EncryptThenMac() bool

	// AuthenticatedEncryption returns true if this signer is part of an
	// AEAD cipher (e.g., GCM) rather than a separate HMAC.
	AuthenticatedEncryption() bool
}

// MessageVerifier verifies authentication tags on SSH messages.
type MessageVerifier interface {
	// DigestLength returns the MAC tag size in bytes.
	DigestLength() int

	// Verify checks if the signature matches the data.
	Verify(data, signature []byte) bool

	// EncryptThenMac returns true if the MAC should be verified over
	// ciphertext rather than plaintext.
	EncryptThenMac() bool

	// AuthenticatedEncryption returns true if this verifier is part of an
	// AEAD cipher (e.g., GCM) rather than a separate HMAC.
	AuthenticatedEncryption() bool
}

// HmacAlgorithm describes an HMAC algorithm and creates MessageSigner
// and MessageVerifier instances.
type HmacAlgorithm struct {
	// Name is the SSH algorithm name (e.g., "hmac-sha2-256").
	Name string

	// KeyLength is the HMAC key size in bytes.
	KeyLength int

	// DigestLength is the MAC tag size in bytes.
	digestLength int

	// IsEtm indicates this is an encrypt-then-MAC variant.
	IsEtm bool

	// hashFunc is the hash constructor for this HMAC algorithm.
	hashFunc func() hash.Hash
}

// CreateSigner creates a new MessageSigner using the given key.
func (a *HmacAlgorithm) CreateSigner(key []byte) MessageSigner {
	return &hmacSigner{
		mac:       hmac.New(a.hashFunc, key[:a.KeyLength]),
		digestLen: a.digestLength,
		etm:       a.IsEtm,
		hashFunc:  a.hashFunc,
		key:       key[:a.KeyLength],
		sumBuf:    make([]byte, 0, a.digestLength),
	}
}

// CreateVerifier creates a new MessageVerifier using the given key.
func (a *HmacAlgorithm) CreateVerifier(key []byte) MessageVerifier {
	return &hmacVerifier{
		mac:       hmac.New(a.hashFunc, key[:a.KeyLength]),
		digestLen: a.digestLength,
		etm:       a.IsEtm,
		hashFunc:  a.hashFunc,
		key:       key[:a.KeyLength],
	}
}

// --- HMAC-SHA2-256 ---

// NewHmacSha256 creates an HMAC-SHA2-256 algorithm descriptor.
func NewHmacSha256() *HmacAlgorithm {
	return &HmacAlgorithm{
		Name:         "hmac-sha2-256",
		KeyLength:    32,
		digestLength: 32,
		IsEtm:        false,
		hashFunc:     sha256.New,
	}
}

// --- HMAC-SHA2-512 ---

// NewHmacSha512 creates an HMAC-SHA2-512 algorithm descriptor.
func NewHmacSha512() *HmacAlgorithm {
	return &HmacAlgorithm{
		Name:         "hmac-sha2-512",
		KeyLength:    64,
		digestLength: 64,
		IsEtm:        false,
		hashFunc:     sha512.New,
	}
}

// --- HMAC-SHA2-256-ETM ---

// NewHmacSha256Etm creates an HMAC-SHA2-256 encrypt-then-MAC algorithm descriptor.
func NewHmacSha256Etm() *HmacAlgorithm {
	return &HmacAlgorithm{
		Name:         "hmac-sha2-256-etm@openssh.com",
		KeyLength:    32,
		digestLength: 32,
		IsEtm:        true,
		hashFunc:     sha256.New,
	}
}

// --- HMAC-SHA2-512-ETM ---

// NewHmacSha512Etm creates an HMAC-SHA2-512 encrypt-then-MAC algorithm descriptor.
func NewHmacSha512Etm() *HmacAlgorithm {
	return &HmacAlgorithm{
		Name:         "hmac-sha2-512-etm@openssh.com",
		KeyLength:    64,
		digestLength: 64,
		IsEtm:        true,
		hashFunc:     sha512.New,
	}
}

// --- hmacSigner ---

type hmacSigner struct {
	mac       hash.Hash
	digestLen int
	etm       bool
	hashFunc  func() hash.Hash
	key       []byte
	sumBuf    []byte // reusable buffer for Sum output
}

func (s *hmacSigner) DigestLength() int {
	return s.digestLen
}

// Sign computes the HMAC of data.
//
// The returned slice aliases internal state and is valid only until the next
// call to Sign. Callers must not modify the returned slice.
func (s *hmacSigner) Sign(data []byte) []byte {
	s.mac.Reset()
	s.mac.Write(data)
	s.sumBuf = s.mac.Sum(s.sumBuf[:0])
	return s.sumBuf
}

func (s *hmacSigner) EncryptThenMac() bool {
	return s.etm
}

func (s *hmacSigner) AuthenticatedEncryption() bool {
	return false
}

// --- hmacVerifier ---

type hmacVerifier struct {
	mac       hash.Hash
	digestLen int
	etm       bool
	hashFunc  func() hash.Hash
	key       []byte
}

func (v *hmacVerifier) DigestLength() int {
	return v.digestLen
}

func (v *hmacVerifier) Verify(data, signature []byte) bool {
	v.mac.Reset()
	v.mac.Write(data)
	expected := v.mac.Sum(nil)
	return hmac.Equal(expected, signature)
}

func (v *hmacVerifier) EncryptThenMac() bool {
	return v.etm
}

func (v *hmacVerifier) AuthenticatedEncryption() bool {
	return false
}
