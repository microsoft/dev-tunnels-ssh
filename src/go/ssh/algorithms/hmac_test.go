// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestHmacSha256SignVerify(t *testing.T) {
	algo := NewHmacSha256()
	key := make([]byte, algo.KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	data := []byte("hello, SSH protocol")
	signer := algo.CreateSigner(key)
	verifier := algo.CreateVerifier(key)

	sig := signer.Sign(data)
	if len(sig) != algo.digestLength {
		t.Fatalf("expected digest length %d, got %d", algo.digestLength, len(sig))
	}

	if !verifier.Verify(data, sig) {
		t.Fatal("HMAC-SHA2-256 verify should succeed with correct key")
	}
}

func TestHmacSha512SignVerify(t *testing.T) {
	algo := NewHmacSha512()
	key := make([]byte, algo.KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	data := []byte("hello, SSH protocol")
	signer := algo.CreateSigner(key)
	verifier := algo.CreateVerifier(key)

	sig := signer.Sign(data)
	if len(sig) != algo.digestLength {
		t.Fatalf("expected digest length %d, got %d", algo.digestLength, len(sig))
	}

	if !verifier.Verify(data, sig) {
		t.Fatal("HMAC-SHA2-512 verify should succeed with correct key")
	}
}

func TestHmacSha256EtmSignVerify(t *testing.T) {
	algo := NewHmacSha256Etm()
	key := make([]byte, algo.KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	data := []byte("encrypt-then-MAC test data")
	signer := algo.CreateSigner(key)
	verifier := algo.CreateVerifier(key)

	sig := signer.Sign(data)
	if !verifier.Verify(data, sig) {
		t.Fatal("HMAC-SHA2-256-ETM verify should succeed with correct key")
	}

	// Verify EtM flag.
	if !signer.EncryptThenMac() {
		t.Fatal("signer should report EncryptThenMac=true")
	}
	if !verifier.EncryptThenMac() {
		t.Fatal("verifier should report EncryptThenMac=true")
	}
	if signer.AuthenticatedEncryption() {
		t.Fatal("signer should report AuthenticatedEncryption=false")
	}
	if verifier.AuthenticatedEncryption() {
		t.Fatal("verifier should report AuthenticatedEncryption=false")
	}
}

func TestHmacSha512EtmSignVerify(t *testing.T) {
	algo := NewHmacSha512Etm()
	key := make([]byte, algo.KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	data := []byte("encrypt-then-MAC test data for SHA-512")
	signer := algo.CreateSigner(key)
	verifier := algo.CreateVerifier(key)

	sig := signer.Sign(data)
	if !verifier.Verify(data, sig) {
		t.Fatal("HMAC-SHA2-512-ETM verify should succeed with correct key")
	}

	if !signer.EncryptThenMac() {
		t.Fatal("signer should report EncryptThenMac=true")
	}
	if !verifier.EncryptThenMac() {
		t.Fatal("verifier should report EncryptThenMac=true")
	}
}

func TestHmacVerifyFailsWithWrongKey(t *testing.T) {
	algos := []*HmacAlgorithm{
		NewHmacSha256(),
		NewHmacSha512(),
		NewHmacSha256Etm(),
		NewHmacSha512Etm(),
	}

	for _, algo := range algos {
		t.Run(algo.Name, func(t *testing.T) {
			key1 := make([]byte, algo.KeyLength)
			key2 := make([]byte, algo.KeyLength)
			if _, err := rand.Read(key1); err != nil {
				t.Fatal(err)
			}
			if _, err := rand.Read(key2); err != nil {
				t.Fatal(err)
			}

			data := []byte("test data")
			signer := algo.CreateSigner(key1)
			verifier := algo.CreateVerifier(key2)

			sig := signer.Sign(data)
			if verifier.Verify(data, sig) {
				t.Fatal("verify should fail with wrong key")
			}
		})
	}
}

func TestHmacVerifyFailsWithTamperedData(t *testing.T) {
	algos := []*HmacAlgorithm{
		NewHmacSha256(),
		NewHmacSha512(),
		NewHmacSha256Etm(),
		NewHmacSha512Etm(),
	}

	for _, algo := range algos {
		t.Run(algo.Name, func(t *testing.T) {
			key := make([]byte, algo.KeyLength)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}

			data := []byte("test data")
			signer := algo.CreateSigner(key)
			verifier := algo.CreateVerifier(key)

			sig := signer.Sign(data)

			// Tamper with data.
			tampered := make([]byte, len(data))
			copy(tampered, data)
			tampered[0] ^= 0xFF

			if verifier.Verify(tampered, sig) {
				t.Fatal("verify should fail with tampered data")
			}
		})
	}
}

func TestHmacSignDeterministic(t *testing.T) {
	algo := NewHmacSha256()
	key := make([]byte, algo.KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	data := []byte("deterministic test")
	signer := algo.CreateSigner(key)

	sig1 := signer.Sign(data)
	sig2 := signer.Sign(data)

	if !bytes.Equal(sig1, sig2) {
		t.Fatal("HMAC should produce deterministic signatures for same data")
	}
}

// TestHmacSignSequentialVaryingSizes verifies that the HMAC signer correctly
// handles sequential Sign() calls with varying data sizes, exercising the
// internal sumBuf reuse.
func TestHmacSignSequentialVaryingSizes(t *testing.T) {
	algos := []*HmacAlgorithm{
		NewHmacSha256(), NewHmacSha512(), NewHmacSha256Etm(), NewHmacSha512Etm(),
	}

	for _, algo := range algos {
		t.Run(algo.Name, func(t *testing.T) {
			key := make([]byte, algo.KeyLength)
			rand.Read(key)
			signer := algo.CreateSigner(key)
			verifier := algo.CreateVerifier(key)

			sizes := []int{1, 100, 32 * 1024, 50, 1}
			for _, size := range sizes {
				data := make([]byte, size)
				rand.Read(data)

				sig := signer.Sign(data)
				// Copy immediately since Sign() returns aliased internal state.
				sigCopy := make([]byte, len(sig))
				copy(sigCopy, sig)

				if !verifier.Verify(data, sigCopy) {
					t.Fatalf("verify failed for data size %d", size)
				}
			}
		})
	}
}

// TestHmacSignReturnsInternalState verifies Sign() returns a slice aliasing
// internal state that is overwritten by the next Sign() call.
func TestHmacSignReturnsInternalState(t *testing.T) {
	algo := NewHmacSha256()
	key := make([]byte, algo.KeyLength)
	rand.Read(key)
	signer := algo.CreateSigner(key)

	data1 := []byte("first message")
	data2 := []byte("second message")

	sig1 := signer.Sign(data1)
	saved := make([]byte, len(sig1))
	copy(saved, sig1)

	sig2 := signer.Sign(data2)

	// sig1 and sig2 should alias the same internal buffer.
	if &sig1[0] != &sig2[0] {
		t.Fatal("Sign() should return the same internal slice across calls")
	}

	// The saved value of sig1 should differ from sig2 (different data).
	if bytes.Equal(saved, sig2) {
		t.Fatal("signatures for different data should differ")
	}
}

func TestHmacAlgorithmNames(t *testing.T) {
	tests := []struct {
		algo   *HmacAlgorithm
		name   string
		keyLen int
		digLen int
		isEtm  bool
	}{
		{NewHmacSha256(), "hmac-sha2-256", 32, 32, false},
		{NewHmacSha512(), "hmac-sha2-512", 64, 64, false},
		{NewHmacSha256Etm(), "hmac-sha2-256-etm@openssh.com", 32, 32, true},
		{NewHmacSha512Etm(), "hmac-sha2-512-etm@openssh.com", 64, 64, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.algo.Name != tt.name {
				t.Errorf("expected name %q, got %q", tt.name, tt.algo.Name)
			}
			if tt.algo.KeyLength != tt.keyLen {
				t.Errorf("expected key length %d, got %d", tt.keyLen, tt.algo.KeyLength)
			}
			if tt.algo.digestLength != tt.digLen {
				t.Errorf("expected digest length %d, got %d", tt.digLen, tt.algo.digestLength)
			}
			if tt.algo.IsEtm != tt.isEtm {
				t.Errorf("expected IsEtm=%v, got %v", tt.isEtm, tt.algo.IsEtm)
			}
		})
	}
}

func TestHmacNonEtmFlags(t *testing.T) {
	algo := NewHmacSha256()
	key := make([]byte, algo.KeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	signer := algo.CreateSigner(key)
	verifier := algo.CreateVerifier(key)

	if signer.EncryptThenMac() {
		t.Fatal("non-ETM signer should report EncryptThenMac=false")
	}
	if verifier.EncryptThenMac() {
		t.Fatal("non-ETM verifier should report EncryptThenMac=false")
	}
	if signer.AuthenticatedEncryption() {
		t.Fatal("HMAC signer should report AuthenticatedEncryption=false")
	}
	if verifier.AuthenticatedEncryption() {
		t.Fatal("HMAC verifier should report AuthenticatedEncryption=false")
	}
}
