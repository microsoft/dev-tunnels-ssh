// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// testKeyExchangeSharedSecret verifies that two independent key exchange
// instances from the same algorithm derive the same shared secret.
func testKeyExchangeSharedSecret(t *testing.T, algo *KeyExchangeAlgorithm) {
	t.Helper()

	kex1, err := algo.CreateKeyExchange()
	if err != nil {
		t.Fatalf("CreateKeyExchange (1) failed: %v", err)
	}

	kex2, err := algo.CreateKeyExchange()
	if err != nil {
		t.Fatalf("CreateKeyExchange (2) failed: %v", err)
	}

	// Both sides generate their public exchange values.
	pub1, err := kex1.StartKeyExchange()
	if err != nil {
		t.Fatalf("StartKeyExchange (1) failed: %v", err)
	}

	pub2, err := kex2.StartKeyExchange()
	if err != nil {
		t.Fatalf("StartKeyExchange (2) failed: %v", err)
	}

	// Public values should not be empty.
	if len(pub1) == 0 {
		t.Fatal("StartKeyExchange (1) returned empty exchange value")
	}
	if len(pub2) == 0 {
		t.Fatal("StartKeyExchange (2) returned empty exchange value")
	}

	// Public values should differ (different random keys).
	if bytes.Equal(pub1, pub2) {
		t.Fatal("two independent key exchanges produced identical public values")
	}

	// Each side decrypts the other's public value to derive the shared secret.
	secret1, err := kex1.DecryptKeyExchange(pub2)
	if err != nil {
		t.Fatalf("DecryptKeyExchange (1) failed: %v", err)
	}

	secret2, err := kex2.DecryptKeyExchange(pub1)
	if err != nil {
		t.Fatalf("DecryptKeyExchange (2) failed: %v", err)
	}

	// Both sides must derive the same shared secret.
	if !bytes.Equal(secret1, secret2) {
		t.Fatalf("shared secrets differ:\n  side 1: %x\n  side 2: %x", secret1, secret2)
	}

	// Shared secret should not be empty.
	if len(secret1) == 0 {
		t.Fatal("shared secret is empty")
	}

	// Verify Sign produces correct digest length.
	testData := []byte("test data for hashing")
	digest, err := kex1.Sign(testData)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(digest) != algo.HashDigestLength {
		t.Fatalf("digest length = %d, want %d", len(digest), algo.HashDigestLength)
	}
	if len(digest) != kex1.DigestLength() {
		t.Fatalf("digest length = %d, want DigestLength() = %d", len(digest), kex1.DigestLength())
	}

	// Sign should be deterministic for the same input.
	digest2, err := kex1.Sign(testData)
	if err != nil {
		t.Fatalf("Sign (2) failed: %v", err)
	}
	if !bytes.Equal(digest, digest2) {
		t.Fatal("Sign produced different digests for the same input")
	}
}

func TestDHGroup14SHA256(t *testing.T) {
	algo := NewDHGroup14SHA256()
	if algo.Name != "diffie-hellman-group14-sha256" {
		t.Fatalf("Name = %q, want %q", algo.Name, "diffie-hellman-group14-sha256")
	}
	if algo.KeySizeInBits != 2048 {
		t.Fatalf("KeySizeInBits = %d, want 2048", algo.KeySizeInBits)
	}
	if algo.HashDigestLength != 32 {
		t.Fatalf("HashDigestLength = %d, want 32", algo.HashDigestLength)
	}
	testKeyExchangeSharedSecret(t, algo)
}

func TestDHGroup16SHA512(t *testing.T) {
	algo := NewDHGroup16SHA512()
	if algo.Name != "diffie-hellman-group16-sha512" {
		t.Fatalf("Name = %q, want %q", algo.Name, "diffie-hellman-group16-sha512")
	}
	if algo.KeySizeInBits != 4096 {
		t.Fatalf("KeySizeInBits = %d, want 4096", algo.KeySizeInBits)
	}
	if algo.HashDigestLength != 64 {
		t.Fatalf("HashDigestLength = %d, want 64", algo.HashDigestLength)
	}
	testKeyExchangeSharedSecret(t, algo)
}

func TestECDHP256SHA256(t *testing.T) {
	algo := NewECDHP256SHA256()
	if algo.Name != "ecdh-sha2-nistp256" {
		t.Fatalf("Name = %q, want %q", algo.Name, "ecdh-sha2-nistp256")
	}
	if algo.KeySizeInBits != 256 {
		t.Fatalf("KeySizeInBits = %d, want 256", algo.KeySizeInBits)
	}
	if algo.HashDigestLength != 32 {
		t.Fatalf("HashDigestLength = %d, want 32", algo.HashDigestLength)
	}
	testKeyExchangeSharedSecret(t, algo)
}

func TestECDHP384SHA384(t *testing.T) {
	algo := NewECDHP384SHA384()
	if algo.Name != "ecdh-sha2-nistp384" {
		t.Fatalf("Name = %q, want %q", algo.Name, "ecdh-sha2-nistp384")
	}
	if algo.KeySizeInBits != 384 {
		t.Fatalf("KeySizeInBits = %d, want 384", algo.KeySizeInBits)
	}
	if algo.HashDigestLength != 48 {
		t.Fatalf("HashDigestLength = %d, want 48", algo.HashDigestLength)
	}
	testKeyExchangeSharedSecret(t, algo)
}

func TestECDHP521SHA512(t *testing.T) {
	algo := NewECDHP521SHA512()
	if algo.Name != "ecdh-sha2-nistp521" {
		t.Fatalf("Name = %q, want %q", algo.Name, "ecdh-sha2-nistp521")
	}
	if algo.KeySizeInBits != 521 {
		t.Fatalf("KeySizeInBits = %d, want 521", algo.KeySizeInBits)
	}
	if algo.HashDigestLength != 64 {
		t.Fatalf("HashDigestLength = %d, want 64", algo.HashDigestLength)
	}
	testKeyExchangeSharedSecret(t, algo)
}

// newDHKexForTest creates a DH key exchange instance for testing validation.
func newDHKexForTest(t *testing.T) *dhKeyExchange {
	t.Helper()
	algo := NewDHGroup14SHA256()
	kex, err := algo.CreateKeyExchange()
	if err != nil {
		t.Fatalf("CreateKeyExchange failed: %v", err)
	}
	return kex.(*dhKeyExchange)
}

func TestDHRejectsZeroPublicValue(t *testing.T) {
	kex := newDHKexForTest(t)
	zeroBytes := sshio.BigIntToSSHBytes(big.NewInt(0))
	_, err := kex.DecryptKeyExchange(zeroBytes)
	if err == nil {
		t.Fatal("expected error for e=0, got nil")
	}
	if !strings.Contains(err.Error(), "invalid DH public value") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDHRejectsOnePublicValue(t *testing.T) {
	kex := newDHKexForTest(t)
	oneBytes := sshio.BigIntToSSHBytes(big.NewInt(1))
	_, err := kex.DecryptKeyExchange(oneBytes)
	if err == nil {
		t.Fatal("expected error for e=1, got nil")
	}
	if !strings.Contains(err.Error(), "invalid DH public value") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDHRejectsPMinusOnePublicValue(t *testing.T) {
	kex := newDHKexForTest(t)
	pMinusOne := new(big.Int).Sub(oakley2048, big.NewInt(1))
	pMinusOneBytes := sshio.BigIntToSSHBytes(pMinusOne)
	_, err := kex.DecryptKeyExchange(pMinusOneBytes)
	if err == nil {
		t.Fatal("expected error for e=p-1, got nil")
	}
	if !strings.Contains(err.Error(), "invalid DH public value") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDHRejectsPPublicValue(t *testing.T) {
	kex := newDHKexForTest(t)
	pBytes := sshio.BigIntToSSHBytes(oakley2048)
	_, err := kex.DecryptKeyExchange(pBytes)
	if err == nil {
		t.Fatal("expected error for e=p, got nil")
	}
	if !strings.Contains(err.Error(), "invalid DH public value") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDHRejectsNegativePublicValue(t *testing.T) {
	kex := newDHKexForTest(t)
	negBytes := sshio.BigIntToSSHBytes(big.NewInt(-1))
	_, err := kex.DecryptKeyExchange(negBytes)
	if err == nil {
		t.Fatal("expected error for negative e, got nil")
	}
	if !strings.Contains(err.Error(), "invalid DH public value") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestDHAcceptsValidPublicValue(t *testing.T) {
	kex1 := newDHKexForTest(t)
	kex2 := newDHKexForTest(t)

	pub1, err := kex1.StartKeyExchange()
	if err != nil {
		t.Fatalf("StartKeyExchange failed: %v", err)
	}

	// A legitimately generated public value should be accepted.
	secret, err := kex2.DecryptKeyExchange(pub1)
	if err != nil {
		t.Fatalf("DecryptKeyExchange rejected valid public value: %v", err)
	}
	if len(secret) == 0 {
		t.Fatal("shared secret is empty")
	}

	// Also verify the boundary value e=2 is accepted.
	twoBytes := sshio.BigIntToSSHBytes(big.NewInt(2))
	_, err = kex2.DecryptKeyExchange(twoBytes)
	if err != nil {
		t.Fatalf("DecryptKeyExchange rejected e=2: %v", err)
	}

	// And e=p-2 is accepted.
	pMinusTwo := new(big.Int).Sub(oakley2048, big.NewInt(2))
	pMinusTwoBytes := sshio.BigIntToSSHBytes(pMinusTwo)
	kex3 := newDHKexForTest(t)
	_, err = kex3.DecryptKeyExchange(pMinusTwoBytes)
	if err != nil {
		t.Fatalf("DecryptKeyExchange rejected e=p-2: %v", err)
	}
}
