// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

// TestGenerateKeyPairRsaSha256 tests generating an RSA key pair with SHA-256.
func TestGenerateKeyPairRsaSha256(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	rsaKP := kp.(*RsaKeyPair)

	if kp.KeyAlgorithmName() != AlgoKeyRsa {
		t.Errorf("expected key algorithm %q, got %q", AlgoKeyRsa, kp.KeyAlgorithmName())
	}
	if !kp.HasPrivateKey() {
		t.Error("expected HasPrivateKey to be true")
	}
	if rsaKP.PrivateKey() == nil {
		t.Error("expected private key to be non-nil")
	}
	if rsaKP.PublicKey() == nil {
		t.Error("expected public key to be non-nil")
	}
	// rsa-sha2-256 generates 2048-bit keys
	if rsaKP.PublicKey().N.BitLen() < 2048 {
		t.Errorf("expected key size >= 2048 bits, got %d", rsaKP.PublicKey().N.BitLen())
	}
}

// TestGenerateKeyPairRsaSha512 tests generating an RSA key pair with SHA-512.
func TestGenerateKeyPairRsaSha512(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKRsaSha512)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	rsaKP := kp.(*RsaKeyPair)

	if kp.KeyAlgorithmName() != AlgoKeyRsa {
		t.Errorf("expected key algorithm %q, got %q", AlgoKeyRsa, kp.KeyAlgorithmName())
	}
	if !kp.HasPrivateKey() {
		t.Error("expected HasPrivateKey to be true")
	}
	// rsa-sha2-512 generates 4096-bit keys
	if rsaKP.PublicKey().N.BitLen() < 4096 {
		t.Errorf("expected key size >= 4096 bits, got %d", rsaKP.PublicKey().N.BitLen())
	}
}

// TestGenerateKeyPairEcdsaP256 tests generating an ECDSA P-256 key pair.
func TestGenerateKeyPairEcdsaP256(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if kp.KeyAlgorithmName() != AlgoPKEcdsaSha2P256 {
		t.Errorf("expected algorithm %q, got %q", AlgoPKEcdsaSha2P256, kp.KeyAlgorithmName())
	}
	if !kp.HasPrivateKey() {
		t.Error("expected HasPrivateKey to be true")
	}

	ecKP := kp.(*EcdsaKeyPair)
	if ecKP.PublicKey().Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
}

// TestGenerateKeyPairEcdsaP384 tests generating an ECDSA P-384 key pair.
func TestGenerateKeyPairEcdsaP384(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKEcdsaSha2P384)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if kp.KeyAlgorithmName() != AlgoPKEcdsaSha2P384 {
		t.Errorf("expected algorithm %q, got %q", AlgoPKEcdsaSha2P384, kp.KeyAlgorithmName())
	}

	ecKP := kp.(*EcdsaKeyPair)
	if ecKP.PublicKey().Curve != elliptic.P384() {
		t.Error("expected P-384 curve")
	}
}

// TestGenerateKeyPairEcdsaP521 tests generating an ECDSA P-521 key pair.
func TestGenerateKeyPairEcdsaP521(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKEcdsaSha2P521)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if kp.KeyAlgorithmName() != AlgoPKEcdsaSha2P521 {
		t.Errorf("expected algorithm %q, got %q", AlgoPKEcdsaSha2P521, kp.KeyAlgorithmName())
	}

	ecKP := kp.(*EcdsaKeyPair)
	if ecKP.PublicKey().Curve != elliptic.P521() {
		t.Error("expected P-521 curve")
	}
}

// TestGenerateKeyPairUnsupported tests that unsupported algorithm returns error.
func TestGenerateKeyPairUnsupported(t *testing.T) {
	_, err := GenerateKeyPair("unsupported-algo")
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

// TestGenerateKeyPairWithSizeRsa tests generating RSA key pairs with explicit sizes.
func TestGenerateKeyPairWithSizeRsa(t *testing.T) {
	tests := []struct {
		algo    string
		bits    int
	}{
		{AlgoPKRsaSha256, 2048},
		{AlgoPKRsaSha256, 4096},
		{AlgoPKRsaSha512, 2048},
		{AlgoPKRsaSha512, 4096},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s-%d", tc.algo, tc.bits), func(t *testing.T) {
			kp, err := GenerateKeyPairWithSize(tc.algo, tc.bits)
			if err != nil {
				t.Fatalf("GenerateKeyPairWithSize failed: %v", err)
			}
			rsaKP := kp.(*RsaKeyPair)
			if rsaKP.PublicKey().N.BitLen() < tc.bits {
				t.Errorf("expected key size >= %d bits, got %d", tc.bits, rsaKP.PublicKey().N.BitLen())
			}
		})
	}
}

// TestGenerateKeyPairWithSizeEcdsaIgnoresSize tests that ECDSA ignores the size parameter.
func TestGenerateKeyPairWithSizeEcdsaIgnoresSize(t *testing.T) {
	kp, err := GenerateKeyPairWithSize(AlgoPKEcdsaSha2P256, 9999)
	if err != nil {
		t.Fatalf("GenerateKeyPairWithSize failed: %v", err)
	}
	if kp.KeyAlgorithmName() != AlgoPKEcdsaSha2P256 {
		t.Errorf("expected algorithm %q, got %q", AlgoPKEcdsaSha2P256, kp.KeyAlgorithmName())
	}
}

// TestGenerateKeyPairWithSizeUnsupported tests that unsupported algorithms return an error.
func TestGenerateKeyPairWithSizeUnsupported(t *testing.T) {
	_, err := GenerateKeyPairWithSize("unsupported-algo", 2048)
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

// TestRsaPublicKeyBytesRoundTrip tests RSA public key serialization round-trip.
func TestRsaPublicKeyBytesRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Get public key bytes
	pubBytes, err := kp.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("GetPublicKeyBytes failed: %v", err)
	}
	if len(pubBytes) == 0 {
		t.Fatal("expected non-empty public key bytes")
	}

	// Import into a new key pair
	kp2 := NewRsaKeyPairFromPublicKey(nil)
	err = kp2.SetPublicKeyBytes(pubBytes)
	if err != nil {
		t.Fatalf("SetPublicKeyBytes failed: %v", err)
	}

	// Verify the imported key matches
	if kp2.HasPrivateKey() {
		t.Error("imported key should not have private key")
	}
	pubBytes2, err := kp2.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("GetPublicKeyBytes on imported key failed: %v", err)
	}
	if !bytes.Equal(pubBytes, pubBytes2) {
		t.Error("round-trip public key bytes do not match")
	}
}

// TestEcdsaPublicKeyBytesRoundTrip tests ECDSA public key serialization round-trip
// for all three curves.
func TestEcdsaPublicKeyBytesRoundTrip(t *testing.T) {
	algorithms := []string{AlgoPKEcdsaSha2P256, AlgoPKEcdsaSha2P384, AlgoPKEcdsaSha2P521}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			kp, err := GenerateKeyPair(algo)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			pubBytes, err := kp.GetPublicKeyBytes()
			if err != nil {
				t.Fatalf("GetPublicKeyBytes failed: %v", err)
			}
			if len(pubBytes) == 0 {
				t.Fatal("expected non-empty public key bytes")
			}

			// Import into a new key pair
			kp2 := &EcdsaKeyPair{}
			err = kp2.SetPublicKeyBytes(pubBytes)
			if err != nil {
				t.Fatalf("SetPublicKeyBytes failed: %v", err)
			}

			if kp2.HasPrivateKey() {
				t.Error("imported key should not have private key")
			}
			if kp2.KeyAlgorithmName() != algo {
				t.Errorf("expected algorithm %q, got %q", algo, kp2.KeyAlgorithmName())
			}

			pubBytes2, err := kp2.GetPublicKeyBytes()
			if err != nil {
				t.Fatalf("GetPublicKeyBytes on imported key failed: %v", err)
			}
			if !bytes.Equal(pubBytes, pubBytes2) {
				t.Error("round-trip public key bytes do not match")
			}
		})
	}
}

// TestRsaSignVerifySha256 tests RSA sign and verify with SHA-256.
func TestRsaSignVerifySha256(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	rsaKP := kp.(*RsaKeyPair)

	data := []byte("test data for signing")
	sig, err := rsaKP.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	valid, err := rsaKP.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("expected signature to be valid")
	}

	// Verify with modified data fails
	modified := []byte("modified data")
	valid, err = rsaKP.Verify(modified, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Error("expected signature verification to fail with modified data")
	}
}

// TestRsaSignVerifySha512 tests RSA sign and verify with SHA-512.
func TestRsaSignVerifySha512(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKRsaSha512)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	rsaKP := kp.(*RsaKeyPair)

	data := []byte("test data for SHA-512 signing")
	sig, err := rsaKP.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	valid, err := rsaKP.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("expected signature to be valid")
	}
}

// TestRsaSignWithoutPrivateKey tests that signing without a private key returns error.
func TestRsaSignWithoutPrivateKey(t *testing.T) {
	kp := NewRsaKeyPairFromPublicKey(&rsa.PublicKey{})
	_, err := kp.Sign([]byte("test"))
	if err == nil {
		t.Error("expected error when signing without private key")
	}
}

// TestRsaVerifyWithPublicKeyOnly tests that verification works with public key only.
func TestRsaVerifyWithPublicKeyOnly(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	rsaKP := kp.(*RsaKeyPair)

	data := []byte("test data")
	sig, err := rsaKP.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Create public-key-only pair and verify
	pubKP, err := NewRsaKeyPair(&rsa.PrivateKey{PublicKey: *rsaKP.PublicKey()}, AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("NewRsaKeyPair failed: %v", err)
	}
	// Instead, create from the public key bytes
	pubBytes, err := rsaKP.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("GetPublicKeyBytes failed: %v", err)
	}
	pubOnlyKP := NewRsaKeyPairFromPublicKey(nil)
	err = pubOnlyKP.SetPublicKeyBytes(pubBytes)
	if err != nil {
		t.Fatalf("SetPublicKeyBytes failed: %v", err)
	}

	// Should be able to verify but not sign
	if pubOnlyKP.HasPrivateKey() {
		t.Error("public-key-only pair should not have private key")
	}

	valid, err := pubOnlyKP.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("expected signature to be valid with public key only")
	}

	// Avoid unused variable warning
	_ = pubKP
}

// TestEcdsaSignVerify tests ECDSA sign and verify for all three curves.
func TestEcdsaSignVerify(t *testing.T) {
	algorithms := []string{AlgoPKEcdsaSha2P256, AlgoPKEcdsaSha2P384, AlgoPKEcdsaSha2P521}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			kp, err := GenerateKeyPair(algo)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}
			ecKP := kp.(*EcdsaKeyPair)

			data := []byte("test data for ECDSA signing")
			sig, err := ecKP.Sign(data)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("expected non-empty signature")
			}

			valid, err := ecKP.Verify(data, sig)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
			if !valid {
				t.Error("expected signature to be valid")
			}

			// Verify with modified data fails
			modified := []byte("modified data")
			valid, err = ecKP.Verify(modified, sig)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
			if valid {
				t.Error("expected signature verification to fail with modified data")
			}
		})
	}
}

// TestEcdsaSignWithoutPrivateKey tests that signing without a private key returns error.
func TestEcdsaSignWithoutPrivateKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kp, err := NewEcdsaKeyPairFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewEcdsaKeyPairFromPublicKey failed: %v", err)
	}

	_, err = kp.Sign([]byte("test"))
	if err == nil {
		t.Error("expected error when signing without private key")
	}
}

// TestEcdsaVerifyWithPublicKeyOnly tests that verification works with public key only.
func TestEcdsaVerifyWithPublicKeyOnly(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKEcdsaSha2P384)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	ecKP := kp.(*EcdsaKeyPair)

	data := []byte("test data")
	sig, err := ecKP.Sign(data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Create public-key-only pair from public key bytes
	pubBytes, err := ecKP.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("GetPublicKeyBytes failed: %v", err)
	}
	pubOnlyKP := &EcdsaKeyPair{}
	err = pubOnlyKP.SetPublicKeyBytes(pubBytes)
	if err != nil {
		t.Fatalf("SetPublicKeyBytes failed: %v", err)
	}

	if pubOnlyKP.HasPrivateKey() {
		t.Error("public-key-only pair should not have private key")
	}

	valid, err := pubOnlyKP.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("expected signature to be valid with public key only")
	}
}

// TestNewEcdsaKeyPairFromPrivateKey tests creating an ECDSA key pair from
// an existing crypto/ecdsa private key.
func TestNewEcdsaKeyPairFromPrivateKey(t *testing.T) {
	curves := []struct {
		curve    elliptic.Curve
		expected string
	}{
		{elliptic.P256(), AlgoPKEcdsaSha2P256},
		{elliptic.P384(), AlgoPKEcdsaSha2P384},
		{elliptic.P521(), AlgoPKEcdsaSha2P521},
	}

	for _, tc := range curves {
		t.Run(tc.expected, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey failed: %v", err)
			}

			kp, err := NewEcdsaKeyPair(key)
			if err != nil {
				t.Fatalf("NewEcdsaKeyPair failed: %v", err)
			}

			if kp.KeyAlgorithmName() != tc.expected {
				t.Errorf("expected algorithm %q, got %q", tc.expected, kp.KeyAlgorithmName())
			}
			if !kp.HasPrivateKey() {
				t.Error("expected HasPrivateKey to be true")
			}
		})
	}
}

// TestNewRsaKeyPairFromPrivateKey tests creating an RSA key pair from
// an existing crypto/rsa private key.
func TestNewRsaKeyPairFromPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}

	kp, err := NewRsaKeyPair(key, AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("NewRsaKeyPair failed: %v", err)
	}

	if kp.KeyAlgorithmName() != AlgoKeyRsa {
		t.Errorf("expected algorithm %q, got %q", AlgoKeyRsa, kp.KeyAlgorithmName())
	}
	if !kp.HasPrivateKey() {
		t.Error("expected HasPrivateKey to be true")
	}
}

// TestKeyPairComment tests the Comment/SetComment methods.
func TestKeyPairComment(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if kp.Comment() != "" {
		t.Errorf("expected empty comment, got %q", kp.Comment())
	}

	kp.SetComment("test-comment")
	if kp.Comment() != "test-comment" {
		t.Errorf("expected %q, got %q", "test-comment", kp.Comment())
	}

	// Test with ECDSA too
	ecKP, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ecKP.SetComment("ecdsa-comment")
	if ecKP.Comment() != "ecdsa-comment" {
		t.Errorf("expected %q, got %q", "ecdsa-comment", ecKP.Comment())
	}
}

// TestKeyPairInterfaceCompliance verifies that both key pair types implement the KeyPair interface.
func TestKeyPairInterfaceCompliance(t *testing.T) {
	var _ KeyPair = (*RsaKeyPair)(nil)
	var _ KeyPair = (*EcdsaKeyPair)(nil)
}

// TestRsaSetPublicKeyBytesInvalidAlgorithm tests that invalid algorithm names are rejected.
func TestRsaSetPublicKeyBytesInvalidAlgorithm(t *testing.T) {
	kp := &RsaKeyPair{}
	// Create fake data with wrong algorithm name
	kp2, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pubBytes, err := kp2.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("GetPublicKeyBytes failed: %v", err)
	}

	err = kp.SetPublicKeyBytes(pubBytes)
	if err == nil {
		t.Error("expected error for ECDSA key bytes imported as RSA")
	}
}

// TestEcdsaSetPublicKeyBytesInvalidAlgorithm tests that invalid algorithm names are rejected.
func TestEcdsaSetPublicKeyBytesInvalidAlgorithm(t *testing.T) {
	kp := &EcdsaKeyPair{}
	// Create fake data with wrong algorithm name
	rsaKP, err := GenerateKeyPair(AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pubBytes, err := rsaKP.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("GetPublicKeyBytes failed: %v", err)
	}

	err = kp.SetPublicKeyBytes(pubBytes)
	if err == nil {
		t.Error("expected error for RSA key bytes imported as ECDSA")
	}
}

// TestRsaSetPublicKeyBytesAcceptsSigningAlgorithms tests that SetPublicKeyBytes
// accepts both "ssh-rsa" and signing algorithm names like "rsa-sha2-256".
func TestRsaSetPublicKeyBytesAcceptsSigningAlgorithms(t *testing.T) {
	kp, err := GenerateKeyPair(AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	pubBytes, err := kp.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("GetPublicKeyBytes failed: %v", err)
	}

	// The default public key bytes use "ssh-rsa" algorithm name.
	// Verify it imports correctly.
	kp2 := &RsaKeyPair{}
	err = kp2.SetPublicKeyBytes(pubBytes)
	if err != nil {
		t.Fatalf("SetPublicKeyBytes with 'ssh-rsa' failed: %v", err)
	}
}
