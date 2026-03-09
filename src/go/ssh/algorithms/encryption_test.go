// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"
)

func generateKey(t *testing.T, size int) []byte {
	t.Helper()
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

func generateIV(t *testing.T, size int) []byte {
	t.Helper()
	iv := make([]byte, size)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("failed to generate IV: %v", err)
	}
	return iv
}

func TestAes256CbcEncryptDecrypt(t *testing.T) {
	algo := NewAes256Cbc()
	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())

	// Plaintext must be a multiple of the block size for CBC.
	plaintext := make([]byte, 3*aes.BlockSize)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(plaintext))
	copy(original, plaintext)

	// Encrypt.
	encrypter, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}
	encrypter.Transform(plaintext)

	// Ciphertext should differ from original plaintext.
	if bytes.Equal(plaintext, original) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	// Decrypt with same key and IV.
	decrypter, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatalf("failed to create decrypter: %v", err)
	}
	decrypter.Transform(plaintext)

	// Decrypted data should match original.
	if !bytes.Equal(plaintext, original) {
		t.Fatal("decrypted data should match original plaintext")
	}
}

func TestAes256CbcBlockLength(t *testing.T) {
	algo := NewAes256Cbc()
	if algo.blockLength != aes.BlockSize {
		t.Fatalf("expected block length %d, got %d", aes.BlockSize, algo.blockLength)
	}

	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())
	c, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockLength() != aes.BlockSize {
		t.Fatalf("expected BlockLength() %d, got %d", aes.BlockSize, c.BlockLength())
	}
}

func TestAes256CtrEncryptDecrypt(t *testing.T) {
	algo := NewAes256Ctr()
	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())

	// CTR mode works on any length data.
	plaintext := make([]byte, 100)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(plaintext))
	copy(original, plaintext)

	// Encrypt.
	encrypter, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}
	encrypter.Transform(plaintext)

	// Ciphertext should differ from original plaintext.
	if bytes.Equal(plaintext, original) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	// Decrypt with same key and IV (CTR is symmetric).
	decrypter, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatalf("failed to create decrypter: %v", err)
	}
	decrypter.Transform(plaintext)

	// Decrypted data should match original.
	if !bytes.Equal(plaintext, original) {
		t.Fatal("decrypted data should match original plaintext")
	}
}

func TestAes256CtrStreamCipher(t *testing.T) {
	// CTR mode acts as a stream cipher: encrypt/decrypt can happen in chunks.
	algo := NewAes256Ctr()
	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())

	plaintext := make([]byte, 100)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(plaintext))
	copy(original, plaintext)

	// Encrypt in two chunks.
	encrypter, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	encrypter.Transform(plaintext[:50])
	encrypter.Transform(plaintext[50:])

	// Decrypt in one chunk.
	decrypter, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	decrypter.Transform(plaintext)

	if !bytes.Equal(plaintext, original) {
		t.Fatal("chunked CTR encrypt then full decrypt should recover plaintext")
	}
}

func TestAes256GcmEncryptDecrypt(t *testing.T) {
	algo := NewAes256Gcm()
	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())

	plaintext := make([]byte, 100)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, len(plaintext))
	copy(original, plaintext)

	// Encrypt.
	encCipher, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}
	encCipher.Transform(plaintext)

	// Ciphertext should differ from original plaintext.
	if bytes.Equal(plaintext, original) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	// Get the authentication tag.
	gcmEnc := encCipher.(*AesGcmCipher)
	tag := gcmEnc.Sign(nil)
	if len(tag) != gcmTagSize {
		t.Fatalf("expected tag size %d, got %d", gcmTagSize, len(tag))
	}

	// Decrypt with same key and IV.
	decCipher, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatalf("failed to create decrypter: %v", err)
	}
	gcmDec := decCipher.(*AesGcmCipher)
	gcmDec.SetTag(tag)
	if err = gcmDec.Transform(plaintext); err != nil {
		t.Fatalf("GCM decryption failed: %v", err)
	}

	// Decrypted data should match original.
	if !bytes.Equal(plaintext, original) {
		t.Fatal("decrypted data should match original plaintext")
	}
}

func TestAes256GcmAuthenticationTag(t *testing.T) {
	algo := NewAes256Gcm()
	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())

	plaintext := make([]byte, 64)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	// Encrypt and get tag.
	encCipher, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	encCipher.Transform(plaintext)
	gcmEnc := encCipher.(*AesGcmCipher)
	tag := gcmEnc.Sign(nil)

	// Tamper with ciphertext.
	plaintext[0] ^= 0xFF

	// Decrypt with tampered data should fail with an error.
	decCipher, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	gcmDec := decCipher.(*AesGcmCipher)
	gcmDec.SetTag(tag)
	err = gcmDec.Transform(plaintext)
	if err == nil {
		t.Fatal("GCM decryption with tampered ciphertext should return an error")
	}
}

func TestAes256GcmIsAead(t *testing.T) {
	algo := NewAes256Gcm()
	if !algo.IsAead {
		t.Fatal("AES-256-GCM should be AEAD")
	}

	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())
	c, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	gcm := c.(*AesGcmCipher)
	if !gcm.AuthenticatedEncryption() {
		t.Fatal("GCM cipher should report AuthenticatedEncryption=true")
	}
	if gcm.EncryptThenMac() {
		t.Fatal("GCM cipher should report EncryptThenMac=false")
	}
	if gcm.DigestLength() != gcmTagSize {
		t.Fatalf("expected digest length %d, got %d", gcmTagSize, gcm.DigestLength())
	}
}

func TestAes256GcmNonceIncrement(t *testing.T) {
	// Verify that two consecutive encryptions with the same key produce
	// different ciphertexts (nonce is incremented).
	algo := NewAes256Gcm()
	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())

	data1 := make([]byte, 32)
	data2 := make([]byte, 32)
	// Both start as zeros — same plaintext.

	encCipher, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	encCipher.Transform(data1)
	encCipher.Transform(data2)

	// Different nonces should produce different ciphertexts even for same plaintext.
	if bytes.Equal(data1, data2) {
		t.Fatal("consecutive GCM encryptions should produce different ciphertexts due to nonce increment")
	}
}

// TestAes256GcmBufferReuseVaryingSizes verifies that the GCM cipher correctly
// handles multiple sequential operations with varying payload sizes, which
// forces the internal sealBuf to grow.
func TestAes256GcmBufferReuseVaryingSizes(t *testing.T) {
	algo := NewAes256Gcm()
	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())

	encCipher, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	decCipher, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	gcmEnc := encCipher.(*AesGcmCipher)
	gcmDec := decCipher.(*AesGcmCipher)

	// Varying sizes: small → large (forces sealBuf growth) → small again.
	sizes := []int{16, 100, 1024, 64 * 1024, 100, 16}
	for _, size := range sizes {
		plaintext := make([]byte, size)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		original := make([]byte, size)
		copy(original, plaintext)

		gcmEnc.Transform(plaintext)
		tag := gcmEnc.Sign(nil)

		// Copy tag since Sign returns internal state.
		tagCopy := make([]byte, len(tag))
		copy(tagCopy, tag)

		gcmDec.SetTag(tagCopy)
		if err := gcmDec.Transform(plaintext); err != nil {
			t.Fatalf("decryption failed for size %d: %v", size, err)
		}
		if !bytes.Equal(plaintext, original) {
			t.Fatalf("round-trip failed for size %d", size)
		}
	}
}

// TestAes256GcmSignReturnsInternalState verifies Sign() returns a slice that
// aliases internal cipher state (valid until next Transform call).
func TestAes256GcmSignReturnsInternalState(t *testing.T) {
	algo := NewAes256Gcm()
	key := generateKey(t, algo.KeyLength)
	iv := generateIV(t, algo.IVLength())

	encCipher, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	gcmEnc := encCipher.(*AesGcmCipher)

	data := make([]byte, 64)
	rand.Read(data)
	gcmEnc.Transform(data)

	tag1 := gcmEnc.Sign(nil)
	tag2 := gcmEnc.Sign(nil)

	// Both calls should return the same underlying slice (aliased internal state).
	if &tag1[0] != &tag2[0] {
		t.Fatal("Sign() should return the same internal slice on consecutive calls")
	}

	// Save the tag value before next Transform overwrites it.
	savedTag := make([]byte, len(tag1))
	copy(savedTag, tag1)

	// Next Transform should overwrite the tag.
	rand.Read(data)
	gcmEnc.Transform(data)
	tag3 := gcmEnc.Sign(nil)

	// tag1 and tag3 point to the same buffer, so tag1's content is now tag3's.
	if &tag1[0] != &tag3[0] {
		t.Fatal("Sign() should return the same internal slice across Transform calls")
	}
	// The saved tag should differ from the new tag (different plaintext + nonce).
	if bytes.Equal(savedTag, tag3) {
		t.Fatal("tag should change after encrypting different data")
	}
}

func TestEncryptionAlgorithmNames(t *testing.T) {
	tests := []struct {
		algo     *EncryptionAlgorithm
		name     string
		keyLen   int
		isAead   bool
	}{
		{NewAes256Cbc(), "aes256-cbc", 32, false},
		{NewAes256Ctr(), "aes256-ctr", 32, false},
		{NewAes256Gcm(), "aes256-gcm@openssh.com", 32, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.algo.Name != tt.name {
				t.Errorf("expected name %q, got %q", tt.name, tt.algo.Name)
			}
			if tt.algo.KeyLength != tt.keyLen {
				t.Errorf("expected key length %d, got %d", tt.keyLen, tt.algo.KeyLength)
			}
			if tt.algo.IsAead != tt.isAead {
				t.Errorf("expected IsAead=%v, got %v", tt.isAead, tt.algo.IsAead)
			}
		})
	}
}
