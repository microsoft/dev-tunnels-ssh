// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"
)

// TestAllEncryptionAlgorithmsRoundTrip tests each encryption algorithm
// (aes256-gcm, aes256-ctr, aes256-cbc): create cipher with known key/IV,
// encrypt a 1KB plaintext, decrypt, verify output matches original.
func TestAllEncryptionAlgorithmsRoundTrip(t *testing.T) {
	t.Run("aes256-gcm", func(t *testing.T) {
		algo := NewAes256Gcm()
		key := generateKey(t, algo.KeyLength)
		iv := generateIV(t, algo.IVLength())

		plaintext := make([]byte, 1024)
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

		if bytes.Equal(plaintext, original) {
			t.Fatal("ciphertext should differ from plaintext")
		}

		// Get the authentication tag.
		gcmEnc := encCipher.(*AesGcmCipher)
		tag := gcmEnc.Sign(nil)

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

		if !bytes.Equal(plaintext, original) {
			t.Fatal("decrypted data should match original 1KB plaintext")
		}
	})

	t.Run("aes256-ctr", func(t *testing.T) {
		algo := NewAes256Ctr()
		key := generateKey(t, algo.KeyLength)
		iv := generateIV(t, algo.IVLength())

		plaintext := make([]byte, 1024)
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

		if bytes.Equal(plaintext, original) {
			t.Fatal("ciphertext should differ from plaintext")
		}

		// Decrypt with same key and IV.
		decCipher, err := algo.CreateCipher(false, key, iv)
		if err != nil {
			t.Fatalf("failed to create decrypter: %v", err)
		}
		decCipher.Transform(plaintext)

		if !bytes.Equal(plaintext, original) {
			t.Fatal("decrypted data should match original 1KB plaintext")
		}
	})

	t.Run("aes256-cbc", func(t *testing.T) {
		algo := NewAes256Cbc()
		key := generateKey(t, algo.KeyLength)
		iv := generateIV(t, algo.IVLength())

		// CBC requires plaintext to be a multiple of the block size.
		// 1024 bytes is exactly 64 AES blocks (1024 / 16 = 64).
		plaintext := make([]byte, 1024)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		if len(plaintext)%aes.BlockSize != 0 {
			t.Fatal("plaintext length must be a multiple of block size")
		}
		original := make([]byte, len(plaintext))
		copy(original, plaintext)

		// Encrypt.
		encCipher, err := algo.CreateCipher(true, key, iv)
		if err != nil {
			t.Fatalf("failed to create encrypter: %v", err)
		}
		encCipher.Transform(plaintext)

		if bytes.Equal(plaintext, original) {
			t.Fatal("ciphertext should differ from plaintext")
		}

		// Decrypt with same key and IV.
		decCipher, err := algo.CreateCipher(false, key, iv)
		if err != nil {
			t.Fatalf("failed to create decrypter: %v", err)
		}
		decCipher.Transform(plaintext)

		if !bytes.Equal(plaintext, original) {
			t.Fatal("decrypted data should match original 1KB plaintext")
		}
	})
}
