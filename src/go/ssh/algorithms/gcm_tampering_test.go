// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"crypto/rand"
	"strings"
	"testing"
)

// gcmEncryptHelper encrypts data with AES-256-GCM and returns the ciphertext, tag, key, and IV.
func gcmEncryptHelper(t *testing.T, plaintext []byte) (ciphertext, tag, key, iv []byte) {
	t.Helper()
	algo := NewAes256Gcm()
	key = generateKey(t, algo.KeyLength)
	iv = generateIV(t, algo.IVLength())

	ciphertext = make([]byte, len(plaintext))
	copy(ciphertext, plaintext)

	encCipher, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}
	if err := encCipher.Transform(ciphertext); err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	gcmEnc := encCipher.(*AesGcmCipher)
	tag = gcmEnc.Sign(nil)
	return ciphertext, tag, key, iv
}

func TestGCMDecryptTamperedCiphertext(t *testing.T) {
	plaintext := make([]byte, 64)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ciphertext, tag, key, iv := gcmEncryptHelper(t, plaintext)

	// Tamper with ciphertext.
	ciphertext[0] ^= 0xFF

	// Decrypt should fail.
	algo := NewAes256Gcm()
	decCipher, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	gcmDec := decCipher.(*AesGcmCipher)
	gcmDec.SetTag(tag)

	err = gcmDec.Transform(ciphertext)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext, got nil")
	}
	if !strings.Contains(err.Error(), "gcm authentication failed") {
		t.Fatalf("expected gcm authentication error, got: %v", err)
	}
}

func TestGCMDecryptTamperedTag(t *testing.T) {
	plaintext := make([]byte, 64)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ciphertext, tag, key, iv := gcmEncryptHelper(t, plaintext)

	// Tamper with the authentication tag.
	tag[0] ^= 0xFF

	algo := NewAes256Gcm()
	decCipher, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	gcmDec := decCipher.(*AesGcmCipher)
	gcmDec.SetTag(tag)

	err = gcmDec.Transform(ciphertext)
	if err == nil {
		t.Fatal("expected error for tampered tag, got nil")
	}
	if !strings.Contains(err.Error(), "gcm authentication failed") {
		t.Fatalf("expected gcm authentication error, got: %v", err)
	}
}

func TestGCMDecryptTamperedNonce(t *testing.T) {
	plaintext := make([]byte, 64)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ciphertext, tag, key, _ := gcmEncryptHelper(t, plaintext)

	// Use a different IV (nonce) for decryption.
	wrongIV := generateIV(t, NewAes256Gcm().IVLength())

	algo := NewAes256Gcm()
	decCipher, err := algo.CreateCipher(false, key, wrongIV)
	if err != nil {
		t.Fatal(err)
	}
	gcmDec := decCipher.(*AesGcmCipher)
	gcmDec.SetTag(tag)

	err = gcmDec.Transform(ciphertext)
	if err == nil {
		t.Fatal("expected error for wrong nonce, got nil")
	}
	if !strings.Contains(err.Error(), "gcm authentication failed") {
		t.Fatalf("expected gcm authentication error, got: %v", err)
	}
}

func TestGCMDecryptTamperedAAD(t *testing.T) {
	plaintext := make([]byte, 64)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	ciphertext, tag, key, iv := gcmEncryptHelper(t, plaintext)

	// Decrypt with a different data length (which changes the AAD).
	// The AAD is derived from len(data), so passing a different-length slice
	// will produce a different AAD and fail authentication.
	// We simulate this by creating a longer ciphertext buffer.
	tamperedCiphertext := make([]byte, len(ciphertext)+1)
	copy(tamperedCiphertext, ciphertext)

	algo := NewAes256Gcm()
	decCipher, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	gcmDec := decCipher.(*AesGcmCipher)
	gcmDec.SetTag(tag)

	err = gcmDec.Transform(tamperedCiphertext)
	if err == nil {
		t.Fatal("expected error for tampered AAD (different data length), got nil")
	}
	if !strings.Contains(err.Error(), "gcm authentication failed") {
		t.Fatalf("expected gcm authentication error, got: %v", err)
	}
}
