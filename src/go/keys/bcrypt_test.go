// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"encoding/hex"
	"testing"
)

func TestBcryptPbkdfKnownVector(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt1234567890ab")
	rounds := 16
	keyLen := 48

	result := bcryptPbkdf(password, salt, rounds, keyLen)
	got := hex.EncodeToString(result)
	expected := "0b1cbc9575040af2e1cf0fcbc1446951171cf7614e9855991049265bb1e58fd1775d0099450f9105084f9d5d7c763120"

	if got != expected {
		t.Fatalf("bcryptPbkdf mismatch:\n  got:      %s\n  expected: %s", got, expected)
	}
}

func TestBlowfishKnownVector(t *testing.T) {
	// Standard Blowfish test vector:
	// Key: all zeros (8 bytes)
	// Plaintext: all zeros (8 bytes)
	// Expected Ciphertext: 4EF997456198DD78
	bf := newBlowfish()
	key := make([]byte, 8)
	bf.expandKey(key)

	var l, r uint32
	bf.encrypt(&l, &r)

	got := hex.EncodeToString([]byte{
		byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l),
		byte(r >> 24), byte(r >> 16), byte(r >> 8), byte(r),
	})
	expected := "4ef997456198dd78"

	if got != expected {
		t.Fatalf("Blowfish mismatch: got %s, expected %s", got, expected)
	}
}
