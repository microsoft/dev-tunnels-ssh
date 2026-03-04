// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"crypto/rand"
	"testing"
)

// BenchmarkEncryptDecrypt benchmarks symmetric encryption and decryption
// for each supported algorithm.

func BenchmarkEncryptDecryptAes256Ctr(b *testing.B) {
	benchmarkEncryptDecrypt(b, NewAes256Ctr())
}

func BenchmarkEncryptDecryptAes256Cbc(b *testing.B) {
	benchmarkEncryptDecrypt(b, NewAes256Cbc())
}

func BenchmarkEncryptDecryptAes256Gcm(b *testing.B) {
	benchmarkEncryptDecryptGcm(b)
}

func benchmarkEncryptDecrypt(b *testing.B, algo *EncryptionAlgorithm) {
	b.Helper()

	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	rand.Read(key)
	rand.Read(iv)

	enc, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		b.Fatalf("create encrypt cipher: %v", err)
	}

	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	dec, err := algo.CreateCipher(false, key, ivCopy)
	if err != nil {
		b.Fatalf("create decrypt cipher: %v", err)
	}

	// 32KB payload (typical SSH max packet size).
	blockLen := enc.BlockLength()
	dataSize := 32 * 1024
	dataSize = (dataSize / blockLen) * blockLen
	if dataSize == 0 {
		dataSize = blockLen
	}

	plaintext := make([]byte, dataSize)
	rand.Read(plaintext)

	b.SetBytes(int64(dataSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, dataSize)
		copy(buf, plaintext)

		if err := enc.Transform(buf); err != nil {
			b.Fatalf("encrypt: %v", err)
		}
		if err := dec.Transform(buf); err != nil {
			b.Fatalf("decrypt: %v", err)
		}
	}
}

// benchmarkEncryptDecryptGcm benchmarks AES-256-GCM which requires special
// handling for the authentication tag transfer between encrypt and decrypt.
func benchmarkEncryptDecryptGcm(b *testing.B) {
	b.Helper()

	algo := NewAes256Gcm()
	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	rand.Read(key)
	rand.Read(iv)

	enc, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		b.Fatalf("create encrypt cipher: %v", err)
	}

	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	dec, err := algo.CreateCipher(false, key, ivCopy)
	if err != nil {
		b.Fatalf("create decrypt cipher: %v", err)
	}

	encGcm := enc.(*AesGcmCipher)
	decGcm := dec.(*AesGcmCipher)

	dataSize := 32 * 1024
	plaintext := make([]byte, dataSize)
	rand.Read(plaintext)

	b.SetBytes(int64(dataSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf := make([]byte, dataSize)
		copy(buf, plaintext)

		// Encrypt.
		if err := encGcm.Transform(buf); err != nil {
			b.Fatalf("encrypt: %v", err)
		}

		// Transfer tag from encryptor to decryptor (GCM requirement).
		tag := encGcm.Sign(nil) // Sign returns the last encryption tag.
		decGcm.SetTag(tag)

		// Decrypt.
		if err := decGcm.Transform(buf); err != nil {
			b.Fatalf("decrypt: %v", err)
		}
	}
}

// BenchmarkKeyExchange benchmarks key exchange operations for each
// supported algorithm.

func BenchmarkKeyExchangeEcdhP256(b *testing.B) {
	benchmarkKeyExchange(b, NewECDHP256SHA256())
}

func BenchmarkKeyExchangeEcdhP384(b *testing.B) {
	benchmarkKeyExchange(b, NewECDHP384SHA384())
}

func BenchmarkKeyExchangeEcdhP521(b *testing.B) {
	benchmarkKeyExchange(b, NewECDHP521SHA512())
}

func BenchmarkKeyExchangeDHGroup14(b *testing.B) {
	benchmarkKeyExchange(b, NewDHGroup14SHA256())
}

func BenchmarkKeyExchangeDHGroup16(b *testing.B) {
	benchmarkKeyExchange(b, NewDHGroup16SHA512())
}

func benchmarkKeyExchange(b *testing.B, algo *KeyExchangeAlgorithm) {
	b.Helper()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		kex1, err := algo.CreateKeyExchange()
		if err != nil {
			b.Fatalf("create kex1: %v", err)
		}

		kex2, err := algo.CreateKeyExchange()
		if err != nil {
			b.Fatalf("create kex2: %v", err)
		}

		pub1, err := kex1.StartKeyExchange()
		if err != nil {
			b.Fatalf("start kex1: %v", err)
		}

		pub2, err := kex2.StartKeyExchange()
		if err != nil {
			b.Fatalf("start kex2: %v", err)
		}

		_, err = kex1.DecryptKeyExchange(pub2)
		if err != nil {
			b.Fatalf("decrypt kex1: %v", err)
		}

		_, err = kex2.DecryptKeyExchange(pub1)
		if err != nil {
			b.Fatalf("decrypt kex2: %v", err)
		}
	}
}
