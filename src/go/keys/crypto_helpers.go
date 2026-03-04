// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash"
)

// pbkdf2Key derives a key using PBKDF2 (RFC 2898 Section 5.2).
func pbkdf2Key(password, salt []byte, iterations, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)

	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(buf, uint32(block))

		prf.Reset()
		prf.Write(salt)
		prf.Write(buf)
		u := prf.Sum(nil)

		result := make([]byte, hashLen)
		copy(result, u)

		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range result {
				result[j] ^= u[j]
			}
		}

		dk = append(dk, result...)
	}

	return dk[:keyLen]
}

// evpBytesToKey derives a key using the EVP_BytesToKey algorithm (MD5-based).
// This is used for PKCS#1 encrypted PEM files (DEK-Info header).
func evpBytesToKey(password, salt []byte, keyLen int) []byte {
	var key []byte
	var prev []byte

	for len(key) < keyLen {
		h := md5.New()
		if prev != nil {
			h.Write(prev)
		}
		h.Write(password)
		h.Write(salt)
		prev = h.Sum(nil)
		key = append(key, prev...)
	}

	return key[:keyLen]
}

// addPkcs7Padding adds PKCS#7 padding to data.
func addPkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// removePkcs7Padding removes PKCS#7 padding from data.
func removePkcs7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

// aesDecryptCBC decrypts data using AES-CBC.
func aesDecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// aesEncryptCBC encrypts data using AES-CBC. Data must be padded before calling.
func aesEncryptCBC(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}
