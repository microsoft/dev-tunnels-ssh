// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// importPkcs1PrivateKey parses an RSA private key from PKCS#1 DER data.
func importPkcs1PrivateKey(der []byte) (ssh.KeyPair, error) {
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
	}

	return ssh.NewRsaKeyPair(key, rsaAlgorithmForKeySize(key.N.BitLen()))
}

// importPkcs1PublicKey parses an RSA public key from PKCS#1 DER data.
func importPkcs1PublicKey(der []byte) (ssh.KeyPair, error) {
	key, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#1 public key: %w", err)
	}

	return ssh.NewRsaKeyPairFromPublicKey(key), nil
}

// decryptPkcs1PEM decrypts a PKCS#1 encrypted PEM block using the DEK-Info header.
func decryptPkcs1PEM(block *pem.Block, passphrase string) ([]byte, error) {
	dekInfo, ok := block.Headers["DEK-Info"]
	if !ok {
		return nil, fmt.Errorf("encrypted PEM missing DEK-Info header")
	}

	parts := strings.SplitN(dekInfo, ",", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid DEK-Info header: %s", dekInfo)
	}

	cipherName := parts[0]
	ivHex := parts[1]

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("invalid IV in DEK-Info: %w", err)
	}

	keySize, err := dekInfoCipherKeySize(cipherName)
	if err != nil {
		return nil, err
	}

	// Derive key using EVP_BytesToKey with first 8 bytes of IV as salt.
	key := evpBytesToKey([]byte(passphrase), iv[:8], keySize)

	// Decrypt with AES-CBC.
	plaintext, err := aesDecryptCBC(key, iv, block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Remove PKCS#7 padding.
	plaintext, err = removePkcs7Padding(plaintext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}

	return plaintext, nil
}

// isEncryptedPEM checks if a PEM block has encryption headers.
func isEncryptedPEM(block *pem.Block) bool {
	_, ok := block.Headers["DEK-Info"]
	return ok
}

// exportPkcs1PublicKey exports an RSA public key in PKCS#1 PEM format.
func exportPkcs1PublicKey(key ssh.KeyPair) ([]byte, error) {
	rsaKey, ok := key.(*ssh.RsaKeyPair)
	if !ok {
		return nil, fmt.Errorf("pkcs#1 format only supports RSA keys")
	}

	pubKey := rsaKey.PublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("public key not available")
	}

	der := x509.MarshalPKCS1PublicKey(pubKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}), nil
}

// exportPkcs1PrivateKey exports an RSA private key in PKCS#1 PEM format (unencrypted).
func exportPkcs1PrivateKey(key ssh.KeyPair) ([]byte, error) {
	rsaKey, ok := key.(*ssh.RsaKeyPair)
	if !ok {
		return nil, fmt.Errorf("pkcs#1 format only supports RSA keys")
	}

	privKey := rsaKey.PrivateKey()
	if privKey == nil {
		return nil, fmt.Errorf("private key not available")
	}

	der := x509.MarshalPKCS1PrivateKey(privKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}), nil
}

// dekInfoCipherKeySize returns the key size for a DEK-Info cipher name.
func dekInfoCipherKeySize(cipherName string) (int, error) {
	switch cipherName {
	case "AES-128-CBC":
		return 16, nil
	case "AES-192-CBC":
		return 24, nil
	case "AES-256-CBC":
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported DEK-Info cipher: %s", cipherName)
	}
}

// rsaAlgorithmForKeySize returns the SSH algorithm name based on RSA key size.
func rsaAlgorithmForKeySize(bits int) string {
	if bits >= 4096 {
		return ssh.AlgoPKRsaSha512
	}
	return ssh.AlgoPKRsaSha256
}

// rsaPublicKeyFromKeyPair extracts the *rsa.PublicKey from a KeyPair.
func rsaPublicKeyFromKeyPair(key ssh.KeyPair) *rsa.PublicKey {
	if rsaKey, ok := key.(*ssh.RsaKeyPair); ok {
		return rsaKey.PublicKey()
	}
	return nil
}
