// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// ASN.1 OIDs for PKCS#8 encrypted keys.
var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// DefaultPbkdf2Iterations is the recommended number of PBKDF2 iterations for key encryption.
const DefaultPbkdf2Iterations = 100000

// Pbkdf2Iterations controls the number of PBKDF2 iterations used when encrypting keys.
// Defaults to DefaultPbkdf2Iterations. This should only be changed in tests —
// modifying it affects all subsequent key encryption operations in the process.
var Pbkdf2Iterations = DefaultPbkdf2Iterations

// importPkcs8PrivateKey parses a private key from PKCS#8 DER data.
func importPkcs8PrivateKey(der []byte) (ssh.KeyPair, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	return keyPairFromCryptoKey(key)
}

// importPkcs8PublicKey parses a public key from PKCS#8 (PKIX/SubjectPublicKeyInfo) DER data.
func importPkcs8PublicKey(der []byte) (ssh.KeyPair, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 public key: %w", err)
	}

	return keyPairFromCryptoKey(key)
}

// keyPairFromCryptoKey converts a Go crypto key to an ssh.KeyPair.
func keyPairFromCryptoKey(key interface{}) (ssh.KeyPair, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return ssh.NewRsaKeyPair(k, rsaAlgorithmForKeySize(k.N.BitLen()))
	case *rsa.PublicKey:
		return ssh.NewRsaKeyPairFromPublicKey(k), nil
	case *ecdsa.PrivateKey:
		return ssh.NewEcdsaKeyPair(k)
	case *ecdsa.PublicKey:
		return ssh.NewEcdsaKeyPairFromPublicKey(k)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// decryptPkcs8 decrypts an encrypted PKCS#8 (PBES2) DER structure and returns the
// decrypted PKCS#8 PrivateKeyInfo DER data.
func decryptPkcs8(data []byte, passphrase string) ([]byte, error) {
	// Parse the EncryptedPrivateKeyInfo outer structure.
	var outer struct {
		Algo struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		EncryptedData []byte
	}
	if _, err := asn1.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("failed to parse encrypted PKCS#8: %w", err)
	}

	if !outer.Algo.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported encryption algorithm: %v", outer.Algo.Algorithm)
	}

	// Parse PBES2 params (KDF + encryption scheme).
	var pbes2 struct {
		KDF struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		Encryption struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
	}
	if _, err := asn1.Unmarshal(outer.Algo.Parameters.FullBytes, &pbes2); err != nil {
		return nil, fmt.Errorf("failed to parse PBES2 params: %w", err)
	}

	if !pbes2.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("unsupported KDF: %v", pbes2.KDF.Algorithm)
	}

	// Parse PBKDF2 params.
	salt, iterations, hashFunc, err := parsePBKDF2Params(pbes2.KDF.Parameters.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PBKDF2 params: %w", err)
	}

	// Get cipher key size.
	keySize, err := pkcs8CipherKeySize(pbes2.Encryption.Algorithm)
	if err != nil {
		return nil, err
	}

	// Parse IV.
	var iv []byte
	if _, err := asn1.Unmarshal(pbes2.Encryption.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("failed to parse IV: %w", err)
	}

	// Derive key using PBKDF2.
	derivedKey := pbkdf2Key([]byte(passphrase), salt, iterations, keySize, hashFunc)

	// Decrypt with AES-CBC.
	plaintext, err := aesDecryptCBC(derivedKey, iv, outer.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Remove padding.
	plaintext, err = removePkcs7Padding(plaintext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}

	// Verify by checking DER SEQUENCE tag.
	if len(plaintext) == 0 || plaintext[0] != 0x30 {
		return nil, fmt.Errorf("decryption failed: wrong passphrase")
	}

	return plaintext, nil
}

// parsePBKDF2Params parses PBKDF2 parameters from a DER-encoded SEQUENCE.
func parsePBKDF2Params(data []byte) (salt []byte, iterations int, hashFunc func() hash.Hash, err error) {
	// Parse the outer SEQUENCE wrapper.
	var seq asn1.RawValue
	if _, err = asn1.Unmarshal(data, &seq); err != nil {
		return
	}

	rest := seq.Bytes

	// Parse salt (OCTET STRING).
	rest, err = asn1.Unmarshal(rest, &salt)
	if err != nil {
		return
	}

	// Parse iterations (INTEGER).
	rest, err = asn1.Unmarshal(rest, &iterations)
	if err != nil {
		return
	}

	// Default to HMAC-SHA1 per RFC 8018 Section 5.2 when no PRF is specified.
	hashFunc = sha1New

	// Parse optional remaining fields (keyLength, PRF).
	for len(rest) > 0 {
		var elem asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &elem)
		if err != nil {
			break
		}
		// A SEQUENCE element is the PRF algorithm identifier.
		if elem.Tag == asn1.TagSequence && elem.Class == asn1.ClassUniversal {
			var oid asn1.ObjectIdentifier
			if _, err2 := asn1.Unmarshal(elem.Bytes, &oid); err2 == nil {
				if oid.Equal(oidHMACSHA256) {
					hashFunc = sha256.New
				}
				// HMAC-SHA1 is the default per RFC 8018, no change needed.
			}
		}
		// INTEGER would be keyLength — skip it.
	}

	err = nil
	return
}

// encryptPkcs8 encrypts PKCS#8 DER data using PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC.
func encryptPkcs8(der []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	iterations := Pbkdf2Iterations
	keySize := 32 // AES-256
	derivedKey := pbkdf2Key([]byte(passphrase), salt, iterations, keySize, sha256.New)

	padded := addPkcs7Padding(der, aes.BlockSize)
	ciphertext, err := aesEncryptCBC(derivedKey, iv, padded)
	if err != nil {
		return nil, err
	}

	return buildEncryptedPkcs8ASN1(ciphertext, salt, iv, iterations)
}

// buildEncryptedPkcs8ASN1 builds the ASN.1 DER encoding for an EncryptedPrivateKeyInfo.
func buildEncryptedPkcs8ASN1(ciphertext, salt, iv []byte, iterations int) ([]byte, error) {
	// HMAC-SHA256 algorithm identifier: SEQUENCE { OID, NULL }
	hmacAlgID, err := asn1.Marshal(struct {
		Algo   asn1.ObjectIdentifier
		Params asn1.RawValue
	}{oidHMACSHA256, asn1.NullRawValue})
	if err != nil {
		return nil, err
	}

	// PBKDF2 params: SEQUENCE { salt, iterations, PRF }
	pbkdf2Params, err := asn1.Marshal(struct {
		Salt       []byte
		Iterations int
		PRF        asn1.RawValue
	}{salt, iterations, asn1.RawValue{FullBytes: hmacAlgID}})
	if err != nil {
		return nil, err
	}

	// PBKDF2 algorithm identifier: SEQUENCE { OID, params }
	kdfAlgID, err := asn1.Marshal(struct {
		Algo   asn1.ObjectIdentifier
		Params asn1.RawValue
	}{oidPBKDF2, asn1.RawValue{FullBytes: pbkdf2Params}})
	if err != nil {
		return nil, err
	}

	// IV as OCTET STRING
	ivASN1, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}

	// AES-256-CBC algorithm identifier: SEQUENCE { OID, IV }
	encAlgID, err := asn1.Marshal(struct {
		Algo   asn1.ObjectIdentifier
		Params asn1.RawValue
	}{oidAES256CBC, asn1.RawValue{FullBytes: ivASN1}})
	if err != nil {
		return nil, err
	}

	// PBES2 params: SEQUENCE { KDF, encryption }
	pbes2Params, err := asn1.Marshal(struct {
		KDF        asn1.RawValue
		Encryption asn1.RawValue
	}{asn1.RawValue{FullBytes: kdfAlgID}, asn1.RawValue{FullBytes: encAlgID}})
	if err != nil {
		return nil, err
	}

	// PBES2 algorithm identifier: SEQUENCE { OID, params }
	pbes2AlgID, err := asn1.Marshal(struct {
		Algo   asn1.ObjectIdentifier
		Params asn1.RawValue
	}{oidPBES2, asn1.RawValue{FullBytes: pbes2Params}})
	if err != nil {
		return nil, err
	}

	// EncryptedPrivateKeyInfo: SEQUENCE { algorithm, encryptedData }
	return asn1.Marshal(struct {
		Algo asn1.RawValue
		Data []byte
	}{asn1.RawValue{FullBytes: pbes2AlgID}, ciphertext})
}

// exportPkcs8PublicKey exports a public key in PKCS#8 (SubjectPublicKeyInfo) PEM format.
func exportPkcs8PublicKey(key ssh.KeyPair) ([]byte, error) {
	cryptoKey, err := cryptoPublicKeyFromKeyPair(key)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKIXPublicKey(cryptoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKCS#8 public key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// exportPkcs8PrivateKey exports a private key in PKCS#8 PEM format, optionally encrypted.
func exportPkcs8PrivateKey(key ssh.KeyPair, passphrase string) ([]byte, error) {
	cryptoKey, err := cryptoPrivateKeyFromKeyPair(key)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(cryptoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKCS#8 private key: %w", err)
	}

	if passphrase != "" {
		encryptedDER, err := encryptPkcs8(der, passphrase)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: encryptedDER,
		}), nil
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// cryptoPublicKeyFromKeyPair extracts the Go crypto public key from a KeyPair.
func cryptoPublicKeyFromKeyPair(key ssh.KeyPair) (interface{}, error) {
	switch k := key.(type) {
	case *ssh.RsaKeyPair:
		if k.PublicKey() == nil {
			return nil, fmt.Errorf("public key not available")
		}
		return k.PublicKey(), nil
	case *ssh.EcdsaKeyPair:
		if k.PublicKey() == nil {
			return nil, fmt.Errorf("public key not available")
		}
		return k.PublicKey(), nil
	default:
		return nil, fmt.Errorf("unsupported key pair type: %T", key)
	}
}

// cryptoPrivateKeyFromKeyPair extracts the Go crypto private key from a KeyPair.
func cryptoPrivateKeyFromKeyPair(key ssh.KeyPair) (interface{}, error) {
	switch k := key.(type) {
	case *ssh.RsaKeyPair:
		if k.PrivateKey() == nil {
			return nil, fmt.Errorf("private key not available")
		}
		return k.PrivateKey(), nil
	case *ssh.EcdsaKeyPair:
		if k.PrivateKey() == nil {
			return nil, fmt.Errorf("private key not available")
		}
		return k.PrivateKey(), nil
	default:
		return nil, fmt.Errorf("unsupported key pair type: %T", key)
	}
}

// pkcs8CipherKeySize returns the AES key size for a given encryption scheme OID.
func pkcs8CipherKeySize(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(oidAES128CBC):
		return 16, nil
	case oid.Equal(oidAES192CBC):
		return 24, nil
	case oid.Equal(oidAES256CBC):
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported encryption scheme: %v", oid)
	}
}

// sha1New returns a new SHA-1 hash. Used for HMAC-SHA1 in PBKDF2 when specified.
func sha1New() hash.Hash {
	return sha1.New()
}
