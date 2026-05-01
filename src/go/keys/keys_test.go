// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// testDataDir returns the path to the test data directory.
func testDataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "test", "data")
}

// readTestFile reads a test data file.
func readTestFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testDataDir(), name))
	if err != nil {
		t.Fatalf("Failed to read test file %s: %v", name, err)
	}
	return data
}

// assertPublicKeyBytesEqual verifies two key pairs have the same public key bytes.
func assertPublicKeyBytesEqual(t *testing.T, expected, actual ssh.KeyPair) {
	t.Helper()
	expectedBytes, err := expected.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("Failed to get expected public key bytes: %v", err)
	}
	actualBytes, err := actual.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("Failed to get actual public key bytes: %v", err)
	}
	if !bytes.Equal(expectedBytes, actualBytes) {
		t.Fatalf("Public key bytes do not match")
	}
}

// --- SSH Public Key Format Tests ---

func TestImportSSHPublicKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-ssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoKeyRsa {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoKeyRsa, key.KeyAlgorithmName())
	}
	if key.HasPrivateKey() {
		t.Fatal("Expected public-key-only")
	}
	if key.Comment() != "comment" {
		t.Fatalf("Expected comment 'comment', got %q", key.Comment())
	}
}

func TestImportSSHPublicKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-public-ecdsa384-ssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P384 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P384, key.KeyAlgorithmName())
	}
	if key.HasPrivateKey() {
		t.Fatal("Expected public-key-only")
	}
}

func TestImportSSHPublicKeyEcdsa521(t *testing.T) {
	data := readTestFile(t, "testkey-public-ecdsa521-ssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P521 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P521, key.KeyAlgorithmName())
	}
}

func TestExportSSHPublicKeyRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-ssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPublicKey(key, KeyFormatSSH)
	if err != nil {
		t.Fatalf("ExportPublicKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
}

func TestExportSSHPublicKeyEcdsaRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-public-ecdsa384-ssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPublicKey(key, KeyFormatSSH)
	if err != nil {
		t.Fatalf("ExportPublicKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
}

// --- PKCS#1 Format Tests ---

func TestImportPkcs1PrivateKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoKeyRsa {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoKeyRsa, key.KeyAlgorithmName())
	}
	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportPkcs1PrivateKeyRsa4096(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa4096-pkcs1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportPkcs1PublicKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-pkcs1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.HasPrivateKey() {
		t.Fatal("Expected public-key-only")
	}
}

func TestImportPkcs1EncryptedPrivateKey(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs1-pw.txt")
	key, err := ImportKey(data, "password")
	if err != nil {
		t.Fatalf("ImportKey with password failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}

	// Verify same public key as unencrypted version.
	unencData := readTestFile(t, "testkey-private-rsa2048-pkcs1.txt")
	unencKey, err := ImportKey(unencData, "")
	if err != nil {
		t.Fatalf("ImportKey unencrypted failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, unencKey, key)
}

func TestImportPkcs1EncryptedWrongPassword(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs1-pw.txt")
	_, err := ImportKey(data, "wrong")
	if err == nil {
		t.Fatal("Expected error for wrong passphrase")
	}
}

func TestImportPkcs1EncryptedNoPassword(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs1-pw.txt")
	_, err := ImportKey(data, "")
	if err == nil {
		t.Fatal("Expected error for missing passphrase")
	}
}

func TestExportPkcs1RoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatPkcs1, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

func TestExportPkcs1PublicKeyRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-pkcs1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPublicKey(key, KeyFormatPkcs1)
	if err != nil {
		t.Fatalf("ExportPublicKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
}

// --- PKCS#8 Format Tests ---

func TestImportPkcs8PrivateKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportPkcs8PrivateKeyRsa4096(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa4096-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportPkcs8PublicKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.HasPrivateKey() {
		t.Fatal("Expected public-key-only")
	}
}

func TestImportPkcs8PrivateKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P384 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P384, key.KeyAlgorithmName())
	}
	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportPkcs8PrivateKeyEcdsa521(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa521-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P521 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P521, key.KeyAlgorithmName())
	}
}

func TestImportPkcs8PublicKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-public-ecdsa384-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P384 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P384, key.KeyAlgorithmName())
	}
	if key.HasPrivateKey() {
		t.Fatal("Expected public-key-only")
	}
}

func TestImportPkcs8PublicKeyEcdsa521(t *testing.T) {
	data := readTestFile(t, "testkey-public-ecdsa521-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P521 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P521, key.KeyAlgorithmName())
	}
}

func TestImportPkcs8EncryptedPrivateKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs8-pw.txt")
	key, err := ImportKey(data, "password")
	if err != nil {
		t.Fatalf("ImportKey with password failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}

	// Verify same public key as unencrypted version.
	unencData := readTestFile(t, "testkey-private-rsa2048-pkcs8.txt")
	unencKey, err := ImportKey(unencData, "")
	if err != nil {
		t.Fatalf("ImportKey unencrypted failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, unencKey, key)
}

func TestImportPkcs8EncryptedPrivateKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-pkcs8-pw.txt")
	key, err := ImportKey(data, "password")
	if err != nil {
		t.Fatalf("ImportKey with password failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}

	// Verify same public key as unencrypted version.
	unencData := readTestFile(t, "testkey-private-ecdsa384-pkcs8.txt")
	unencKey, err := ImportKey(unencData, "")
	if err != nil {
		t.Fatalf("ImportKey unencrypted failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, unencKey, key)
}

func TestImportPkcs8EncryptedWrongPassword(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs8-pw.txt")
	_, err := ImportKey(data, "wrong")
	if err == nil {
		t.Fatal("Expected error for wrong passphrase")
	}
}

func TestImportPkcs8EncryptedNoPassword(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs8-pw.txt")
	_, err := ImportKey(data, "")
	if err == nil {
		t.Fatal("Expected error for missing passphrase")
	}
}

func TestExportPkcs8PrivateKeyRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatPkcs8, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

func TestExportPkcs8PublicKeyRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPublicKey(key, KeyFormatPkcs8)
	if err != nil {
		t.Fatalf("ExportPublicKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
}

func TestExportPkcs8EcdsaRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatPkcs8, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

func TestExportPkcs8EncryptedRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	// Use fewer iterations for test speed.
	origIterations := Pbkdf2Iterations
	Pbkdf2Iterations = 1000
	defer func() { Pbkdf2Iterations = origIterations }()

	exported, err := ExportPrivateKey(key, KeyFormatPkcs8, "testpass")
	if err != nil {
		t.Fatalf("ExportPrivateKey with passphrase failed: %v", err)
	}

	reimported, err := ImportKey(exported, "testpass")
	if err != nil {
		t.Fatalf("Re-import with passphrase failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}

	// Wrong passphrase should fail.
	_, err = ImportKey(exported, "wrongpass")
	if err == nil {
		t.Fatal("Expected error for wrong passphrase on re-import")
	}
}

func TestExportPkcs8EcdsaEncryptedRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	origIterations := Pbkdf2Iterations
	Pbkdf2Iterations = 1000
	defer func() { Pbkdf2Iterations = origIterations }()

	exported, err := ExportPrivateKey(key, KeyFormatPkcs8, "ecpass")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "ecpass")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
}

// --- Cross-format tests ---

func TestPkcs1AndPkcs8ProduceSamePublicKey(t *testing.T) {
	pkcs1Data := readTestFile(t, "testkey-private-rsa2048-pkcs1.txt")
	pkcs1Key, err := ImportKey(pkcs1Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#1 failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-private-rsa2048-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, pkcs1Key, pkcs8Key)
}

func TestSSHAndPkcs8ProduceSamePublicKey(t *testing.T) {
	sshData := readTestFile(t, "testkey-public-rsa2048-ssh.txt")
	sshKey, err := ImportKey(sshData, "")
	if err != nil {
		t.Fatalf("ImportKey SSH failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-public-rsa2048-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, sshKey, pkcs8Key)
}

func TestSSHAndPkcs8EcdsaProduceSamePublicKey(t *testing.T) {
	sshData := readTestFile(t, "testkey-public-ecdsa384-ssh.txt")
	sshKey, err := ImportKey(sshData, "")
	if err != nil {
		t.Fatalf("ImportKey SSH failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-public-ecdsa384-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, sshKey, pkcs8Key)
}

func TestImportRsa4096SSHAndPkcs8Match(t *testing.T) {
	sshData := readTestFile(t, "testkey-public-rsa4096-ssh.txt")
	sshKey, err := ImportKey(sshData, "")
	if err != nil {
		t.Fatalf("ImportKey SSH failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-private-rsa4096-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, sshKey, pkcs8Key)
}

// --- PBKDF2 unit test ---

func TestPbkdf2KnownVector(t *testing.T) {
	// Verify PBKDF2 produces deterministic output.
	result1 := pbkdf2Key([]byte("password"), []byte("salt"), 1, 32, sha256.New)
	result2 := pbkdf2Key([]byte("password"), []byte("salt"), 1, 32, sha256.New)
	if !bytes.Equal(result1, result2) {
		t.Fatal("PBKDF2 not deterministic")
	}
	if len(result1) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(result1))
	}

	// Different passwords should produce different results.
	result3 := pbkdf2Key([]byte("other"), []byte("salt"), 1, 32, sha256.New)
	if bytes.Equal(result1, result3) {
		t.Fatal("Different passwords produced same PBKDF2 output")
	}
}

func TestImportExportWithFormat(t *testing.T) {
	// Test ImportKeyWithFormat
	data := readTestFile(t, "testkey-private-rsa2048-pkcs8.txt")
	key, err := ImportKeyWithFormat(data, KeyFormatPkcs8, "")
	if err != nil {
		t.Fatalf("ImportKeyWithFormat failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestExportPublicKeyDefaultFormat(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-ssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	// Default format for public key should be SSH.
	exported, err := ExportPublicKey(key, KeyFormatDefault)
	if err != nil {
		t.Fatalf("ExportPublicKey failed: %v", err)
	}

	// Should be importable as SSH format.
	if !isSSHPublicKeyFormat(exported) {
		t.Fatal("Default public key export should be SSH format")
	}
}

func TestExportPrivateKeyDefaultFormat(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	// Default format for private key should be PKCS#8.
	exported, err := ExportPrivateKey(key, KeyFormatDefault, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	// Should be importable back.
	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
}

func TestExportPrivateKeyNoPrivateKeyError(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-ssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	_, err = ExportPrivateKey(key, KeyFormatPkcs8, "")
	if err == nil {
		t.Fatal("Expected error when exporting private key from public-key-only pair")
	}
}

func TestPkcs1EncryptedExportNotSupported(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	_, err = ExportPrivateKey(key, KeyFormatPkcs1, "password")
	if err == nil {
		t.Fatal("Expected error for encrypted PKCS#1 export")
	}
}

// --- SEC1 Format Tests ---

func TestImportSec1PrivateKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-sec1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P384 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P384, key.KeyAlgorithmName())
	}
	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportSec1PrivateKeyEcdsa521(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa521-sec1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P521 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P521, key.KeyAlgorithmName())
	}
	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportSec1EncryptedPrivateKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-sec1-pw.txt")
	key, err := ImportKey(data, "password")
	if err != nil {
		t.Fatalf("ImportKey with password failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}

	// Verify same public key as unencrypted version.
	unencData := readTestFile(t, "testkey-private-ecdsa384-sec1.txt")
	unencKey, err := ImportKey(unencData, "")
	if err != nil {
		t.Fatalf("ImportKey unencrypted failed: %v", err)
	}
	assertPublicKeyBytesEqual(t, unencKey, key)
}

func TestImportSec1EncryptedNoPassword(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-sec1-pw.txt")
	_, err := ImportKey(data, "")
	if err == nil {
		t.Fatal("Expected error for missing passphrase")
	}
}

func TestExportSec1RoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-sec1.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatSec1, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

func TestSec1AndPkcs8ProduceSamePublicKey(t *testing.T) {
	sec1Data := readTestFile(t, "testkey-private-ecdsa384-sec1.txt")
	sec1Key, err := ImportKey(sec1Data, "")
	if err != nil {
		t.Fatalf("ImportKey SEC1 failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-private-ecdsa384-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, sec1Key, pkcs8Key)
}

// --- OpenSSH Format Tests ---

func TestImportOpenSSHPrivateKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-openssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoKeyRsa {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoKeyRsa, key.KeyAlgorithmName())
	}
	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
	if key.Comment() != "comment" {
		t.Fatalf("Expected comment 'comment', got %q", key.Comment())
	}
}

func TestImportOpenSSHPrivateKeyRsa4096(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa4096-openssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportOpenSSHPrivateKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-openssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P384 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P384, key.KeyAlgorithmName())
	}
	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportOpenSSHEncryptedPrivateKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-openssh-pw.txt")
	key, err := ImportKey(data, "password")
	if err != nil {
		t.Fatalf("ImportKey with password failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}

	// Verify same public key as unencrypted version.
	unencData := readTestFile(t, "testkey-private-rsa2048-openssh.txt")
	unencKey, err := ImportKey(unencData, "")
	if err != nil {
		t.Fatalf("ImportKey unencrypted failed: %v", err)
	}
	assertPublicKeyBytesEqual(t, unencKey, key)
}

func TestImportOpenSSHEncryptedPrivateKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-openssh-pw.txt")
	key, err := ImportKey(data, "password")
	if err != nil {
		t.Fatalf("ImportKey with password failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}

	// Verify same public key as unencrypted version.
	unencData := readTestFile(t, "testkey-private-ecdsa384-openssh.txt")
	unencKey, err := ImportKey(unencData, "")
	if err != nil {
		t.Fatalf("ImportKey unencrypted failed: %v", err)
	}
	assertPublicKeyBytesEqual(t, unencKey, key)
}

func TestImportOpenSSHEncryptedNoPassword(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-openssh-pw.txt")
	_, err := ImportKey(data, "")
	if err == nil {
		t.Fatal("Expected error for missing passphrase")
	}
}

func TestExportOpenSSHRsaRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-openssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatOpenSSH, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

func TestExportOpenSSHEcdsaRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-openssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatOpenSSH, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

func TestExportOpenSSHEncryptedRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-openssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatOpenSSH, "testpass")
	if err != nil {
		t.Fatalf("ExportPrivateKey with passphrase failed: %v", err)
	}

	reimported, err := ImportKey(exported, "testpass")
	if err != nil {
		t.Fatalf("Re-import with passphrase failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}

	// Wrong passphrase should fail.
	_, err = ImportKey(exported, "wrongpass")
	if err == nil {
		t.Fatal("Expected error for wrong passphrase on re-import")
	}
}

func TestOpenSSHAndPkcs8ProduceSamePublicKey(t *testing.T) {
	opensshData := readTestFile(t, "testkey-private-rsa2048-openssh.txt")
	opensshKey, err := ImportKey(opensshData, "")
	if err != nil {
		t.Fatalf("ImportKey OpenSSH failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-private-rsa2048-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, opensshKey, pkcs8Key)
}

// --- SSH2 Format Tests ---

func TestImportSSH2PublicKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-ssh2.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoKeyRsa {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoKeyRsa, key.KeyAlgorithmName())
	}
	if key.HasPrivateKey() {
		t.Fatal("Expected public-key-only")
	}
	if key.Comment() != "comment" {
		t.Fatalf("Expected comment 'comment', got %q", key.Comment())
	}
}

func TestImportSSH2PrivateKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-ssh2.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportSSH2EncryptedPrivateKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-ssh2-pw.txt")
	key, err := ImportKey(data, "password")
	if err != nil {
		t.Fatalf("ImportKey with password failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}

	// Verify same public key as unencrypted version.
	unencData := readTestFile(t, "testkey-private-rsa2048-ssh2.txt")
	unencKey, err := ImportKey(unencData, "")
	if err != nil {
		t.Fatalf("ImportKey unencrypted failed: %v", err)
	}
	assertPublicKeyBytesEqual(t, unencKey, key)
}

func TestImportSSH2EncryptedNoPassword(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-ssh2-pw.txt")
	_, err := ImportKey(data, "")
	if err == nil {
		t.Fatal("Expected error for missing passphrase")
	}
}

func TestSSH2AndPkcs8ProduceSamePublicKey(t *testing.T) {
	ssh2Data := readTestFile(t, "testkey-public-rsa2048-ssh2.txt")
	ssh2Key, err := ImportKey(ssh2Data, "")
	if err != nil {
		t.Fatalf("ImportKey SSH2 failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-public-rsa2048-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, ssh2Key, pkcs8Key)
}

func TestExportSSH2PublicKeyRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-ssh2.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPublicKey(key, KeyFormatSSH2)
	if err != nil {
		t.Fatalf("ExportPublicKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
}

func TestExportSSH2PrivateKeyRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-ssh2.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatSSH2, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

// --- JWK Format Tests ---

func TestImportJwkPrivateKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-jwk.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoKeyRsa {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoKeyRsa, key.KeyAlgorithmName())
	}
	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
	if key.Comment() != "comment" {
		t.Fatalf("Expected comment 'comment', got %q", key.Comment())
	}
}

func TestImportJwkPublicKeyRsa2048(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-jwk.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoKeyRsa {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoKeyRsa, key.KeyAlgorithmName())
	}
	if key.HasPrivateKey() {
		t.Fatal("Expected public-key-only")
	}
}

func TestImportJwkPrivateKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-jwk.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P384 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P384, key.KeyAlgorithmName())
	}
	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportJwkPublicKeyEcdsa384(t *testing.T) {
	data := readTestFile(t, "testkey-public-ecdsa384-jwk.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P384 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P384, key.KeyAlgorithmName())
	}
	if key.HasPrivateKey() {
		t.Fatal("Expected public-key-only")
	}
}

func TestJwkAndPkcs8RsaProduceSamePublicKey(t *testing.T) {
	jwkData := readTestFile(t, "testkey-private-rsa2048-jwk.txt")
	jwkKey, err := ImportKey(jwkData, "")
	if err != nil {
		t.Fatalf("ImportKey JWK failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-private-rsa2048-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, jwkKey, pkcs8Key)
}

func TestJwkAndPkcs8EcdsaProduceSamePublicKey(t *testing.T) {
	jwkData := readTestFile(t, "testkey-private-ecdsa384-jwk.txt")
	jwkKey, err := ImportKey(jwkData, "")
	if err != nil {
		t.Fatalf("ImportKey JWK failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-private-ecdsa384-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, jwkKey, pkcs8Key)
}

func TestExportJwkRsaRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-jwk.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatJwk, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

func TestExportJwkEcdsaRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-jwk.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPrivateKey(key, KeyFormatJwk, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

func TestExportJwkPublicKeyRoundTrip(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-jwk.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	exported, err := ExportPublicKey(key, KeyFormatJwk)
	if err != nil {
		t.Fatalf("ExportPublicKey failed: %v", err)
	}

	reimported, err := ImportKey(exported, "")
	if err != nil {
		t.Fatalf("Re-import failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
}

// --- File-based Import/Export Tests ---

func TestImportExportKeyFile(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-pkcs8.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	// Export to temp file.
	tmpFile := t.TempDir() + "/test-key.pem"
	err = ExportPrivateKeyFile(key, tmpFile, KeyFormatPkcs8, "")
	if err != nil {
		t.Fatalf("ExportPrivateKeyFile failed: %v", err)
	}

	// Import from file.
	reimported, err := ImportKeyFile(tmpFile, "")
	if err != nil {
		t.Fatalf("ImportKeyFile failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
	if !reimported.HasPrivateKey() {
		t.Fatal("Re-imported key should have private key")
	}
}

func TestExportPublicKeyFile(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-ssh.txt")
	key, err := ImportKey(data, "")
	if err != nil {
		t.Fatalf("ImportKey failed: %v", err)
	}

	tmpFile := t.TempDir() + "/test-key.pub"
	err = ExportPublicKeyFile(key, tmpFile, KeyFormatSSH)
	if err != nil {
		t.Fatalf("ExportPublicKeyFile failed: %v", err)
	}

	reimported, err := ImportKeyFile(tmpFile, "")
	if err != nil {
		t.Fatalf("ImportKeyFile failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, key, reimported)
}

// --- ImportKeyWithFormat Tests for New Formats ---

func TestImportKeyWithFormatSec1(t *testing.T) {
	data := readTestFile(t, "testkey-private-ecdsa384-sec1.txt")
	key, err := ImportKeyWithFormat(data, KeyFormatSec1, "")
	if err != nil {
		t.Fatalf("ImportKeyWithFormat SEC1 failed: %v", err)
	}

	if key.KeyAlgorithmName() != ssh.AlgoPKEcdsaSha2P384 {
		t.Fatalf("Expected algorithm %s, got %s", ssh.AlgoPKEcdsaSha2P384, key.KeyAlgorithmName())
	}
}

func TestImportKeyWithFormatOpenSSH(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-openssh.txt")
	key, err := ImportKeyWithFormat(data, KeyFormatOpenSSH, "")
	if err != nil {
		t.Fatalf("ImportKeyWithFormat OpenSSH failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

func TestImportKeyWithFormatSSH2(t *testing.T) {
	data := readTestFile(t, "testkey-public-rsa2048-ssh2.txt")
	key, err := ImportKeyWithFormat(data, KeyFormatSSH2, "")
	if err != nil {
		t.Fatalf("ImportKeyWithFormat SSH2 failed: %v", err)
	}

	if key.HasPrivateKey() {
		t.Fatal("Expected public-key-only")
	}
}

func TestImportKeyWithFormatJwk(t *testing.T) {
	data := readTestFile(t, "testkey-private-rsa2048-jwk.txt")
	key, err := ImportKeyWithFormat(data, KeyFormatJwk, "")
	if err != nil {
		t.Fatalf("ImportKeyWithFormat JWK failed: %v", err)
	}

	if !key.HasPrivateKey() {
		t.Fatal("Expected private key")
	}
}

// --- RSA 4096 Tests for Additional Formats ---

func TestImportRsa4096OpenSSHAndPkcs8Match(t *testing.T) {
	opensshData := readTestFile(t, "testkey-private-rsa4096-openssh.txt")
	opensshKey, err := ImportKey(opensshData, "")
	if err != nil {
		t.Fatalf("ImportKey OpenSSH failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-private-rsa4096-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, opensshKey, pkcs8Key)
}

func TestImportRsa4096SSH2AndPkcs8Match(t *testing.T) {
	ssh2Data := readTestFile(t, "testkey-private-rsa4096-ssh2.txt")
	ssh2Key, err := ImportKey(ssh2Data, "")
	if err != nil {
		t.Fatalf("ImportKey SSH2 failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-private-rsa4096-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, ssh2Key, pkcs8Key)
}

func TestImportRsa4096JwkAndPkcs8Match(t *testing.T) {
	jwkData := readTestFile(t, "testkey-private-rsa4096-jwk.txt")
	jwkKey, err := ImportKey(jwkData, "")
	if err != nil {
		t.Fatalf("ImportKey JWK failed: %v", err)
	}

	pkcs8Data := readTestFile(t, "testkey-private-rsa4096-pkcs8.txt")
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}

	assertPublicKeyBytesEqual(t, jwkKey, pkcs8Key)
}
