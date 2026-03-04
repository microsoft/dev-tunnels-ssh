// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// TestCrossFormatKeyConversion generates an RSA-2048 key, exports as PKCS#1,
// imports, re-exports as PKCS#8, imports again, and verifies the public key
// bytes match the original.
func TestCrossFormatKeyConversion(t *testing.T) {
	// Generate an RSA-2048 key pair.
	key, err := ssh.GenerateKeyPair(ssh.AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Export as PKCS#1 (private key).
	pkcs1Data, err := ExportPrivateKey(key, KeyFormatPkcs1, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey PKCS#1 failed: %v", err)
	}

	// Import from PKCS#1.
	pkcs1Key, err := ImportKey(pkcs1Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#1 failed: %v", err)
	}
	if !pkcs1Key.HasPrivateKey() {
		t.Fatal("PKCS#1 imported key should have private key")
	}
	assertPublicKeyBytesEqual(t, key, pkcs1Key)

	// Re-export as PKCS#8 (private key).
	pkcs8Data, err := ExportPrivateKey(pkcs1Key, KeyFormatPkcs8, "")
	if err != nil {
		t.Fatalf("ExportPrivateKey PKCS#8 failed: %v", err)
	}

	// Import from PKCS#8.
	pkcs8Key, err := ImportKey(pkcs8Data, "")
	if err != nil {
		t.Fatalf("ImportKey PKCS#8 failed: %v", err)
	}
	if !pkcs8Key.HasPrivateKey() {
		t.Fatal("PKCS#8 imported key should have private key")
	}

	// Verify the public key bytes match the original.
	assertPublicKeyBytesEqual(t, key, pkcs8Key)
}
