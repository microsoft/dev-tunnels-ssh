// Copyright (c) Microsoft Corporation. All rights reserved.

package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// TestKeySize is the RSA key size used for test key generation.
// 2048 bits provides reasonable security while being fast to generate.
const TestKeySize = 2048

// GenerateTestRSAKey generates a new RSA key pair for testing.
// The key is 2048-bit which balances test speed and realistic behavior.
func GenerateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, TestKeySize)
	if err != nil {
		t.Fatalf("failed to generate RSA test key: %v", err)
	}
	return key
}

// GenerateTestECDSAKey generates a new ECDSA key pair for testing using the P-384 curve.
// P-384 is the default curve used in the C#/TS implementations.
func GenerateTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA test key: %v", err)
	}
	return key
}

// GenerateTestECDSAKeyWithCurve generates a new ECDSA key pair using the specified curve.
func GenerateTestECDSAKeyWithCurve(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA test key with curve %s: %v", curve.Params().Name, err)
	}
	return key
}

// TestKeys holds pre-generated key pairs for use across multiple tests.
// Generate once per test suite for performance.
type TestKeys struct {
	RSA2048   *rsa.PrivateKey
	ECDSAP256 *ecdsa.PrivateKey
	ECDSAP384 *ecdsa.PrivateKey
	ECDSAP521 *ecdsa.PrivateKey
}

// DefaultECDSACurve returns the default ECDSA curve used for test keys (P-384).
func DefaultECDSACurve() elliptic.Curve {
	return elliptic.P384()
}

// GenerateTestKeys generates a complete set of test keys.
// This should be called once per test suite using TestMain or a sync.Once.
func GenerateTestKeys(t *testing.T) *TestKeys {
	t.Helper()
	keys := &TestKeys{}
	keys.RSA2048 = GenerateTestRSAKey(t)
	keys.ECDSAP256, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys.ECDSAP384, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	keys.ECDSAP521, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if keys.ECDSAP256 == nil || keys.ECDSAP384 == nil || keys.ECDSAP521 == nil {
		t.Fatal("failed to generate ECDSA test keys")
	}
	return keys
}
