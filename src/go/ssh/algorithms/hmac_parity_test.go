// Copyright (c) Microsoft Corporation. All rights reserved.

package algorithms

import (
	"crypto/rand"
	"testing"
)

// TestAllHMACAlgorithmsRoundTrip tests each HMAC algorithm (hmac-sha2-256,
// hmac-sha2-512, hmac-sha2-256-etm, hmac-sha2-512-etm): create signer with
// known key, sign 1KB data, verify with verifier using same key.
func TestAllHMACAlgorithmsRoundTrip(t *testing.T) {
	algos := []struct {
		name   string
		create func() *HmacAlgorithm
	}{
		{"hmac-sha2-256", NewHmacSha256},
		{"hmac-sha2-512", NewHmacSha512},
		{"hmac-sha2-256-etm@openssh.com", NewHmacSha256Etm},
		{"hmac-sha2-512-etm@openssh.com", NewHmacSha512Etm},
	}

	for _, tc := range algos {
		t.Run(tc.name, func(t *testing.T) {
			algo := tc.create()
			if algo.Name != tc.name {
				t.Fatalf("expected algorithm name %q, got %q", tc.name, algo.Name)
			}

			key := make([]byte, algo.KeyLength)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}

			// Generate 1KB of random data.
			data := make([]byte, 1024)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}

			signer := algo.CreateSigner(key)
			verifier := algo.CreateVerifier(key)

			// Sign.
			sig := signer.Sign(data)
			if len(sig) != algo.digestLength {
				t.Fatalf("expected digest length %d, got %d", algo.digestLength, len(sig))
			}

			// Verify with same key should succeed.
			if !verifier.Verify(data, sig) {
				t.Fatalf("verify should succeed with correct key for %s", tc.name)
			}

			// Verify with tampered data should fail.
			tampered := make([]byte, len(data))
			copy(tampered, data)
			tampered[0] ^= 0xFF
			if verifier.Verify(tampered, sig) {
				t.Fatalf("verify should fail with tampered data for %s", tc.name)
			}
		})
	}
}
