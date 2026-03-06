// Copyright (c) Microsoft Corporation. All rights reserved.

// Use external test package to import the parent ssh package without
// creating a circular dependency (ssh already imports ssh/algorithms).
package algorithms_test

import (
	"crypto/rand"
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// BenchmarkKeygen benchmarks key pair generation for each supported algorithm.

func BenchmarkKeygenRsa2048(b *testing.B) {
	benchmarkKeygen(b, ssh.AlgoPKRsaSha256)
}

func BenchmarkKeygenRsa4096(b *testing.B) {
	benchmarkKeygen(b, ssh.AlgoPKRsaSha512)
}

func BenchmarkKeygenEcdsaP256(b *testing.B) {
	benchmarkKeygen(b, ssh.AlgoPKEcdsaSha2P256)
}

func BenchmarkKeygenEcdsaP384(b *testing.B) {
	benchmarkKeygen(b, ssh.AlgoPKEcdsaSha2P384)
}

func BenchmarkKeygenEcdsaP521(b *testing.B) {
	benchmarkKeygen(b, ssh.AlgoPKEcdsaSha2P521)
}

func benchmarkKeygen(b *testing.B, algorithmName string) {
	b.Helper()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := ssh.GenerateKeyPair(algorithmName)
		if err != nil {
			b.Fatalf("generate key pair: %v", err)
		}
	}
}

// BenchmarkSignVerify benchmarks signing and verification for each
// supported public key algorithm.

func BenchmarkSignVerifyRsaSha256(b *testing.B) {
	benchmarkSignVerify(b, ssh.AlgoPKRsaSha256)
}

func BenchmarkSignVerifyRsaSha512(b *testing.B) {
	benchmarkSignVerify(b, ssh.AlgoPKRsaSha512)
}

func BenchmarkSignVerifyEcdsaP256(b *testing.B) {
	benchmarkSignVerify(b, ssh.AlgoPKEcdsaSha2P256)
}

func BenchmarkSignVerifyEcdsaP384(b *testing.B) {
	benchmarkSignVerify(b, ssh.AlgoPKEcdsaSha2P384)
}

func BenchmarkSignVerifyEcdsaP521(b *testing.B) {
	benchmarkSignVerify(b, ssh.AlgoPKEcdsaSha2P521)
}

// signer is the interface for key pairs that support Sign and Verify.
type signer interface {
	Sign(data []byte) ([]byte, error)
	Verify(data, signature []byte) (bool, error)
}

func benchmarkSignVerify(b *testing.B, algorithmName string) {
	b.Helper()

	kp, err := ssh.GenerateKeyPair(algorithmName)
	if err != nil {
		b.Fatalf("generate key pair: %v", err)
	}

	s, ok := kp.(signer)
	if !ok {
		b.Fatalf("key pair does not implement signer interface")
	}

	// Fixed message to sign (32 bytes, typical hash size).
	data := make([]byte, 32)
	rand.Read(data)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sig, err := s.Sign(data)
		if err != nil {
			b.Fatalf("sign: %v", err)
		}

		ok, err := s.Verify(data, sig)
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
		if !ok {
			b.Fatal("signature verification failed")
		}
	}
}
