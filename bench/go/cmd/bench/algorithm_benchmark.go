// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/algorithms"
)

// --- Encryption benchmarks ---

func encryptionScenarios() []benchmarkScenario {
	type encSpec struct {
		name     string
		algo     *algorithms.EncryptionAlgorithm
		size     int
		scenName string
	}

	specs := []encSpec{
		{"AES-256-GCM", algorithms.NewAes256Gcm(), 1024, "enc-aes256gcm-1024"},
		{"AES-256-GCM", algorithms.NewAes256Gcm(), 32768, "enc-aes256gcm-32768"},
		{"AES-256-GCM", algorithms.NewAes256Gcm(), 65536, "enc-aes256gcm-65536"},
		{"AES-256-CBC", algorithms.NewAes256Cbc(), 32768, "enc-aes256cbc-32768"},
		{"AES-256-CTR", algorithms.NewAes256Ctr(), 32768, "enc-aes256ctr-32768"},
	}

	var scenarios []benchmarkScenario
	for _, spec := range specs {
		spec := spec // capture
		scenarios = append(scenarios, benchmarkScenario{
			name:     spec.scenName,
			category: "algorithm-encryption",
			tags:     map[string]string{"algo": spec.algo.Name, "size": fmt.Sprintf("%d", spec.size)},
			run:      func(runs int) []metric { return runEncryptionBenchmark(spec.algo, spec.size, runs) },
		})
	}
	return scenarios
}

func runEncryptionBenchmark(algo *algorithms.EncryptionAlgorithm, payloadSize, runs int) []metric {
	key := make([]byte, algo.KeyLength)
	rand.Read(key)

	blockLen := 16 // AES block length
	alignedSize := (payloadSize / blockLen) * blockLen
	if alignedSize < blockLen {
		alignedSize = blockLen
	}

	plaintext := make([]byte, alignedSize)
	rand.Read(plaintext)

	timesMs := make([]float64, 0, runs)
	throughputs := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		iv := make([]byte, algo.IVLength())
		rand.Read(iv)
		ivCopy := make([]byte, len(iv))
		copy(ivCopy, iv)

		enc, err := algo.CreateCipher(true, key, iv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating encryptor: %v\n", err)
			continue
		}
		dec, err := algo.CreateCipher(false, key, ivCopy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating decryptor: %v\n", err)
			continue
		}

		buf := make([]byte, alignedSize)
		copy(buf, plaintext)

		start := time.Now()

		if err := enc.Transform(buf); err != nil {
			fmt.Fprintf(os.Stderr, "Encrypt error: %v\n", err)
			continue
		}

		// Handle GCM tag transfer
		if algo.IsAead {
			if gcmEnc, ok := enc.(*algorithms.AesGcmCipher); ok {
				tag := gcmEnc.Sign(nil)
				if gcmDec, ok := dec.(*algorithms.AesGcmCipher); ok {
					gcmDec.SetTag(tag)
				}
			}
		}

		if err := dec.Transform(buf); err != nil {
			fmt.Fprintf(os.Stderr, "Decrypt error: %v\n", err)
			continue
		}

		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		timesMs = append(timesMs, ms)

		// Skip throughput for small payloads — sub-millisecond operations produce
		// wildly noisy MB/s values due to timer resolution limits.
		if alignedSize >= 4096 {
			megabytes := float64(alignedSize) / (1024 * 1024)
			seconds := elapsed.Seconds()
			if seconds > 0 {
				throughputs = append(throughputs, megabytes/seconds)
			} else {
				throughputs = append(throughputs, 0)
			}
		}

		fmt.Print(".")
	}

	metrics := []metric{
		{Name: "Encrypt+Decrypt time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
	if len(throughputs) > 0 {
		metrics = append(metrics, metric{Name: "Throughput", Unit: "MB/s", Values: throughputs, HigherIsBetter: true})
	}
	return metrics
}

// --- HMAC benchmarks ---

func hmacScenarios() []benchmarkScenario {
	type hmacSpec struct {
		algo     *algorithms.HmacAlgorithm
		scenName string
	}

	specs := []hmacSpec{
		{algorithms.NewHmacSha256(), "hmac-sha256"},
		{algorithms.NewHmacSha512(), "hmac-sha512"},
		{algorithms.NewHmacSha256Etm(), "hmac-sha256-etm"},
		{algorithms.NewHmacSha512Etm(), "hmac-sha512-etm"},
	}

	var scenarios []benchmarkScenario
	for _, spec := range specs {
		spec := spec
		scenarios = append(scenarios, benchmarkScenario{
			name:     spec.scenName,
			category: "algorithm-hmac",
			tags:     map[string]string{"algo": spec.algo.Name},
			run:      func(runs int) []metric { return runHmacBenchmark(spec.algo, runs) },
		})
	}
	return scenarios
}

func runHmacBenchmark(algo *algorithms.HmacAlgorithm, runs int) []metric {
	key := make([]byte, algo.KeyLength)
	rand.Read(key)

	data := make([]byte, 256)
	rand.Read(data)

	timesMs := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		signer := algo.CreateSigner(key)
		verifier := algo.CreateVerifier(key)

		start := time.Now()

		sig := signer.Sign(data)
		verifier.Verify(data, sig)

		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		timesMs = append(timesMs, ms)
		fmt.Print(".")
	}

	return []metric{
		{Name: "Sign+Verify time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}

// --- KEX benchmarks ---

func kexScenarios() []benchmarkScenario {
	type kexSpec struct {
		algo     *algorithms.KeyExchangeAlgorithm
		scenName string
	}

	specs := []kexSpec{
		{algorithms.NewECDHP256SHA256(), "kex-ecdh-p256"},
		{algorithms.NewECDHP384SHA384(), "kex-ecdh-p384"},
		{algorithms.NewECDHP521SHA512(), "kex-ecdh-p521"},
		{algorithms.NewDHGroup14SHA256(), "kex-dh-group14"},
		{algorithms.NewDHGroup16SHA512(), "kex-dh-group16"},
	}

	var scenarios []benchmarkScenario
	for _, spec := range specs {
		spec := spec
		scenarios = append(scenarios, benchmarkScenario{
			name:     spec.scenName,
			category: "algorithm-kex",
			tags:     map[string]string{"algo": spec.algo.Name},
			run:      func(runs int) []metric { return runKexBenchmark(spec.algo, runs) },
		})
	}
	return scenarios
}

func runKexBenchmark(algo *algorithms.KeyExchangeAlgorithm, runs int) []metric {
	timesMs := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		start := time.Now()

		kex1, err := algo.CreateKeyExchange()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating KEX: %v\n", err)
			continue
		}
		kex2, err := algo.CreateKeyExchange()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating KEX: %v\n", err)
			continue
		}

		pub1, err := kex1.StartKeyExchange()
		if err != nil {
			fmt.Fprintf(os.Stderr, "StartKeyExchange error: %v\n", err)
			continue
		}
		pub2, err := kex2.StartKeyExchange()
		if err != nil {
			fmt.Fprintf(os.Stderr, "StartKeyExchange error: %v\n", err)
			continue
		}

		_, err = kex1.DecryptKeyExchange(pub2)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DecryptKeyExchange error: %v\n", err)
			continue
		}
		_, err = kex2.DecryptKeyExchange(pub1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DecryptKeyExchange error: %v\n", err)
			continue
		}

		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		timesMs = append(timesMs, ms)
		fmt.Print(".")
	}

	return []metric{
		{Name: "Key exchange time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}

// --- Keygen benchmarks ---

func keygenScenarios() []benchmarkScenario {
	type keygenSpec struct {
		algoName string
		keySize  int
		scenName string
	}

	specs := []keygenSpec{
		{ssh.AlgoPKRsaSha256, 2048, "keygen-rsa-2048"},
		{ssh.AlgoPKRsaSha512, 4096, "keygen-rsa-4096"},
		{ssh.AlgoPKEcdsaSha2P256, 256, "keygen-ecdsa-p256"},
		{ssh.AlgoPKEcdsaSha2P384, 384, "keygen-ecdsa-p384"},
		{ssh.AlgoPKEcdsaSha2P521, 521, "keygen-ecdsa-p521"},
	}

	var scenarios []benchmarkScenario
	for _, spec := range specs {
		spec := spec
		// Determine key algorithm name for tags (matches C# pattern)
		keyAlgoName := keyAlgorithmName(spec.algoName)
		scenarios = append(scenarios, benchmarkScenario{
			name:     spec.scenName,
			category: "algorithm-keygen",
			tags:     map[string]string{"algo": keyAlgoName, "size": fmt.Sprintf("%d", spec.keySize)},
			run:      func(runs int) []metric { return runKeygenBenchmark(spec.algoName, runs) },
		})
	}
	return scenarios
}

// keyAlgorithmName maps public key algorithm names to SSH key algorithm names.
// This matches C#'s PublicKeyAlgorithm.KeyAlgorithmName.
func keyAlgorithmName(algoName string) string {
	switch algoName {
	case ssh.AlgoPKRsaSha256, ssh.AlgoPKRsaSha512:
		return ssh.AlgoKeyRsa
	default:
		// ECDSA key algorithm name equals the algorithm name
		return algoName
	}
}

func runKeygenBenchmark(algoName string, runs int) []metric {
	timesMs := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		start := time.Now()

		_, err := ssh.GenerateKeyPair(algoName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			continue
		}

		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		timesMs = append(timesMs, ms)
		fmt.Print(".")
	}

	return []metric{
		{Name: "Keygen time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}

// --- Signature benchmarks ---

// signer is the interface implemented by key pairs that can sign and verify.
type signer interface {
	Sign(data []byte) ([]byte, error)
	Verify(data, signature []byte) (bool, error)
}

func signatureScenarios() []benchmarkScenario {
	type sigSpec struct {
		algoName string
		keySize  int
		scenName string
	}

	specs := []sigSpec{
		{ssh.AlgoPKRsaSha256, 2048, "sig-rsa-sha256"},
		{ssh.AlgoPKRsaSha512, 2048, "sig-rsa-sha512"},
		{ssh.AlgoPKEcdsaSha2P256, 256, "sig-ecdsa-p256"},
		{ssh.AlgoPKEcdsaSha2P384, 384, "sig-ecdsa-p384"},
		{ssh.AlgoPKEcdsaSha2P521, 521, "sig-ecdsa-p521"},
	}

	var scenarios []benchmarkScenario
	for _, spec := range specs {
		spec := spec
		// Use the public key algorithm name (not the key algorithm name) for signature tags
		// This matches C# where sig tags use algorithm.Name (e.g., "rsa-sha2-256")
		scenarios = append(scenarios, benchmarkScenario{
			name:     spec.scenName,
			category: "algorithm-signature",
			tags:     map[string]string{"algo": spec.algoName, "size": fmt.Sprintf("%d", spec.keySize)},
			run:      func(runs int) []metric { return runSignatureBenchmark(spec.algoName, runs) },
		})
	}
	return scenarios
}

func runSignatureBenchmark(algoName string, runs int) []metric {
	// Generate key pair outside timed section
	kp, err := ssh.GenerateKeyPair(algoName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key for signature benchmark: %v\n", err)
		return nil
	}

	s, ok := kp.(signer)
	if !ok {
		fmt.Fprintf(os.Stderr, "Key pair does not implement signer interface\n")
		return nil
	}

	data := make([]byte, 256)
	rand.Read(data)

	timesMs := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		start := time.Now()

		sig, err := s.Sign(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Sign error: %v\n", err)
			continue
		}

		_, err = s.Verify(data, sig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verify error: %v\n", err)
			continue
		}

		elapsed := time.Since(start)
		ms := float64(elapsed.Nanoseconds()) / 1e6
		timesMs = append(timesMs, ms)
		fmt.Print(".")
	}

	return []metric{
		{Name: "Sign+Verify time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}
