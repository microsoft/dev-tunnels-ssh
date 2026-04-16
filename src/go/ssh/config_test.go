// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"testing"
)

func TestNewDefaultConfig(t *testing.T) {
	config := NewDefaultConfig()

	// Verify protocol extensions.
	if len(config.ProtocolExtensions) != 2 {
		t.Fatalf("expected 2 protocol extensions, got %d", len(config.ProtocolExtensions))
	}
	if config.ProtocolExtensions[0] != ExtensionServerSignatureAlgorithms {
		t.Errorf("expected first extension to be %q", ExtensionServerSignatureAlgorithms)
	}
	if config.ProtocolExtensions[1] != ExtensionOpenChannelRequest {
		t.Errorf("expected second extension to be %q", ExtensionOpenChannelRequest)
	}

	// Verify KEX algorithms match C#/TS preference order.
	expectedKex := []string{
		AlgoKexEcdhNistp384,
		AlgoKexEcdhNistp256,
		AlgoKexDHGroup16,
		AlgoKexDHGroup14,
	}
	if len(config.KeyExchangeAlgorithms) != len(expectedKex) {
		t.Fatalf("expected %d KEX algorithms, got %d", len(expectedKex), len(config.KeyExchangeAlgorithms))
	}
	for i, expected := range expectedKex {
		if config.KeyExchangeAlgorithms[i] != expected {
			t.Errorf("KEX[%d]: expected %q, got %q", i, expected, config.KeyExchangeAlgorithms[i])
		}
	}

	// Verify public key algorithms match C#/TS preference order.
	expectedPK := []string{
		AlgoPKRsaSha512,
		AlgoPKRsaSha256,
		AlgoPKEcdsaSha2P384,
		AlgoPKEcdsaSha2P256,
	}
	if len(config.PublicKeyAlgorithms) != len(expectedPK) {
		t.Fatalf("expected %d PK algorithms, got %d", len(expectedPK), len(config.PublicKeyAlgorithms))
	}
	for i, expected := range expectedPK {
		if config.PublicKeyAlgorithms[i] != expected {
			t.Errorf("PK[%d]: expected %q, got %q", i, expected, config.PublicKeyAlgorithms[i])
		}
	}

	// Verify encryption algorithms match C#/TS preference order.
	expectedEnc := []string{
		AlgoEncAes256Gcm,
		AlgoEncAes256Cbc,
		AlgoEncAes256Ctr,
	}
	if len(config.EncryptionAlgorithms) != len(expectedEnc) {
		t.Fatalf("expected %d encryption algorithms, got %d", len(expectedEnc), len(config.EncryptionAlgorithms))
	}
	for i, expected := range expectedEnc {
		if config.EncryptionAlgorithms[i] != expected {
			t.Errorf("Enc[%d]: expected %q, got %q", i, expected, config.EncryptionAlgorithms[i])
		}
	}

	// Verify HMAC algorithms match C#/TS preference order.
	expectedHmac := []string{
		AlgoHmacSha512Etm,
		AlgoHmacSha256Etm,
		AlgoHmacSha512,
		AlgoHmacSha256,
	}
	if len(config.HmacAlgorithms) != len(expectedHmac) {
		t.Fatalf("expected %d HMAC algorithms, got %d", len(expectedHmac), len(config.HmacAlgorithms))
	}
	for i, expected := range expectedHmac {
		if config.HmacAlgorithms[i] != expected {
			t.Errorf("HMAC[%d]: expected %q, got %q", i, expected, config.HmacAlgorithms[i])
		}
	}

	// Verify compression.
	if len(config.CompressionAlgorithms) != 1 || config.CompressionAlgorithms[0] != AlgoCompNone {
		t.Error("expected single 'none' compression algorithm")
	}

	// Verify authentication methods.
	expectedAuth := []string{
		AuthMethodNone,
		AuthMethodPassword,
		AuthMethodPublicKey,
		AuthMethodKeyboardInteractive,
	}
	if len(config.AuthenticationMethods) != len(expectedAuth) {
		t.Fatalf("expected %d auth methods, got %d", len(expectedAuth), len(config.AuthenticationMethods))
	}
	for i, expected := range expectedAuth {
		if config.AuthenticationMethods[i] != expected {
			t.Errorf("Auth[%d]: expected %q, got %q", i, expected, config.AuthenticationMethods[i])
		}
	}

	// Verify service registrations.
	if len(config.ServiceRegistrations) < 1 {
		t.Errorf("expected at least 1 service registration, got %d", len(config.ServiceRegistrations))
	}

	// Verify settings.
	if config.MaxClientAuthenticationAttempts != 5 {
		t.Errorf("expected MaxClientAuthenticationAttempts=5, got %d", config.MaxClientAuthenticationAttempts)
	}
	if config.EnableKeyExchangeGuess {
		t.Error("expected EnableKeyExchangeGuess=false by default")
	}
	if config.KeepAliveIntervalSeconds != 0 {
		t.Errorf("expected KeepAliveIntervalSeconds=0, got %d", config.KeepAliveIntervalSeconds)
	}
	if config.KeyRotationThreshold != 512*1024*1024 {
		t.Errorf("expected KeyRotationThreshold=512MiB, got %d", config.KeyRotationThreshold)
	}
}

func TestNewDefaultConfigWithReconnect(t *testing.T) {
	config := NewDefaultConfigWithReconnect()

	// Should have 4 protocol extensions (default 2 + reconnect + latency).
	if len(config.ProtocolExtensions) != 4 {
		t.Fatalf("expected 4 protocol extensions, got %d", len(config.ProtocolExtensions))
	}

	hasReconnect := false
	hasLatency := false
	for _, ext := range config.ProtocolExtensions {
		if ext == ExtensionSessionReconnect {
			hasReconnect = true
		}
		if ext == ExtensionSessionLatency {
			hasLatency = true
		}
	}
	if !hasReconnect {
		t.Error("expected reconnect extension")
	}
	if !hasLatency {
		t.Error("expected latency extension")
	}

	// Should still have the same secure algorithms as default.
	if len(config.KeyExchangeAlgorithms) != 4 {
		t.Errorf("expected 4 KEX algorithms, got %d", len(config.KeyExchangeAlgorithms))
	}
}

func TestNewNoSecurityConfig(t *testing.T) {
	config := NewNoSecurityConfig()

	// All algorithm lists should have just "none".
	if len(config.KeyExchangeAlgorithms) != 1 || config.KeyExchangeAlgorithms[0] != AlgoKexNone {
		t.Error("expected single 'none' KEX algorithm")
	}
	if len(config.PublicKeyAlgorithms) != 1 || config.PublicKeyAlgorithms[0] != AlgoPKNone {
		t.Error("expected single 'none' PK algorithm")
	}
	if len(config.EncryptionAlgorithms) != 1 || config.EncryptionAlgorithms[0] != AlgoEncNone {
		t.Error("expected single 'none' encryption algorithm")
	}
	if len(config.HmacAlgorithms) != 1 || config.HmacAlgorithms[0] != AlgoHmacNone {
		t.Error("expected single 'none' HMAC algorithm")
	}
	if len(config.CompressionAlgorithms) != 1 || config.CompressionAlgorithms[0] != AlgoCompNone {
		t.Error("expected single 'none' compression algorithm")
	}

	// Should still have protocol extensions.
	if len(config.ProtocolExtensions) != 2 {
		t.Errorf("expected 2 protocol extensions, got %d", len(config.ProtocolExtensions))
	}

	// Should still have service registrations.
	if len(config.ServiceRegistrations) < 1 {
		t.Errorf("expected at least 1 service registration, got %d", len(config.ServiceRegistrations))
	}
}

func TestDefaultConfigsAreIndependent(t *testing.T) {
	config1 := NewDefaultConfig()
	config2 := NewDefaultConfig()

	// Modifying one should not affect the other.
	config1.KeyExchangeAlgorithms = append(config1.KeyExchangeAlgorithms, "extra")
	if len(config2.KeyExchangeAlgorithms) != 4 {
		t.Error("modifying config1 should not affect config2")
	}
}
