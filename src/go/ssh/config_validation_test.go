// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// duplexPipe is defined in protocol_test.go — used here as well.

// TestValidateEncryptionWithoutKex verifies that a config with encryption algorithms
// but no key exchange algorithm is rejected by Validate().
func TestValidateEncryptionWithoutKex(t *testing.T) {
	config := &SessionConfig{
		KeyExchangeAlgorithms: []string{AlgoKexNone},
		EncryptionAlgorithms:  []string{AlgoEncAes256Gcm},
		HmacAlgorithms:        []string{AlgoHmacNone},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected validation error for encryption without KEX")
	}
	if !strings.Contains(err.Error(), "encryption") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestValidateHmacWithoutKex verifies that a config with HMAC algorithms
// but no key exchange algorithm is rejected by Validate().
func TestValidateHmacWithoutKex(t *testing.T) {
	config := &SessionConfig{
		KeyExchangeAlgorithms: []string{AlgoKexNone},
		EncryptionAlgorithms:  []string{AlgoEncNone},
		HmacAlgorithms:        []string{AlgoHmacSha256},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected validation error for HMAC without KEX")
	}
	if !strings.Contains(err.Error(), "HMAC") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestValidateDefaultConfigPasses verifies that the default config passes validation.
func TestValidateDefaultConfigPasses(t *testing.T) {
	config := NewDefaultConfig()
	if err := config.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
}

// TestValidateNoSecurityConfigPasses verifies that the no-security config passes validation.
func TestValidateNoSecurityConfigPasses(t *testing.T) {
	config := NewNoSecurityConfig()
	if err := config.Validate(); err != nil {
		t.Fatalf("no-security config should be valid: %v", err)
	}
}

// TestValidateReconnectConfigPasses verifies that the reconnect config passes validation.
func TestValidateReconnectConfigPasses(t *testing.T) {
	config := NewDefaultConfigWithReconnect()
	if err := config.Validate(); err != nil {
		t.Fatalf("reconnect config should be valid: %v", err)
	}
}

// TestConnectWithInvalidConfig verifies that Connect rejects an invalid config.
func TestConnectWithInvalidConfig(t *testing.T) {
	config := &SessionConfig{
		KeyExchangeAlgorithms: []string{AlgoKexNone},
		EncryptionAlgorithms:  []string{AlgoEncAes256Gcm},
		HmacAlgorithms:        []string{AlgoHmacNone},
	}
	cs := NewClientSession(config)
	clientStream, serverStream := duplexPipe()
	defer clientStream.Close()
	defer serverStream.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := cs.Connect(ctx, clientStream)
	if err == nil {
		t.Fatal("expected error from Connect with invalid config")
	}
	if !strings.Contains(err.Error(), "encryption") {
		t.Fatalf("unexpected error from Connect: %v", err)
	}
}

// TestSessionCloseReturnsNil verifies that Session.Close returns nil error.
func TestSessionCloseReturnsNil(t *testing.T) {
	client, _ := createSessionPair(t, nil)
	err := client.Close()
	if err != nil {
		t.Fatalf("Close() should return nil, got: %v", err)
	}
}

// TestSessionCloseIdempotent verifies that calling Close multiple times returns nil.
func TestSessionCloseIdempotent(t *testing.T) {
	client, _ := createSessionPair(t, nil)
	if err := client.Close(); err != nil {
		t.Fatalf("first Close() returned error: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close() returned error: %v", err)
	}
}

// TestSessionIOCloserCompliance verifies the compile-time io.Closer check works at runtime.
func TestSessionIOCloserCompliance(t *testing.T) {
	config := NewNoSecurityConfig()
	cs := NewClientSession(config)

	// Verify that *Session can be used as io.Closer.
	var closer io.Closer = &cs.Session
	_ = closer
}
