// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestPrivateKeyProviderCalledDuringAuth verifies that when a key in
// ClientCredentials.PublicKeys lacks private material and a PrivateKeyProvider
// is set, the provider is called and the resolved key is used for authentication.
func TestPrivateKeyProviderCalledDuringAuth(t *testing.T) {
	// Generate a full key pair, then create a public-key-only copy.
	fullKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubBytes, err := fullKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("get public key bytes: %v", err)
	}
	publicOnlyKey, err := KeyPairFromPublicKeyBytes(pubBytes)
	if err != nil {
		t.Fatalf("create public-only key: %v", err)
	}

	// Verify the public-only key lacks private material.
	if publicOnlyKey.HasPrivateKey() {
		t.Fatal("public-only key should not have private key")
	}

	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	var providerCalled bool
	var providerMu sync.Mutex

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username:   "testuser",
		PublicKeys: []KeyPair{publicOnlyKey},
		PrivateKeyProvider: func(ctx context.Context, pubKey KeyPair) (KeyPair, error) {
			providerMu.Lock()
			providerCalled = true
			providerMu.Unlock()
			// Return the full key pair with private material.
			return fullKey, nil
		},
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false, want true")
	}

	providerMu.Lock()
	defer providerMu.Unlock()
	if !providerCalled {
		t.Fatal("PrivateKeyProvider was not called")
	}
}

// TestPrivateKeyProviderNotCalledWhenKeyHasPrivate verifies that the provider
// is NOT called when the key already has private material.
func TestPrivateKeyProviderNotCalledWhenKeyHasPrivate(t *testing.T) {
	fullKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	var providerCalled bool
	var mu sync.Mutex

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username:   "testuser",
		PublicKeys: []KeyPair{fullKey},
		PrivateKeyProvider: func(ctx context.Context, pubKey KeyPair) (KeyPair, error) {
			mu.Lock()
			providerCalled = true
			mu.Unlock()
			return fullKey, nil
		},
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false, want true")
	}

	mu.Lock()
	defer mu.Unlock()
	if providerCalled {
		t.Fatal("PrivateKeyProvider was called but should not have been (key already has private material)")
	}
}

// TestPrivateKeyProviderSkipsKeyWhenNoProvider verifies that keys without
// private material are skipped when no PrivateKeyProvider is set.
func TestPrivateKeyProviderSkipsKeyWhenNoProvider(t *testing.T) {
	fullKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubBytes, err := fullKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("get public key bytes: %v", err)
	}
	publicOnlyKey, err := KeyPairFromPublicKeyBytes(pubBytes)
	if err != nil {
		t.Fatalf("create public-only key: %v", err)
	}

	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// With only a public-key-only key and no provider, auth should fall through
	// to none/password methods. Since we provide no password, it tries "none"
	// which we approve on the server side.
	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username:   "testuser",
		PublicKeys: []KeyPair{publicOnlyKey},
		// No PrivateKeyProvider set — public-only key should be skipped.
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	// Auth succeeds via "none" since server approves all.
	if !success {
		t.Fatal("Authenticate returned false, want true (via none method)")
	}
}

// TestServerPrivateKeyProvider verifies that the server's PrivateKeyProvider
// is called during key exchange when a host key lacks private material.
func TestServerPrivateKeyProvider(t *testing.T) {
	// Generate a full key pair for the server, then create a public-only copy.
	fullServerKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	pubBytes, err := fullServerKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("get public key bytes: %v", err)
	}
	publicOnlyServerKey, err := KeyPairFromPublicKeyBytes(pubBytes)
	if err != nil {
		t.Fatalf("create public-only key: %v", err)
	}

	var providerCalled bool
	var providerMu sync.Mutex

	// Create session pair with the server using a public-only host key
	// and a PrivateKeyProvider that returns the full key.
	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{publicOnlyServerKey},
			PrivateKeyProvider: func(ctx context.Context, pubKey KeyPair) (KeyPair, error) {
				providerMu.Lock()
				providerCalled = true
				providerMu.Unlock()
				return fullServerKey, nil
			},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		},
	})

	// Connection should succeed — provider resolves the full host key during KEX.
	if !client.IsConnected() {
		t.Fatal("client should be connected after session pair creation")
	}

	providerMu.Lock()
	defer providerMu.Unlock()
	if !providerCalled {
		t.Fatal("server PrivateKeyProvider was not called during key exchange")
	}
}
