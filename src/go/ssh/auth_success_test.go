// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestAuthenticateNone verifies that authentication with the "none" method
// succeeds when the server accepts it, and the server OnAuthenticating callback
// receives AuthClientNone with the expected username.
func TestAuthenticateNone(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	var receivedAuthType AuthenticationType
	var receivedUsername string
	var mu sync.Mutex

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			defer mu.Unlock()
			receivedAuthType = args.AuthenticationType
			receivedUsername = args.Username
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false, want true")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAuthType != AuthClientNone {
		t.Errorf("server received AuthenticationType = %d, want AuthClientNone (%d)",
			receivedAuthType, AuthClientNone)
	}
	if receivedUsername != "testuser" {
		t.Errorf("server received username = %q, want %q", receivedUsername, "testuser")
	}
}

// TestAuthenticatePassword verifies that authentication with a password
// succeeds and the server receives the correct username and password.
func TestAuthenticatePassword(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	var receivedAuthType AuthenticationType
	var receivedUsername string
	var receivedPassword string
	var mu sync.Mutex

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			defer mu.Unlock()
			receivedAuthType = args.AuthenticationType
			receivedUsername = args.Username
			receivedPassword = args.Password
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "secret123",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false, want true")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAuthType != AuthClientPassword {
		t.Errorf("server received AuthenticationType = %d, want AuthClientPassword (%d)",
			receivedAuthType, AuthClientPassword)
	}
	if receivedUsername != "testuser" {
		t.Errorf("server received username = %q, want %q", receivedUsername, "testuser")
	}
	if receivedPassword != "secret123" {
		t.Errorf("server received password = %q, want %q", receivedPassword, "secret123")
	}
}

// TestAuthenticateRSAPublicKey verifies that authentication with an RSA key pair
// (rsa-sha2-256) succeeds with signature verification on the server side.
func TestAuthenticateRSAPublicKey(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	clientKey, err := GenerateKeyPair(AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("generate client RSA key: %v", err)
	}

	var receivedAuthType AuthenticationType
	var receivedUsername string
	var receivedPublicKey KeyPair
	var mu sync.Mutex

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			defer mu.Unlock()
			receivedAuthType = args.AuthenticationType
			receivedUsername = args.Username
			receivedPublicKey = args.PublicKey
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username:   "testuser",
		PublicKeys: []KeyPair{clientKey},
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false, want true")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAuthType != AuthClientPublicKey {
		t.Errorf("server received AuthenticationType = %d, want AuthClientPublicKey (%d)",
			receivedAuthType, AuthClientPublicKey)
	}
	if receivedUsername != "testuser" {
		t.Errorf("server received username = %q, want %q", receivedUsername, "testuser")
	}
	if receivedPublicKey == nil {
		t.Fatal("server received nil public key")
	}

	// Verify the server received the correct key by comparing public key bytes.
	clientPubBytes, err := clientKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("get client public key bytes: %v", err)
	}
	receivedPubBytes, err := receivedPublicKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("get received public key bytes: %v", err)
	}
	if len(clientPubBytes) != len(receivedPubBytes) {
		t.Errorf("public key bytes length mismatch: got %d, want %d",
			len(receivedPubBytes), len(clientPubBytes))
	}
}

// TestAuthenticateECDSAPublicKey verifies that authentication with an ECDSA key pair
// (ecdsa-sha2-nistp256) succeeds with signature verification on the server side.
func TestAuthenticateECDSAPublicKey(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	clientKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate client ECDSA key: %v", err)
	}

	var receivedAuthType AuthenticationType
	var receivedUsername string
	var receivedPublicKey KeyPair
	var mu sync.Mutex

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			defer mu.Unlock()
			receivedAuthType = args.AuthenticationType
			receivedUsername = args.Username
			receivedPublicKey = args.PublicKey
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username:   "testuser",
		PublicKeys: []KeyPair{clientKey},
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false, want true")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAuthType != AuthClientPublicKey {
		t.Errorf("server received AuthenticationType = %d, want AuthClientPublicKey (%d)",
			receivedAuthType, AuthClientPublicKey)
	}
	if receivedUsername != "testuser" {
		t.Errorf("server received username = %q, want %q", receivedUsername, "testuser")
	}
	if receivedPublicKey == nil {
		t.Fatal("server received nil public key")
	}

	// Verify the key algorithm matches ECDSA.
	if receivedPublicKey.KeyAlgorithmName() != AlgoPKEcdsaSha2P256 {
		t.Errorf("received key algorithm = %q, want %q",
			receivedPublicKey.KeyAlgorithmName(), AlgoPKEcdsaSha2P256)
	}
}

// TestAuthenticatePublicKeyQuery verifies that a public key query
// (no signature, just checking if key would be accepted) returns true
// when the server accepts the key.
func TestAuthenticatePublicKeyQuery(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	clientKey, err := GenerateKeyPair(AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	var receivedAuthType AuthenticationType
	var mu sync.Mutex

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			defer mu.Unlock()
			receivedAuthType = args.AuthenticationType
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accepted, err := client.AuthenticatePublicKeyQuery(ctx, "testuser", clientKey)
	if err != nil {
		t.Fatalf("AuthenticatePublicKeyQuery returned error: %v", err)
	}
	if !accepted {
		t.Fatal("AuthenticatePublicKeyQuery returned false, want true")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAuthType != AuthClientPublicKeyQuery {
		t.Errorf("server received AuthenticationType = %d, want AuthClientPublicKeyQuery (%d)",
			receivedAuthType, AuthClientPublicKeyQuery)
	}
}
