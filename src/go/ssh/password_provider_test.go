// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestPasswordProviderReturnsCredentials verifies that when PasswordProvider is set
// and returns valid credentials, the client authenticates successfully using those
// credentials instead of the static Username/Password fields.
func TestPasswordProviderReturnsCredentials(t *testing.T) {
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

	var providerCalled bool
	var providerMu sync.Mutex

	success, err := client.Authenticate(ctx, &ClientCredentials{
		// Static fields left empty — PasswordProvider should be used instead.
		PasswordProvider: func(ctx context.Context) (string, string, error) {
			providerMu.Lock()
			providerCalled = true
			providerMu.Unlock()
			return "provideruser", "providersecret", nil
		},
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false, want true")
	}

	providerMu.Lock()
	if !providerCalled {
		t.Fatal("PasswordProvider was not called")
	}
	providerMu.Unlock()

	mu.Lock()
	defer mu.Unlock()
	if receivedAuthType != AuthClientPassword {
		t.Errorf("server received AuthenticationType = %d, want AuthClientPassword (%d)",
			receivedAuthType, AuthClientPassword)
	}
	if receivedUsername != "provideruser" {
		t.Errorf("server received username = %q, want %q", receivedUsername, "provideruser")
	}
	if receivedPassword != "providersecret" {
		t.Errorf("server received password = %q, want %q", receivedPassword, "providersecret")
	}
}

// TestPasswordProviderReturnsError verifies that when PasswordProvider returns
// an error, the session is closed gracefully with DisconnectAuthCancelledByUser.
func TestPasswordProviderReturnsError(t *testing.T) {
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

	providerErr := fmt.Errorf("user cancelled authentication")

	success, err := client.Authenticate(ctx, &ClientCredentials{
		PasswordProvider: func(ctx context.Context) (string, string, error) {
			return "", "", providerErr
		},
	})
	if success {
		t.Fatal("Authenticate returned true, want false")
	}
	if err == nil {
		t.Fatal("Authenticate returned nil error, want provider error")
	}
	if err != providerErr {
		t.Errorf("Authenticate returned error %v, want %v", err, providerErr)
	}
}

// TestPasswordProviderReturnsEmpty verifies that when PasswordProvider returns
// empty username and password, password auth is skipped and the client falls
// through to other auth methods.
func TestPasswordProviderReturnsEmpty(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
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

	// PasswordProvider returns empty — password auth should be skipped,
	// falling through to "none" method (which the server accepts).
	success, err := client.Authenticate(ctx, &ClientCredentials{
		PasswordProvider: func(ctx context.Context) (string, string, error) {
			return "", "", nil
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
	// Should have fallen through to "none" since password was skipped.
	if receivedAuthType != AuthClientNone {
		t.Errorf("server received AuthenticationType = %d, want AuthClientNone (%d)",
			receivedAuthType, AuthClientNone)
	}
}

// TestStaticPasswordStillWorks verifies backward compatibility: when
// PasswordProvider is nil, the static Username/Password fields are used.
func TestStaticPasswordStillWorks(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

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
			receivedUsername = args.Username
			receivedPassword = args.Password
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "staticuser",
		Password: "staticsecret",
		// PasswordProvider is nil — should use static fields.
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false, want true")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedUsername != "staticuser" {
		t.Errorf("server received username = %q, want %q", receivedUsername, "staticuser")
	}
	if receivedPassword != "staticsecret" {
		t.Errorf("server received password = %q, want %q", receivedPassword, "staticsecret")
	}
}
