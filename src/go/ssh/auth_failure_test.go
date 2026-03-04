// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// TestAuthenticateWrongPassword verifies that authentication with a wrong
// password returns false without error.
func TestAuthenticateWrongPassword(t *testing.T) {
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
			// Only accept correct password.
			if args.AuthenticationType == AuthClientPassword && args.Password == "correct" {
				args.AuthenticationResult = true
			}
			// Leave AuthenticationResult nil for wrong password → rejected.
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "wrong-password",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if success {
		t.Fatal("Authenticate returned true, want false for wrong password")
	}
}

// TestAuthenticateUnknownPublicKey verifies that authentication with an
// unknown public key returns false without error.
func TestAuthenticateUnknownPublicKey(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	// Generate a known key that the server will accept.
	knownKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate known key: %v", err)
	}
	knownPubBytes, err := knownKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("get known key public bytes: %v", err)
	}

	// Generate an unknown key for the client.
	unknownKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate unknown key: %v", err)
	}

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			if args.AuthenticationType == AuthClientPublicKey && args.PublicKey != nil {
				// Only accept the known key.
				pubBytes, _ := args.PublicKey.GetPublicKeyBytes()
				if len(pubBytes) == len(knownPubBytes) {
					match := true
					for i := range pubBytes {
						if pubBytes[i] != knownPubBytes[i] {
							match = false
							break
						}
					}
					if match {
						args.AuthenticationResult = true
						return
					}
				}
			}
			// Reject all other auth types/keys.
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username:   "testuser",
		PublicKeys: []KeyPair{unknownKey},
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if success {
		t.Fatal("Authenticate returned true, want false for unknown public key")
	}
}

// TestMaxAuthAttemptsExceeded verifies that the server disconnects with
// NoMoreAuthMethodsAvailable after the maximum number of auth attempts.
func TestMaxAuthAttemptsExceeded(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	serverConfig := NewDefaultConfig()
	serverConfig.MaxClientAuthenticationAttempts = 2

	var closedReason messages.SSHDisconnectReason
	var closedMu sync.Mutex
	closedCh := make(chan struct{})

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: serverConfig,
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			// Reject all authentication attempts.
		},
	})

	server.SetClosedHandler(func(args *SessionClosedEventArgs) {
		closedMu.Lock()
		closedReason = args.Reason
		closedMu.Unlock()
		close(closedCh)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First attempt — should fail but not disconnect (failureCount=1).
	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "wrong1",
	})
	if err != nil {
		t.Fatalf("first Authenticate returned error: %v", err)
	}
	if success {
		t.Fatal("first Authenticate returned true, want false")
	}

	// Second attempt — should trigger disconnect (failureCount=2 >= max=2).
	success, err = client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "wrong2",
	})
	// On the 2nd attempt, the server sends AuthFailure then disconnects.
	// The client may get either (false, nil) or (false, ConnectionError).
	if success {
		t.Fatal("second Authenticate returned true, want false")
	}

	// Wait for server to close.
	select {
	case <-closedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server OnClosed")
	}

	closedMu.Lock()
	reason := closedReason
	closedMu.Unlock()

	if reason != messages.DisconnectNoMoreAuthMethodsAvailable {
		t.Errorf("server closed with reason %d, want DisconnectNoMoreAuthMethodsAvailable (%d)",
			reason, messages.DisconnectNoMoreAuthMethodsAvailable)
	}

	// Verify both sessions are eventually closed.
	deadline := time.After(5 * time.Second)
	for !client.IsClosed() {
		select {
		case <-deadline:
			t.Fatal("client did not become closed after server disconnect")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestAuthCallbackPanics verifies that a panic in the server's
// OnAuthenticating callback is recovered and treated as auth failure,
// and the session remains stable.
func TestAuthCallbackPanics(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			panic("simulated callback error")
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "password",
	})
	if err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if success {
		t.Fatal("Authenticate returned true, want false when callback panics")
	}

	// Verify the session is still connected (no crash).
	if !server.IsConnected() {
		t.Error("server session is not connected after callback panic")
	}
	if !client.IsConnected() {
		t.Error("client session is not connected after callback panic")
	}

	// Verify the session can close cleanly (no panic or deadlock).
	client.Close()
}

// TestKeyboardInteractiveAuth verifies keyboard-interactive authentication
// with a single prompt and response succeeds.
func TestKeyboardInteractiveAuth(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	const expectedAnswer = "secret-answer"

	var receivedAnswer string
	var mu sync.Mutex

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ClientOnAuthenticating: func(args *AuthenticatingEventArgs) {
			// Handle server key verification.
			if args.AuthenticationType == AuthServerPublicKey {
				args.AuthenticationResult = true
				return
			}
			// Handle keyboard-interactive prompts.
			if args.AuthenticationType == AuthClientInteractive && args.InfoRequest != nil {
				args.InfoResponse = &messages.AuthenticationInfoResponseMessage{
					Responses: []string{expectedAnswer},
				}
				return
			}
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			// Reject "none" auth.
			if args.AuthenticationType == AuthClientNone {
				return
			}
			// Handle keyboard-interactive.
			if args.AuthenticationType == AuthClientInteractive {
				if args.InfoResponse != nil {
					// Second call: validate the response.
					mu.Lock()
					if len(args.InfoResponse.Responses) > 0 {
						receivedAnswer = args.InfoResponse.Responses[0]
					}
					mu.Unlock()
					if len(args.InfoResponse.Responses) > 0 && args.InfoResponse.Responses[0] == expectedAnswer {
						args.AuthenticationResult = true
					}
					return
				}
				// First call: send a prompt.
				args.InfoRequest = &messages.AuthenticationInfoRequestMessage{
					Name:        "Test Auth",
					Instruction: "Please answer the question",
					Prompts: []messages.AuthenticationInfoRequestPrompt{
						{Prompt: "What is the secret? ", Echo: false},
					},
				}
				return
			}
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
		t.Fatal("Authenticate returned false, want true for keyboard-interactive")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAnswer != expectedAnswer {
		t.Errorf("server received answer %q, want %q", receivedAnswer, expectedAnswer)
	}
}
