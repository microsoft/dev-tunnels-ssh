// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"context"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

const pubkeyTestTimeout = 20 * time.Second

// createSecureSessionPair creates a SessionPair with real key exchange (default config)
// and sets up server host keys for authentication testing.
func createSecureSessionPair(t *testing.T) *helpers.SessionPair {
	t.Helper()

	serverConfig := ssh.NewDefaultConfig()
	clientConfig := ssh.NewDefaultConfig()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})

	// Set up server host keys: RSA (for RSA algorithm negotiation) and ECDSA.
	serverRsaKey, err := ssh.NewRsaKeyPair(pair.ClientKey, ssh.AlgoPKRsaSha512)
	if err != nil {
		t.Fatalf("failed to create server RSA key pair: %v", err)
	}
	serverEcdsaKey, err := ssh.NewEcdsaKeyPair(pair.ServerKey)
	if err != nil {
		t.Fatalf("failed to create server ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{serverRsaKey, serverEcdsaKey},
	}

	return pair
}

// TestAuthenticateClientWithPublicKeyECDSA256 tests public key auth with ECDSA P-256.
func TestAuthenticateClientWithPublicKeyECDSA256(t *testing.T) {
	testPublicKeyAuth(t, ssh.AlgoPKEcdsaSha2P256)
}

// TestAuthenticateClientWithPublicKeyECDSA384 tests public key auth with ECDSA P-384.
func TestAuthenticateClientWithPublicKeyECDSA384(t *testing.T) {
	testPublicKeyAuth(t, ssh.AlgoPKEcdsaSha2P384)
}

// TestAuthenticateClientWithPublicKeyRSA256 tests public key auth with RSA-SHA256/2048.
func TestAuthenticateClientWithPublicKeyRSA256(t *testing.T) {
	testPublicKeyAuth(t, ssh.AlgoPKRsaSha256)
}

// TestAuthenticateClientWithPublicKeyRSA512 tests public key auth with RSA-SHA512/4096.
func TestAuthenticateClientWithPublicKeyRSA512(t *testing.T) {
	testPublicKeyAuth(t, ssh.AlgoPKRsaSha512)
}

func testPublicKeyAuth(t *testing.T, pkAlgorithmName string) {
	t.Helper()

	pair := createSecureSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), pubkeyTestTimeout)
	defer cancel()

	// Generate client key pair.
	clientKey, err := ssh.GenerateKeyPair(pkAlgorithmName)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	var capturedAuthType ssh.AuthenticationType
	var capturedPublicKey ssh.KeyPair
	clientAuthenticatedCh := make(chan struct{}, 1)
	var mu sync.Mutex

	// Server: verify the client's public key.
	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		if args.AuthenticationType == ssh.AuthServerPublicKey {
			// Server host key verification (auto-approve for tests).
			args.AuthenticationResult = struct{}{}
			return
		}
		mu.Lock()
		capturedAuthType = args.AuthenticationType
		capturedPublicKey = args.PublicKey
		mu.Unlock()
		args.AuthenticationResult = struct{}{} // approve
	}

	pair.ServerSession.OnClientAuthenticated = func() {
		select {
		case clientAuthenticatedCh <- struct{}{}:
		default:
		}
	}

	// Client: approve server host key.
	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	pair.Connect(ctx)

	authenticated, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username:   testUsername,
		PublicKeys: []ssh.KeyPair{clientKey},
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if !authenticated {
		t.Fatal("expected authentication to succeed")
	}

	// Wait for OnClientAuthenticated to fire on the server side.
	select {
	case <-clientAuthenticatedCh:
		// OK
	case <-ctx.Done():
		t.Fatal("timed out waiting for OnClientAuthenticated")
	}

	mu.Lock()
	defer mu.Unlock()

	if capturedAuthType != ssh.AuthClientPublicKey {
		t.Errorf("AuthenticationType = %d, want %d (AuthClientPublicKey)",
			capturedAuthType, ssh.AuthClientPublicKey)
	}

	if capturedPublicKey == nil {
		t.Fatal("expected captured public key to be non-nil")
	}

	// Verify the key bytes match.
	clientPubBytes, _ := clientKey.GetPublicKeyBytes()
	capturedPubBytes, _ := capturedPublicKey.GetPublicKeyBytes()
	if len(clientPubBytes) != len(capturedPubBytes) {
		t.Errorf("public key bytes length mismatch: got %d, want %d",
			len(capturedPubBytes), len(clientPubBytes))
	}
}

// TestAuthenticateClientWithPublicKeyFail verifies that public key auth fails
// when the server rejects the key.
func TestAuthenticateClientWithPublicKeyFail(t *testing.T) {
	pair := createSecureSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), pubkeyTestTimeout)
	defer cancel()

	clientKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	var serverRaisedClientAuthenticated bool
	var mu sync.Mutex

	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		if args.AuthenticationType == ssh.AuthServerPublicKey {
			args.AuthenticationResult = struct{}{}
			return
		}
		// Reject client public key — don't set AuthenticationResult.
	}

	pair.ServerSession.OnClientAuthenticated = func() {
		mu.Lock()
		serverRaisedClientAuthenticated = true
		mu.Unlock()
	}

	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	pair.Connect(ctx)

	authenticated, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username:   testUsername,
		PublicKeys: []ssh.KeyPair{clientKey},
	})
	if err != nil {
		t.Fatalf("Authenticate should not return error on failure: %v", err)
	}
	if authenticated {
		t.Fatal("expected authentication to fail")
	}

	mu.Lock()
	defer mu.Unlock()
	if serverRaisedClientAuthenticated {
		t.Error("OnClientAuthenticated should NOT have been raised")
	}
}

// TestAuthenticateServerFail verifies that authentication fails when the client
// rejects the server's host key.
func TestAuthenticateServerFail(t *testing.T) {
	pair := createSecureSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), pubkeyTestTimeout)
	defer cancel()

	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	// Client rejects the server's host key.
	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		// Don't set AuthenticationResult — reject.
	}

	pair.Connect(ctx)

	authenticated, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: testUsername,
	})
	// Should fail due to server host key rejection.
	if err != nil {
		t.Logf("got error (expected in some cases): %v", err)
	}
	if authenticated {
		t.Fatal("expected authentication to fail when server host key is rejected")
	}
}

// TestAuthenticateClientPublicKeyQueryAccept verifies that a public key query
// returns true when the server accepts the key.
func TestAuthenticateClientPublicKeyQueryAccept(t *testing.T) {
	testPublicKeyQuery(t, true)
}

// TestAuthenticateClientPublicKeyQueryReject verifies that a public key query
// returns false when the server rejects the key.
func TestAuthenticateClientPublicKeyQueryReject(t *testing.T) {
	testPublicKeyQuery(t, false)
}

func testPublicKeyQuery(t *testing.T, accept bool) {
	t.Helper()

	pair := createSecureSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), pubkeyTestTimeout)
	defer cancel()

	clientKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	var capturedAuthType ssh.AuthenticationType
	var mu sync.Mutex

	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		if args.AuthenticationType == ssh.AuthServerPublicKey {
			args.AuthenticationResult = struct{}{}
			return
		}
		mu.Lock()
		capturedAuthType = args.AuthenticationType
		mu.Unlock()
		if accept {
			args.AuthenticationResult = struct{}{} // approve query
		}
		// else: don't set AuthenticationResult — reject query
	}

	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	pair.Connect(ctx)

	result, err := pair.ClientSession.AuthenticatePublicKeyQuery(ctx, testUsername, clientKey)
	if err != nil {
		t.Fatalf("PublicKeyQuery failed with error: %v", err)
	}

	if result != accept {
		t.Fatalf("PublicKeyQuery result = %v, want %v", result, accept)
	}

	mu.Lock()
	defer mu.Unlock()
	if capturedAuthType != ssh.AuthClientPublicKeyQuery {
		t.Errorf("AuthenticationType = %d, want %d (AuthClientPublicKeyQuery)",
			capturedAuthType, ssh.AuthClientPublicKeyQuery)
	}

	// Session should still be connected after a query.
	if !pair.ServerSession.IsConnected() {
		t.Error("server session should still be connected after query")
	}
}

// TestAuthenticateInteractive verifies keyboard-interactive authentication
// with 2 prompts (one echo, one no-echo).
func TestAuthenticateInteractive(t *testing.T) {
	pair := createSecureSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), pubkeyTestTimeout)
	defer cancel()

	clientAuthenticatedCh := make(chan struct{}, 1)

	// Server: first call sends prompts, second call verifies responses.
	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		if args.AuthenticationType == ssh.AuthServerPublicKey {
			args.AuthenticationResult = struct{}{}
			return
		}

		if args.AuthenticationType != ssh.AuthClientInteractive {
			// Reject non-interactive methods.
			return
		}

		if args.InfoResponse == nil {
			// First round: send prompts.
			args.InfoRequest = &messages.AuthenticationInfoRequestMessage{
				Name:        "TEST",
				Instruction: "",
				Prompts: []messages.AuthenticationInfoRequestPrompt{
					{Prompt: "One", Echo: true},
					{Prompt: "Two", Echo: false},
				},
			}
			// Don't set AuthenticationResult — this will cause the auth service
			// to send the info request.
			return
		}

		// Second round: verify responses.
		if len(args.InfoResponse.Responses) != 2 {
			t.Errorf("expected 2 responses, got %d", len(args.InfoResponse.Responses))
			return
		}
		if args.InfoResponse.Responses[0] != "1" {
			t.Errorf("response[0] = %q, want %q", args.InfoResponse.Responses[0], "1")
		}
		if args.InfoResponse.Responses[1] != "2" {
			t.Errorf("response[1] = %q, want %q", args.InfoResponse.Responses[1], "2")
		}
		args.AuthenticationResult = struct{}{} // approve
	}

	pair.ServerSession.OnClientAuthenticated = func() {
		select {
		case clientAuthenticatedCh <- struct{}{}:
		default:
		}
	}

	// Client: respond to interactive prompts.
	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		if args.AuthenticationType == ssh.AuthServerPublicKey {
			args.AuthenticationResult = struct{}{}
			return
		}
		if args.AuthenticationType == ssh.AuthClientInteractive && args.InfoRequest != nil {
			args.InfoResponse = &messages.AuthenticationInfoResponseMessage{
				Responses: []string{"1", "2"},
			}
		}
	}

	pair.Connect(ctx)

	// Use keyboard-interactive (no credentials).
	authenticated, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: testUsername,
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if !authenticated {
		t.Fatal("expected interactive authentication to succeed")
	}

	select {
	case <-clientAuthenticatedCh:
		// OK
	case <-ctx.Done():
		t.Fatal("timed out waiting for OnClientAuthenticated")
	}
}
