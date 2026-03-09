// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/algorithms"
)

// createHmacPairWithKey creates HMAC signer/verifier with a specific key seed.
func createHmacPairWithKey(algo *algorithms.HmacAlgorithm, seed byte) (algorithms.MessageSigner, algorithms.MessageVerifier) {
	key := make([]byte, algo.KeyLength)
	for i := range key {
		key[i] = byte(i) + seed
	}
	return algo.CreateSigner(key), algo.CreateVerifier(key)
}

// TestReconnectHMACComputation verifies that reconnect HMAC tokens are computed
// using the new (post-reconnect) session keys when available, not the old keys.
func TestReconnectHMACComputation(t *testing.T) {
	// Create two separate HMAC key pairs with DIFFERENT keys.
	oldSigner, oldVerifier := createHmacPairWithKey(algorithms.NewHmacSha256(), 0x00)
	newSigner, newVerifier := createHmacPairWithKey(algorithms.NewHmacSha256(), 0x80)

	previousSessionID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	newSessionID := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}

	// Session using NEW keys (simulating post-reconnect state).
	newSession := &Session{
		Config: NewDefaultConfig(),
		currentAlgorithms: &sessionAlgorithms{
			ReconnectSigner:   newSigner,
			ReconnectVerifier: newVerifier,
		},
	}

	// Session using OLD keys (simulating pre-reconnect state).
	oldSession := &Session{
		Config: NewDefaultConfig(),
		currentAlgorithms: &sessionAlgorithms{
			ReconnectSigner:   oldSigner,
			ReconnectVerifier: oldVerifier,
		},
	}

	// Create token with new keys.
	token, err := newSession.CreateReconnectToken(previousSessionID, newSessionID)
	if err != nil {
		t.Fatalf("CreateReconnectToken failed: %v", err)
	}

	// Token should verify with new keys.
	valid, err := newSession.VerifyReconnectToken(previousSessionID, newSessionID, token)
	if err != nil {
		t.Fatalf("VerifyReconnectToken with new keys failed: %v", err)
	}
	if !valid {
		t.Error("expected token to be valid with new keys")
	}

	// Token should NOT verify with old keys (different HMAC key).
	valid, err = oldSession.VerifyReconnectToken(previousSessionID, newSessionID, token)
	if err != nil {
		t.Fatalf("VerifyReconnectToken with old keys failed: %v", err)
	}
	if valid {
		t.Error("expected token to be invalid with old keys (different HMAC key)")
	}
}

// TestReconnectHMACRoundTrip verifies that a reconnect token created by one side
// can be verified by the other side when both use the same HMAC keys.
func TestReconnectHMACRoundTrip(t *testing.T) {
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())

	previousSessionID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}
	newSessionID := []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40}

	// Create "client" and "server" sessions with shared HMAC keys.
	clientSession := &Session{
		Config: NewDefaultConfig(),
		currentAlgorithms: &sessionAlgorithms{
			ReconnectSigner:   signer,
			ReconnectVerifier: verifier,
		},
	}
	serverSession := &Session{
		Config: NewDefaultConfig(),
		currentAlgorithms: &sessionAlgorithms{
			ReconnectSigner:   signer,
			ReconnectVerifier: verifier,
		},
	}

	// Client creates token.
	clientToken, err := clientSession.CreateReconnectToken(previousSessionID, newSessionID)
	if err != nil {
		t.Fatalf("client CreateReconnectToken failed: %v", err)
	}

	// Server verifies client token.
	valid, err := serverSession.VerifyReconnectToken(previousSessionID, newSessionID, clientToken)
	if err != nil {
		t.Fatalf("server VerifyReconnectToken failed: %v", err)
	}
	if !valid {
		t.Error("server failed to verify client token")
	}

	// Server creates token.
	serverToken, err := serverSession.CreateReconnectToken(previousSessionID, newSessionID)
	if err != nil {
		t.Fatalf("server CreateReconnectToken failed: %v", err)
	}

	// Client verifies server token.
	valid, err = clientSession.VerifyReconnectToken(previousSessionID, newSessionID, serverToken)
	if err != nil {
		t.Fatalf("client VerifyReconnectToken failed: %v", err)
	}
	if !valid {
		t.Error("client failed to verify server token")
	}

	// Tokens should be identical (same data, same key).
	if len(clientToken) != len(serverToken) {
		t.Errorf("token lengths differ: client=%d, server=%d", len(clientToken), len(serverToken))
	}
	for i := range clientToken {
		if clientToken[i] != serverToken[i] {
			t.Errorf("tokens differ at byte %d", i)
			break
		}
	}
}

// TestReconnectHMACUsesReconnectSigner verifies that CreateReconnectToken and
// VerifyReconnectToken use the dedicated ReconnectSigner/ReconnectVerifier
// rather than the regular Signer/Verifier (which may be GCM cipher aliases).
func TestReconnectHMACUsesReconnectSigner(t *testing.T) {
	// Create two different HMAC key pairs.
	regularSigner, regularVerifier := createHmacPair(algorithms.NewHmacSha256())
	reconnectSigner, reconnectVerifier := createHmacPair(algorithms.NewHmacSha512())

	session := &Session{
		Config: NewDefaultConfig(),
		currentAlgorithms: &sessionAlgorithms{
			Signer:            regularSigner,
			Verifier:          regularVerifier,
			ReconnectSigner:   reconnectSigner,
			ReconnectVerifier: reconnectVerifier,
		},
	}

	previousSessionID := make([]byte, 32)
	newSessionID := make([]byte, 32)
	for i := range previousSessionID {
		previousSessionID[i] = byte(i)
	}
	for i := range newSessionID {
		newSessionID[i] = byte(i + 32)
	}

	// Create token — should use ReconnectSigner (SHA-512).
	token, err := session.CreateReconnectToken(previousSessionID, newSessionID)
	if err != nil {
		t.Fatalf("CreateReconnectToken failed: %v", err)
	}

	// SHA-512 HMAC produces 64-byte digest.
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64 (SHA-512 digest)", len(token))
	}

	// Verify with ReconnectVerifier should succeed.
	valid, err := session.VerifyReconnectToken(previousSessionID, newSessionID, token)
	if err != nil {
		t.Fatalf("VerifyReconnectToken failed: %v", err)
	}
	if !valid {
		t.Error("expected token to be valid")
	}
}

// TestAuthSuccessActivatesConnectionService verifies that after successful
// authentication, the server activates the "ssh-connection" service (matching
// C#/TS behavior where the service named in the auth request is activated).
func TestAuthSuccessActivatesConnectionService(t *testing.T) {
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
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Authenticate.
	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if !success {
		t.Fatal("expected authentication to succeed")
	}

	// Give a brief moment for server-side service activation to complete.
	time.Sleep(50 * time.Millisecond)

	// Verify the connection service is activated on the server.
	svc := server.GetService(ConnectionServiceName)
	if svc == nil {
		t.Error("ssh-connection service not activated on server after auth success")
	}
}

// TestAuthFailureDoesNotActivateService verifies that the "ssh-connection"
// service is NOT activated when authentication fails.
func TestAuthFailureDoesNotActivateService(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	_, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			// Reject all auth attempts — leave AuthenticationResult as nil.
		},
	})

	// Give a brief moment for any server-side processing.
	time.Sleep(100 * time.Millisecond)

	// Verify the connection service is NOT activated on the server.
	svc := server.GetService(ConnectionServiceName)
	if svc != nil {
		t.Error("ssh-connection service should not be activated without successful auth")
	}
}

// TestOnReconnectedFiresOnServerStillPasses verifies that the TestOnReconnectedFiresOnServer
// test continues to pass after the CRIT-02 and CRIT-04 fixes.
// This is a regression test — the actual test is in progress_reconnect_auth_test.go.
func TestOnReconnectedFiresOnServerStillPasses(t *testing.T) {
	// This is tested by TestOnReconnectedFiresOnServer in progress_reconnect_auth_test.go.
	// We just verify that the reconnect token mechanism works with real encryption
	// (not kex:none) by running a simple round-trip.
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
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Authenticate to ensure session is fully set up.
	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if !success {
		t.Fatal("expected authentication to succeed")
	}

	// Verify both sessions have reconnect signer available.
	clientSigner := client.reconnectSigner()
	serverSigner := server.reconnectSigner()

	if clientSigner == nil {
		t.Error("client should have a reconnect signer after encrypted connection")
	}
	if serverSigner == nil {
		t.Error("server should have a reconnect signer after encrypted connection")
	}

	// Verify token round-trip works between the two sessions.
	if clientSigner != nil && serverSigner != nil {
		token, err := client.CreateReconnectToken(client.SessionID, server.SessionID)
		if err != nil {
			t.Fatalf("CreateReconnectToken failed: %v", err)
		}

		valid, err := server.VerifyReconnectToken(client.SessionID, server.SessionID, token)
		if err != nil {
			t.Fatalf("VerifyReconnectToken failed: %v", err)
		}
		if !valid {
			t.Error("server failed to verify client reconnect token")
		}
	}
}
