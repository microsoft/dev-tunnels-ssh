// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// TestPrincipalSetAfterAuth verifies that after successful authentication,
// session.Principal is set to the AuthenticationResult value from the
// OnAuthenticating handler.
func TestPrincipalSetAfterAuth(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	type userIdentity struct {
		Username string
		Role     string
	}
	expectedPrincipal := &userIdentity{Username: "testuser", Role: "admin"}

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = expectedPrincipal
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "testpass",
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false")
	}

	// Give a short time for the server to process auth and set Principal.
	time.Sleep(100 * time.Millisecond)

	server.Session.mu.Lock()
	principal := server.Session.Principal
	server.Session.mu.Unlock()

	if principal == nil {
		t.Fatal("server session.Principal is nil after authentication")
	}

	identity, ok := principal.(*userIdentity)
	if !ok {
		t.Fatalf("server session.Principal type = %T, want *userIdentity", principal)
	}
	if identity.Username != expectedPrincipal.Username {
		t.Errorf("Principal.Username = %q, want %q", identity.Username, expectedPrincipal.Username)
	}
	if identity.Role != expectedPrincipal.Role {
		t.Errorf("Principal.Role = %q, want %q", identity.Role, expectedPrincipal.Role)
	}
}

// TestPrincipalInRequestEventArgs verifies that when a session request is sent
// after authentication, the RequestEventArgs.Principal matches the authenticated
// principal on the server session.
func TestPrincipalInRequestEventArgs(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	expectedPrincipal := "user-identity-42"

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = expectedPrincipal
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "testpass",
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false")
	}

	// Set up the server to handle session requests and capture the principal.
	var receivedPrincipal interface{}
	var requestReceived bool
	var mu sync.Mutex
	requestDone := make(chan struct{})

	server.SetRequestHandler(func(args *RequestEventArgs) {
		mu.Lock()
		receivedPrincipal = args.Principal
		requestReceived = true
		mu.Unlock()
		args.IsAuthorized = true
		close(requestDone)
	})

	// Send a session request from client.
	reqMsg := &messages.SessionRequestMessage{
		RequestType: "test-request",
		WantReply:   true,
	}
	ok, err := client.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("Request error: %v", err)
	}
	if !ok {
		t.Fatal("Request returned false, want true")
	}

	select {
	case <-requestDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to receive request")
	}

	mu.Lock()
	defer mu.Unlock()
	if !requestReceived {
		t.Fatal("server did not receive the request")
	}
	if receivedPrincipal != expectedPrincipal {
		t.Errorf("RequestEventArgs.Principal = %v, want %v", receivedPrincipal, expectedPrincipal)
	}
}

// TestPrincipalNilBeforeAuth verifies that session.Principal is nil
// before authentication completes.
func TestPrincipalNilBeforeAuth(t *testing.T) {
	// Use a no-security config so we can check the session state before auth.
	client, server := createSessionPair(t, nil)

	// Before authentication, Principal should be nil on both sides.
	client.Session.mu.Lock()
	clientPrincipal := client.Session.Principal
	client.Session.mu.Unlock()

	server.Session.mu.Lock()
	serverPrincipal := server.Session.Principal
	server.Session.mu.Unlock()

	if clientPrincipal != nil {
		t.Errorf("client session.Principal = %v before auth, want nil", clientPrincipal)
	}
	if serverPrincipal != nil {
		t.Errorf("server session.Principal = %v before auth, want nil", serverPrincipal)
	}
}
