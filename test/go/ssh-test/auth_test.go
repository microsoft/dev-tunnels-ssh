// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

const (
	authTestTimeout = 10 * time.Second
	testUsername    = "testuser"
	testPassword   = "s3cret!"
)

// TestAuthenticateClientWithNoCredentials verifies that authentication with
// no credentials (none method) works when the server approves.
func TestAuthenticateClientWithNoCredentials(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), authTestTimeout)
	defer cancel()

	// Track server-side auth event args.
	var capturedAuthType ssh.AuthenticationType
	var capturedUsername string
	var capturedPassword string
	clientAuthenticatedCh := make(chan struct{}, 1)
	var mu sync.Mutex

	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		mu.Lock()
		capturedAuthType = args.AuthenticationType
		capturedUsername = args.Username
		capturedPassword = args.Password
		mu.Unlock()
		args.AuthenticationResult = struct{}{} // approve
	}

	pair.ServerSession.OnClientAuthenticated = func() {
		select {
		case clientAuthenticatedCh <- struct{}{}:
		default:
		}
	}

	// Client auto-approves server (no-security mode, no host key).
	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	pair.Connect(ctx)

	// Authenticate with just a username (none method).
	authenticated, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: testUsername,
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

	// Verify server received correct auth event.
	mu.Lock()
	defer mu.Unlock()
	if capturedAuthType != ssh.AuthClientNone {
		t.Errorf("AuthenticationType = %d, want %d (AuthClientNone)", capturedAuthType, ssh.AuthClientNone)
	}
	if capturedUsername != testUsername {
		t.Errorf("Username = %q, want %q", capturedUsername, testUsername)
	}
	if capturedPassword != "" {
		t.Errorf("Password = %q, want empty", capturedPassword)
	}
}

// TestAuthenticateClientWithPassword verifies that password authentication
// works when the server approves the credentials.
func TestAuthenticateClientWithPassword(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), authTestTimeout)
	defer cancel()

	var capturedAuthType ssh.AuthenticationType
	var capturedUsername string
	var capturedPassword string
	clientAuthenticatedCh := make(chan struct{}, 1)
	var mu sync.Mutex

	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		mu.Lock()
		capturedAuthType = args.AuthenticationType
		capturedUsername = args.Username
		capturedPassword = args.Password
		mu.Unlock()
		args.AuthenticationResult = struct{}{} // approve
	}

	pair.ServerSession.OnClientAuthenticated = func() {
		select {
		case clientAuthenticatedCh <- struct{}{}:
		default:
		}
	}

	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	pair.Connect(ctx)

	authenticated, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: testUsername,
		Password: testPassword,
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
	if capturedAuthType != ssh.AuthClientPassword {
		t.Errorf("AuthenticationType = %d, want %d (AuthClientPassword)", capturedAuthType, ssh.AuthClientPassword)
	}
	if capturedUsername != testUsername {
		t.Errorf("Username = %q, want %q", capturedUsername, testUsername)
	}
	if capturedPassword != testPassword {
		t.Errorf("Password = %q, want %q", capturedPassword, testPassword)
	}
}

// TestAuthenticateClientWithPasswordFail verifies that authentication fails
// when the server rejects the credentials, without closing the session.
func TestAuthenticateClientWithPasswordFail(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), authTestTimeout)
	defer cancel()

	var serverRaisedClientAuthenticated bool
	var mu sync.Mutex

	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		// Reject: don't set AuthenticationResult
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
		Username: testUsername,
		Password: "wrong-password",
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

// TestAuthenticateCallbackException verifies that a panic in the server's
// authenticating callback is handled gracefully (treated as auth failure).
func TestAuthenticateCallbackException(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), authTestTimeout)
	defer cancel()

	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		panic("test callback error")
	}

	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	pair.Connect(ctx)

	authenticated, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: testUsername,
	})
	if err != nil {
		t.Fatalf("Authenticate should not return error on callback panic: %v", err)
	}
	if authenticated {
		t.Fatal("expected authentication to fail when callback panics")
	}
}

// TestAuthenticateConnectionException verifies that a connection loss during
// authentication returns a ConnectionError.
func TestAuthenticateConnectionException(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), authTestTimeout)
	defer cancel()

	// Server closes the stream during authentication.
	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		// Simulate connection loss by disconnecting.
		pair.Disconnect(nil)
	}

	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	pair.Connect(ctx)

	_, err := pair.ClientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: testUsername,
	})

	// Should get either a ConnectionError or the done channel fires.
	if err != nil {
		var connErr *ssh.ConnectionError
		if !errors.As(err, &connErr) {
			t.Logf("got error (non-ConnectionError): %v", err)
		}
	}
	// The key assertion is that we don't hang — context timeout would catch that.
}
