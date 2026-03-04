// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"
)

// SessionPairOptions configures a session pair created by createSessionPair.
type SessionPairOptions struct {
	// ClientConfig overrides the client session configuration.
	// If nil, NewNoSecurityConfig() is used.
	ClientConfig *SessionConfig

	// ServerConfig overrides the server session configuration.
	// If nil, NewNoSecurityConfig() is used.
	ServerConfig *SessionConfig

	// ServerCredentials sets credentials on the server session.
	ServerCredentials *ServerCredentials

	// ServerOnAuthenticating overrides the server's OnAuthenticating callback.
	// If nil, a default callback that approves all authentication is used.
	ServerOnAuthenticating func(*AuthenticatingEventArgs)

	// ClientOnAuthenticating overrides the client's OnAuthenticating callback.
	// If nil, a default callback that approves all authentication is used.
	ClientOnAuthenticating func(*AuthenticatingEventArgs)

	// ClientTrace sets the Trace callback on the client session.
	ClientTrace TraceFunc

	// ServerTrace sets the Trace callback on the server session.
	ServerTrace TraceFunc

	// ConnectTimeout overrides the connection timeout. Default is 30s.
	ConnectTimeout time.Duration
}

// createSessionPair creates a connected client/server session pair over io.Pipe.
// Both sessions are connected and ready to use when this function returns.
// The sessions are automatically closed when the test ends via t.Cleanup.
//
// If opts is nil, default options are used (no-security config, auto-approve auth).
func createSessionPair(t *testing.T, opts *SessionPairOptions) (*ClientSession, *ServerSession) {
	t.Helper()

	if opts == nil {
		opts = &SessionPairOptions{}
	}

	clientConfig := opts.ClientConfig
	if clientConfig == nil {
		clientConfig = NewNoSecurityConfig()
	}
	serverConfig := opts.ServerConfig
	if serverConfig == nil {
		serverConfig = NewNoSecurityConfig()
	}

	clientStream, serverStream := duplexPipe()

	client := NewClientSession(clientConfig)
	if opts.ClientTrace != nil {
		client.Trace = opts.ClientTrace
	}
	if opts.ClientOnAuthenticating != nil {
		client.OnAuthenticating = opts.ClientOnAuthenticating
	} else {
		client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		}
	}

	server := NewServerSession(serverConfig)
	if opts.ServerTrace != nil {
		server.Trace = opts.ServerTrace
	}
	if opts.ServerCredentials != nil {
		server.Credentials = opts.ServerCredentials
	}
	if opts.ServerOnAuthenticating != nil {
		server.OnAuthenticating = opts.ServerOnAuthenticating
	} else {
		server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		}
	}

	// Use 30s timeout to avoid flakiness under -race with real crypto (RSA).
	connectTimeout := 30 * time.Second
	if opts.ConnectTimeout > 0 {
		connectTimeout = opts.ConnectTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	var wg sync.WaitGroup
	var clientErr, serverErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = client.Connect(ctx, clientStream)
	}()
	go func() {
		defer wg.Done()
		serverErr = server.Connect(ctx, serverStream)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server connect failed: %v", serverErr)
	}

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	return client, server
}

// TestSessionPairSmokeTest verifies that createSessionPair produces two
// connected sessions with default (no-security) config.
func TestSessionPairSmokeTest(t *testing.T) {
	client, server := createSessionPair(t, nil)

	if !client.IsConnected() {
		t.Error("client IsConnected() = false, want true")
	}
	if !server.IsConnected() {
		t.Error("server IsConnected() = false, want true")
	}
	if client.IsClosed() {
		t.Error("client IsClosed() = true, want false")
	}
	if server.IsClosed() {
		t.Error("server IsClosed() = true, want false")
	}
}
