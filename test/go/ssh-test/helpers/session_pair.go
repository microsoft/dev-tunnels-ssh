// Copyright (c) Microsoft Corporation. All rights reserved.

package helpers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// SessionPair creates and manages a pair of connected SSH sessions for testing.
// It provides convenience methods for connecting sessions over in-memory streams,
// opening channels, simulating disconnections, and cleaning up resources.
type SessionPair struct {
	// ClientSession is the SSH client session.
	ClientSession *ssh.ClientSession

	// ServerSession is the SSH server session.
	ServerSession *ssh.ServerSession

	// ClientStream is the mock network stream for the client side.
	ClientStream *MockNetworkStream

	// ServerStream is the mock network stream for the server side.
	ServerStream *MockNetworkStream

	// ClientKey is the RSA private key for the client.
	ClientKey *rsa.PrivateKey

	// ServerKey is the ECDSA private key for the server.
	ServerKey *ecdsa.PrivateKey

	t      *testing.T
	config *SessionPairConfig
}

// SessionPairConfig provides configuration options for creating a SessionPair.
type SessionPairConfig struct {
	// ServerConfig overrides the default server session configuration.
	ServerConfig *ssh.SessionConfig

	// ClientConfig overrides the default client session configuration.
	ClientConfig *ssh.SessionConfig

	// ServerCredentials sets credentials on the server session.
	ServerCredentials *ssh.ServerCredentials

	// ServerOnAuthenticating overrides the server's OnAuthenticating callback.
	// If nil, a default callback that approves all authentication is used.
	ServerOnAuthenticating func(*ssh.AuthenticatingEventArgs)

	// ClientOnAuthenticating overrides the client's OnAuthenticating callback.
	// If nil, a default callback that approves all authentication is used.
	ClientOnAuthenticating func(*ssh.AuthenticatingEventArgs)

	// ClientTrace sets the Trace callback on the client session.
	ClientTrace ssh.TraceFunc

	// ServerTrace sets the Trace callback on the server session.
	ServerTrace ssh.TraceFunc

	// ConnectTimeout overrides the connection timeout. Default is 30s.
	ConnectTimeout time.Duration
}

// NewSessionPair creates a new SessionPair with no-security configuration.
// The pair generates test keys, creates client and server sessions, and
// sets up auto-approval authentication handlers on both sides.
func NewSessionPair(t *testing.T) *SessionPair {
	return NewSessionPairWithConfig(t, nil)
}

// NewSessionPairWithConfig creates a new SessionPair with custom configuration.
// Pass nil for default no-security config.
func NewSessionPairWithConfig(t *testing.T, config *SessionPairConfig) *SessionPair {
	t.Helper()

	if config == nil {
		config = &SessionPairConfig{}
	}

	serverConfig := config.ServerConfig
	if serverConfig == nil {
		serverConfig = ssh.NewNoSecurityConfig()
	}

	clientConfig := config.ClientConfig
	if clientConfig == nil {
		clientConfig = ssh.NewNoSecurityConfig()
	}

	// Generate test keys.
	clientKey, err := rsa.GenerateKey(rand.Reader, TestKeySize)
	if err != nil {
		t.Fatalf("failed to generate client RSA key: %v", err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server ECDSA key: %v", err)
	}

	// Create sessions.
	clientSession := ssh.NewClientSession(clientConfig)
	if config.ClientTrace != nil {
		clientSession.Trace = config.ClientTrace
	}
	if config.ClientOnAuthenticating != nil {
		clientSession.OnAuthenticating = config.ClientOnAuthenticating
	} else {
		clientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
			args.AuthenticationResult = struct{}{} // non-nil = success
		}
	}

	serverSession := ssh.NewServerSession(serverConfig)
	if config.ServerTrace != nil {
		serverSession.Trace = config.ServerTrace
	}
	if config.ServerCredentials != nil {
		serverSession.Credentials = config.ServerCredentials
	}
	if config.ServerOnAuthenticating != nil {
		serverSession.OnAuthenticating = config.ServerOnAuthenticating
	} else {
		serverSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
			args.AuthenticationResult = struct{}{} // non-nil = success
		}
	}

	return &SessionPair{
		ClientSession: clientSession,
		ServerSession: serverSession,
		ClientKey:     clientKey,
		ServerKey:     serverKey,
		t:             t,
		config:        config,
	}
}

// CreateStreams creates duplex streams and wraps them in MockNetworkStreams.
// This sets up the ClientStream and ServerStream fields.
// Call this before Connect if you need access to the streams before connecting.
func (p *SessionPair) CreateStreams() {
	p.t.Helper()

	s1, s2 := CreateDuplexStreams()
	p.ClientStream = NewMockNetworkStream(s1)
	p.ServerStream = NewMockNetworkStream(s2)
}

// Disconnect simulates a network disconnection on both streams.
// If err is nil, the default mock disconnect error is used.
func (p *SessionPair) Disconnect(err error) {
	if p.ClientStream != nil {
		p.ClientStream.MockDisconnect(err)
	}
	if p.ServerStream != nil {
		p.ServerStream.MockDisconnect(err)
	}
}

// DisconnectWithDrop simulates a network disconnection that drops a specified
// number of bytes before the error manifests.
func (p *SessionPair) DisconnectWithDrop(err error, dropBytes int) {
	if p.ClientStream != nil {
		p.ClientStream.MockDisconnectWithDrop(err, dropBytes)
	}
	if p.ServerStream != nil {
		p.ServerStream.MockDisconnectWithDrop(err, dropBytes)
	}
}

// Connect creates streams (if not already created) and connects both sessions.
// Both sessions perform version exchange and key exchange init concurrently.
func (p *SessionPair) Connect(ctx context.Context) {
	p.t.Helper()

	if p.ClientStream == nil {
		p.CreateStreams()
	}

	var wg sync.WaitGroup
	var clientErr, serverErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		serverErr = p.ServerSession.Connect(ctx, p.ServerStream)
	}()
	go func() {
		defer wg.Done()
		clientErr = p.ClientSession.Connect(ctx, p.ClientStream)
	}()

	wg.Wait()

	if clientErr != nil {
		p.t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		p.t.Fatalf("server connect failed: %v", serverErr)
	}
}

// OpenChannel opens a channel from the client side and accepts it on the server side.
// Returns the client channel and server channel.
func (p *SessionPair) OpenChannel(ctx context.Context) (*ssh.Channel, *ssh.Channel) {
	p.t.Helper()

	var clientChannel, serverChannel *ssh.Channel
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientChannel, clientErr = p.ClientSession.OpenChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		serverChannel, serverErr = p.ServerSession.AcceptChannel(ctx)
	}()

	wg.Wait()

	if clientErr != nil {
		p.t.Fatalf("client open channel failed: %v", clientErr)
	}
	if serverErr != nil {
		p.t.Fatalf("server accept channel failed: %v", serverErr)
	}

	return clientChannel, serverChannel
}

// Close cleans up all resources associated with the session pair.
// It closes sessions first (sending disconnect messages), then closes streams.
func (p *SessionPair) Close() {
	if p.ClientSession != nil && p.ClientSession.IsConnected() {
		p.ClientSession.Close()
	}
	if p.ServerSession != nil && p.ServerSession.IsConnected() {
		p.ServerSession.Close()
	}
	if p.ClientStream != nil {
		p.ClientStream.Close()
	}
	if p.ServerStream != nil {
		p.ServerStream.Close()
	}
}

// CreateConnectedSessionPair creates a connected client/server session pair
// matching the internal createSessionPair helper. Both sessions are connected
// and ready to use. Sessions are auto-closed via t.Cleanup.
func CreateConnectedSessionPair(t *testing.T, config *SessionPairConfig) (*ssh.ClientSession, *ssh.ServerSession) {
	t.Helper()

	pair := NewSessionPairWithConfig(t, config)

	connectTimeout := 30 * time.Second
	if config != nil && config.ConnectTimeout > 0 {
		connectTimeout = config.ConnectTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	pair.Connect(ctx)

	t.Cleanup(func() {
		pair.Close()
	})

	return pair.ClientSession, pair.ServerSession
}

// CreateMultiChannelStreamPair creates a connected client/server
// MultiChannelStream pair over in-memory pipes for testing.
// Both streams are connected and ready to use. Cleaned up via t.Cleanup.
func CreateMultiChannelStreamPair(t *testing.T) (*ssh.MultiChannelStream, *ssh.MultiChannelStream) {
	t.Helper()

	s1, s2 := CreateDuplexStreams()

	client := ssh.NewMultiChannelStream(s1, true)
	server := ssh.NewMultiChannelStream(s2, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var clientErr, serverErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = client.Connect(ctx)
	}()
	go func() {
		defer wg.Done()
		serverErr = server.Connect(ctx)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client Connect failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server Connect failed: %v", serverErr)
	}

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	return client, server
}

// CreateSecureStreamPair creates a connected client/server SecureStream pair
// using real encryption. Both streams are authenticated and ready for data exchange.
// Cleaned up via t.Cleanup.
func CreateSecureStreamPair(t *testing.T) (*ssh.SecureStream, *ssh.SecureStream) {
	t.Helper()

	serverKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	s1, s2 := CreateDuplexStreams()

	clientCreds := &ssh.ClientCredentials{Username: "testuser"}
	serverCreds := &ssh.ServerCredentials{PublicKeys: []ssh.KeyPair{serverKey}}

	client := ssh.NewSecureStreamClient(s1, clientCreds, false)
	client.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := ssh.NewSecureStreamServer(s2, serverCreds, nil)
	server.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var clientErr, serverErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = client.Connect(ctx)
	}()
	go func() {
		defer wg.Done()
		serverErr = server.Connect(ctx)
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

// CreatePipedSessionPairs creates two session pairs and pipes the server of the
// first pair to the client of the second pair. This simulates a relay:
//
//	clientA <-> serverA --[pipe]--> clientB <-> serverB
//
// Returns clientA (the external client), serverB (the external server), and a
// channel that will receive the PipeSession error when it completes.
// Cleaned up via t.Cleanup.
func CreatePipedSessionPairs(t *testing.T) (clientA *ssh.ClientSession, serverB *ssh.ServerSession, pipeDone <-chan error) {
	t.Helper()

	clientA, serverA := CreateConnectedSessionPair(t, nil)
	clientB, serverB := CreateConnectedSessionPair(t, nil)

	pipeErrCh := make(chan error, 1)
	pipeCtx, pipeCancel := context.WithCancel(context.Background())
	t.Cleanup(pipeCancel)

	go func() {
		pipeErrCh <- ssh.PipeSession(pipeCtx, &serverA.Session, &clientB.Session)
	}()

	// Wait for PipeSession to install its handlers. Since we can't access
	// unexported fields, use a brief sleep to let the goroutine start.
	time.Sleep(50 * time.Millisecond)

	return clientA, serverB, pipeErrCh
}
