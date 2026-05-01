// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// TestConnectDefaultConfig verifies that a client connects to a server with
// default secure config — both sides report IsConnected() and have RemoteVersion set.
func TestConnectDefaultConfig(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig:      NewDefaultConfig(),
		ServerConfig:      NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{serverKey}},
	})

	if !client.IsConnected() {
		t.Error("client IsConnected() = false, want true")
	}
	if !server.IsConnected() {
		t.Error("server IsConnected() = false, want true")
	}
	if client.RemoteVersion == nil {
		t.Error("client RemoteVersion is nil")
	}
	if server.RemoteVersion == nil {
		t.Error("server RemoteVersion is nil")
	}
}

// TestConnectNoSecurityConfig verifies that a session pair can connect with
// kex:none (no encryption), and both sides report IsConnected().
func TestConnectNoSecurityConfig(t *testing.T) {
	client, server := createSessionPair(t, nil)

	if !client.IsConnected() {
		t.Error("client IsConnected() = false, want true")
	}
	if !server.IsConnected() {
		t.Error("server IsConnected() = false, want true")
	}
}

// TestCloseFromClient verifies that closing the client session causes both
// sides to report IsClosed and fires OnClosed with DisconnectByApplication.
func TestCloseFromClient(t *testing.T) {
	client, server := createSessionPair(t, nil)

	var clientClosedReason messages.SSHDisconnectReason
	var clientClosedOnce sync.Once
	clientClosedCh := make(chan struct{})
	client.SetClosedHandler(func(args *SessionClosedEventArgs) {
		clientClosedOnce.Do(func() {
			clientClosedReason = args.Reason
			close(clientClosedCh)
		})
	})

	var serverClosedOnce sync.Once
	serverClosedCh := make(chan struct{})
	server.SetClosedHandler(func(args *SessionClosedEventArgs) {
		serverClosedOnce.Do(func() {
			close(serverClosedCh)
		})
	})

	client.Close()

	// Wait for client OnClosed.
	select {
	case <-clientClosedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client OnClosed")
	}

	if clientClosedReason != messages.DisconnectByApplication {
		t.Errorf("client close reason = %d, want DisconnectByApplication (%d)",
			clientClosedReason, messages.DisconnectByApplication)
	}

	if !client.IsClosed() {
		t.Error("client IsClosed() = false, want true")
	}

	// Wait for server to detect close.
	select {
	case <-serverClosedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server OnClosed")
	}

	if !server.IsClosed() {
		t.Error("server IsClosed() = false, want true")
	}
}

// TestCloseFromServer verifies that closing the server session causes both
// sides to detect close.
func TestCloseFromServer(t *testing.T) {
	client, server := createSessionPair(t, nil)

	var clientClosedOnce sync.Once
	clientClosedCh := make(chan struct{})
	client.SetClosedHandler(func(args *SessionClosedEventArgs) {
		clientClosedOnce.Do(func() {
			close(clientClosedCh)
		})
	})

	var serverClosedOnce sync.Once
	serverClosedCh := make(chan struct{})
	server.SetClosedHandler(func(args *SessionClosedEventArgs) {
		serverClosedOnce.Do(func() {
			close(serverClosedCh)
		})
	})

	server.Close()

	// Wait for server OnClosed.
	select {
	case <-serverClosedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server OnClosed")
	}

	if !server.IsClosed() {
		t.Error("server IsClosed() = false, want true")
	}

	// Wait for client to detect close.
	select {
	case <-clientClosedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client OnClosed")
	}

	if !client.IsClosed() {
		t.Error("client IsClosed() = false, want true")
	}
}

// TestCloseUnderlyingStream verifies that closing the underlying transport
// (simulating network failure) causes both sides to detect disconnection.
func TestCloseUnderlyingStream(t *testing.T) {
	clientStream, serverStream := duplexPipe()

	client := NewClientSession(NewNoSecurityConfig())
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	server := NewServerSession(NewNoSecurityConfig())
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	clientClosedCh := make(chan struct{})
	var clientClosedOnce sync.Once
	client.SetClosedHandler(func(args *SessionClosedEventArgs) {
		clientClosedOnce.Do(func() {
			close(clientClosedCh)
		})
	})

	serverClosedCh := make(chan struct{})
	var serverClosedOnce sync.Once
	server.SetClosedHandler(func(args *SessionClosedEventArgs) {
		serverClosedOnce.Do(func() {
			close(serverClosedCh)
		})
	})

	// Close both sides of the underlying stream to simulate network failure.
	clientStream.Close()
	serverStream.Close()

	// Wait for both sides to detect the disconnection.
	select {
	case <-clientClosedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client to detect stream close")
	}
	select {
	case <-serverClosedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server to detect stream close")
	}

	if !client.IsClosed() {
		t.Error("client IsClosed() = false after stream close, want true")
	}
	if !server.IsClosed() {
		t.Error("server IsClosed() = false after stream close, want true")
	}
}

// TestConnectEcdhNistp521Only verifies that client and server both offering
// only ecdh-sha2-nistp521 negotiate successfully and complete key exchange.
// This ensures the P-521 KEX algorithm is properly registered in the lookup map
// and can be used end-to-end (not just at the algorithm unit-test level).
func TestConnectEcdhNistp521Only(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	// Configure both sides to offer only ecdh-sha2-nistp521.
	clientConfig := NewDefaultConfig()
	clientConfig.KeyExchangeAlgorithms = []string{AlgoKexEcdhNistp521}

	serverConfig := NewDefaultConfig()
	serverConfig.KeyExchangeAlgorithms = []string{AlgoKexEcdhNistp521}

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig:      clientConfig,
		ServerConfig:      serverConfig,
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{serverKey}},
	})

	if !client.IsConnected() {
		t.Error("client IsConnected() = false, want true")
	}
	if !server.IsConnected() {
		t.Error("server IsConnected() = false, want true")
	}
}

// TestMetricsAfterConnect verifies that session metrics show non-zero
// MessagesSent and MessagesReceived after a successful connection.
func TestMetricsAfterConnect(t *testing.T) {
	client, server := createSessionPair(t, nil)

	clientMetrics := client.Metrics()
	serverMetrics := server.Metrics()

	if clientMetrics.MessagesSent() == 0 {
		t.Error("client MessagesSent() = 0, want > 0")
	}
	if clientMetrics.MessagesReceived() == 0 {
		t.Error("client MessagesReceived() = 0, want > 0")
	}
	if serverMetrics.MessagesSent() == 0 {
		t.Error("server MessagesSent() = 0, want > 0")
	}
	if serverMetrics.MessagesReceived() == 0 {
		t.Error("server MessagesReceived() = 0, want > 0")
	}
}

// TestCloseBeforeDispatchLoop verifies that Close does not deadlock when called
// while Connect is still in the version exchange phase (before the dispatch loop
// starts). This is a regression test for a race where closeImpl waited on
// s.done which was never closed because the dispatch loop was never started.
func TestCloseBeforeDispatchLoop(t *testing.T) {
	clientStream, serverStream := duplexPipe()

	server := NewServerSession(NewNoSecurityConfig())
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start Connect in a goroutine. It will block during version exchange
	// because nothing is reading/writing the other end of the pipe.
	connectDone := make(chan error, 1)
	go func() {
		connectDone <- server.Connect(ctx, serverStream)
	}()

	// Give Connect time to create s.done and start the version read.
	time.Sleep(50 * time.Millisecond)

	// Close the underlying stream to simulate a network failure, then
	// close the session. Before the fix, Close() would deadlock here
	// because s.done was never closed.
	clientStream.Close()

	closeDone := make(chan struct{})
	go func() {
		server.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		// Success: Close returned without deadlocking.
	case <-time.After(3 * time.Second):
		t.Fatal("server.Close() deadlocked — s.done was never closed")
	}

	// Connect should also return with an error.
	select {
	case err := <-connectDone:
		if err == nil {
			t.Error("expected Connect to return an error after stream close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Connect to return")
	}
}
