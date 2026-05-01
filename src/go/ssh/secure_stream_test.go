// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

// createSecureStreamPair creates a connected client/server SecureStream pair
// using real encryption. Both streams are authenticated and ready for data exchange.
func createSecureStreamPair(t *testing.T) (*SecureStream, *SecureStream) {
	t.Helper()

	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	clientStream, serverStream := duplexPipe()

	clientCreds := &ClientCredentials{Username: "testuser"}
	serverCreds := &ServerCredentials{PublicKeys: []KeyPair{serverKey}}

	client := NewSecureStreamClient(clientStream, clientCreds, false)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewSecureStreamServer(serverStream, serverCreds, nil)
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

func TestSecureStreamConnectAndRoundTrip(t *testing.T) {
	client, server := createSecureStreamPair(t)

	// Verify connected state.
	if client.IsClosed() {
		t.Error("client should not be closed")
	}
	if server.IsClosed() {
		t.Error("server should not be closed")
	}

	// Client writes, server reads.
	testData := []byte("hello from client")
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(testData)
		writeDone <- err
	}()

	buf := make([]byte, len(testData))
	_, err := io.ReadFull(server, buf)
	if err != nil {
		t.Fatalf("server read failed: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if !bytes.Equal(buf, testData) {
		t.Errorf("data mismatch: got %q, want %q", buf, testData)
	}

	// Server writes, client reads.
	replyData := []byte("hello from server")
	go func() {
		_, err := server.Write(replyData)
		writeDone <- err
	}()

	buf = make([]byte, len(replyData))
	_, err = io.ReadFull(client, buf)
	if err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("server write failed: %v", err)
	}
	if !bytes.Equal(buf, replyData) {
		t.Errorf("reply mismatch: got %q, want %q", buf, replyData)
	}
}

func TestSecureStreamAuthFailure(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	clientStream, serverStream := duplexPipe()

	clientCreds := &ClientCredentials{Username: "testuser", Password: "wrong"}
	serverCreds := &ServerCredentials{PublicKeys: []KeyPair{serverKey}}

	client := NewSecureStreamClient(clientStream, clientCreds, false)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		// Client approves server host key.
		args.AuthenticationResult = true
	}

	server := NewSecureStreamServer(serverStream, serverCreds, nil)
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		// Server rejects all client credentials (AuthenticationResult stays nil).
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

	// Client should get an error (auth failure).
	if clientErr == nil {
		t.Error("expected client connect to fail with auth error")
	}

	// Clean up (Close is idempotent).
	client.Close()
	server.Close()

	// Server may also get an error (session closed during auth).
	_ = serverErr
}

func TestSecureStreamCloseFiresOnClosed(t *testing.T) {
	client, _ := createSecureStreamPair(t)

	closedCalled := make(chan *SessionClosedEventArgs, 1)
	client.OnClosed = func(args *SessionClosedEventArgs) {
		closedCalled <- args
	}

	client.Close()

	select {
	case args := <-closedCalled:
		if args == nil {
			t.Error("OnClosed args should not be nil")
		}
	case <-time.After(5 * time.Second):
		t.Error("OnClosed not called after Close()")
	}

	if !client.IsClosed() {
		t.Error("client should be closed after Close()")
	}
}

func TestSecureStreamReconnect(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	reconnSessions := NewReconnectableSessions()
	serverCreds := &ServerCredentials{PublicKeys: []KeyPair{serverKey}}
	clientCreds := &ClientCredentials{Username: "testuser"}

	// Create the initial transport pair.
	clientTransport, serverTransport := duplexPipe()

	// Create client SecureStream with reconnect enabled.
	client := NewSecureStreamClient(clientTransport, clientCreds, true)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	disconnectedCh := make(chan struct{}, 1)
	client.OnDisconnected = func() {
		select {
		case disconnectedCh <- struct{}{}:
		default:
		}
	}

	// Create server SecureStream with reconnectable sessions.
	server := NewSecureStreamServer(serverTransport, serverCreds, reconnSessions)
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect both concurrently.
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

	// Wait for reconnect to be fully enabled on both sides.
	if err := WaitUntilReconnectEnabled(ctx, client.Session(), server.Session()); err != nil {
		t.Fatalf("reconnect not enabled: %v", err)
	}

	// Add the server session to the reconnectable collection so reconnect
	// requests can find it. (In production, application code manages this.)
	reconnSessions.add(server.serverSession)

	// Exchange data before disconnect to verify the connection works.
	testData := []byte("before disconnect")
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(testData)
		writeDone <- err
	}()

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("server read before disconnect failed: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write before disconnect failed: %v", err)
	}
	if !bytes.Equal(buf, testData) {
		t.Errorf("data mismatch before disconnect: got %q, want %q", buf, testData)
	}

	// Simulate network failure by closing the transport.
	clientTransport.Close()
	serverTransport.Close()

	// Wait for client to detect disconnect.
	select {
	case <-disconnectedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client OnDisconnected")
	}

	// Wait for server to detect disconnect.
	deadline := time.After(5 * time.Second)
	for server.Session().IsConnected() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for server disconnect")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Create new transport pair for reconnection.
	newClientTransport, newServerTransport := duplexPipe()

	// Create new server SecureStream with same credentials and reconnectable sessions.
	newServer := NewSecureStreamServer(newServerTransport, serverCreds, reconnSessions)
	newServer.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	// Connect new server and reconnect client concurrently.
	wg.Add(2)
	go func() {
		defer wg.Done()
		// The new server's Connect will fail once the old session takes over
		// during reconnection (AcceptChannel fails on the closed temp session).
		_ = newServer.Connect(ctx)
	}()
	go func() {
		defer wg.Done()
		clientErr = client.Reconnect(ctx, newClientTransport)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client reconnect failed: %v", clientErr)
	}

	// Verify client is reconnected.
	if !client.Session().IsConnected() {
		t.Error("client should be connected after reconnect")
	}

	// Verify original server session is reconnected.
	if !server.Session().IsConnected() {
		t.Error("original server should be connected after reconnect")
	}

	// Verify data resumes on the original SecureStream pair.
	postData := []byte("after reconnect")
	go func() {
		_, err := client.Write(postData)
		writeDone <- err
	}()

	buf = make([]byte, len(postData))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("server read after reconnect failed: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write after reconnect failed: %v", err)
	}
	if !bytes.Equal(buf, postData) {
		t.Errorf("data mismatch after reconnect: got %q, want %q", buf, postData)
	}

	// Clean up.
	client.Close()
	server.Close()
	newServer.Close()
}
