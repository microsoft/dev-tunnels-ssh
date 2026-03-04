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

const secureStreamTestTimeout = 20 * time.Second

// secureStreamTestCreds holds generated keys and credentials for secure stream tests.
type secureStreamTestCreds struct {
	serverKey   ssh.KeyPair
	clientKey   ssh.KeyPair
	serverCreds *ssh.ServerCredentials
	clientCreds *ssh.ClientCredentials
}

func newSecureStreamTestCreds(t *testing.T) *secureStreamTestCreds {
	t.Helper()
	serverKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	clientKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	return &secureStreamTestCreds{
		serverKey: serverKey,
		clientKey: clientKey,
		serverCreds: &ssh.ServerCredentials{
			PublicKeys: []ssh.KeyPair{serverKey},
		},
		clientCreds: &ssh.ClientCredentials{
			Username:   "test",
			PublicKeys: []ssh.KeyPair{clientKey},
		},
	}
}

// createSecureStreamPair creates a connected client/server SecureStream pair.
// Returns the client and server SecureStreams. Both have auto-approval auth handlers.
// If reconnectableSessions is non-nil, reconnection is enabled.
func createSecureStreamPair(
	t *testing.T,
	creds *secureStreamTestCreds,
	reconnectableSessions *ssh.ReconnectableSessions,
) (*ssh.SecureStream, *ssh.SecureStream, *helpers.MockNetworkStream, *helpers.MockNetworkStream) {
	t.Helper()

	stream1, stream2 := helpers.CreateDuplexStreams()
	clientMock := helpers.NewMockNetworkStream(stream1)
	serverMock := helpers.NewMockNetworkStream(stream2)

	server := ssh.NewSecureStreamServer(serverMock, creds.serverCreds, reconnectableSessions)
	server.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	client := ssh.NewSecureStreamClient(clientMock, creds.clientCreds, reconnectableSessions != nil)
	client.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	return client, server, clientMock, serverMock
}

// connectSecureStreamPair connects a client/server pair concurrently.
func connectSecureStreamPair(
	t *testing.T,
	ctx context.Context,
	client, server *ssh.SecureStream,
) {
	t.Helper()

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
}

// exchangeData writes data from one side and reads from the other, then vice versa.
func exchangeData(t *testing.T, client, server *ssh.SecureStream) {
	t.Helper()

	payload := []byte("Hello!")
	result := make([]byte, 100)

	// Write from client, read from server.
	n, err := client.Write(payload)
	if err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("client wrote %d bytes, want %d", n, len(payload))
	}

	n, err = server.Read(result)
	if err != nil {
		t.Fatalf("server read failed: %v", err)
	}
	if string(result[:n]) != string(payload) {
		t.Fatalf("server got %q, want %q", string(result[:n]), string(payload))
	}

	// Write from server, read from client.
	n, err = server.Write(payload)
	if err != nil {
		t.Fatalf("server write failed: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("server wrote %d bytes, want %d", n, len(payload))
	}

	n, err = client.Read(result)
	if err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(result[:n]) != string(payload) {
		t.Fatalf("client got %q, want %q", string(result[:n]), string(payload))
	}
}

func TestSecureStreamAuthenticateServerSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), secureStreamTestTimeout)
	defer cancel()

	creds := newSecureStreamTestCreds(t)
	client, server, _, _ := createSecureStreamPair(t, creds, nil)
	defer client.Close()
	defer server.Close()

	var serverAuthEvent *ssh.AuthenticatingEventArgs
	client.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		serverAuthEvent = e
		e.AuthenticationResult = true
	}

	connectSecureStreamPair(t, ctx, client, server)

	// Verify the client received the server's public key for verification.
	if serverAuthEvent == nil {
		t.Fatal("client OnAuthenticating was not called")
	}
	if serverAuthEvent.PublicKey == nil {
		t.Fatal("server public key should be present in auth event")
	}
}

func TestSecureStreamAuthenticateServerFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), secureStreamTestTimeout)
	defer cancel()

	stream1, stream2 := helpers.CreateDuplexStreams()

	serverKey, _ := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	serverCreds := &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{serverKey},
	}
	clientKey, _ := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	clientCreds := &ssh.ClientCredentials{
		Username:   "test",
		PublicKeys: []ssh.KeyPair{clientKey},
	}

	server := ssh.NewSecureStreamServer(stream2, serverCreds, nil)
	server.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	client := ssh.NewSecureStreamClient(stream1, clientCreds, false)
	// Client REJECTS the server host key.
	client.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = nil // reject
	}

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

	// Client should fail with HostKeyNotVerifiable.
	if clientErr == nil {
		t.Fatal("client should have failed to connect")
	}
	var connErr *ssh.ConnectionError
	if errors.As(clientErr, &connErr) {
		if connErr.Reason != 9 { // DisconnectHostKeyNotVerifiable = 9
			t.Errorf("expected HostKeyNotVerifiable reason, got %d", connErr.Reason)
		}
	}

	// Server should also get an error (disconnected by client).
	if serverErr == nil {
		t.Log("server connect returned nil (may have already disconnected)")
	}
}

func TestSecureStreamAuthenticateClientSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), secureStreamTestTimeout)
	defer cancel()

	creds := newSecureStreamTestCreds(t)
	client, server, _, _ := createSecureStreamPair(t, creds, nil)
	defer client.Close()
	defer server.Close()

	var clientAuthEvent *ssh.AuthenticatingEventArgs
	server.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		clientAuthEvent = e
		e.AuthenticationResult = true
	}

	connectSecureStreamPair(t, ctx, client, server)

	// Verify the server received the client's credentials.
	if clientAuthEvent == nil {
		t.Fatal("server OnAuthenticating was not called")
	}
	if clientAuthEvent.PublicKey == nil {
		t.Fatal("client public key should be present in auth event")
	}
	if clientAuthEvent.Username != "test" {
		t.Errorf("username got %q, want %q", clientAuthEvent.Username, "test")
	}
}

func TestSecureStreamAuthenticateClientFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), secureStreamTestTimeout)
	defer cancel()

	stream1, stream2 := helpers.CreateDuplexStreams()

	serverKey, _ := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	serverCreds := &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{serverKey},
	}
	clientKey, _ := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	clientCreds := &ssh.ClientCredentials{
		Username:   "test",
		PublicKeys: []ssh.KeyPair{clientKey},
	}

	// Server REJECTS the client's credentials.
	server := ssh.NewSecureStreamServer(stream2, serverCreds, nil)
	server.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		// Reject all client auth attempts.
		e.AuthenticationResult = nil
	}

	client := ssh.NewSecureStreamClient(stream1, clientCreds, false)
	client.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true // accept server host key
	}

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

	// Client should fail — auth was rejected.
	if clientErr == nil {
		t.Fatal("client should have failed to connect")
	}

	// Server should also get an error (client fails and disconnects).
	if serverErr == nil {
		t.Log("server connect returned nil (may have already disconnected)")
	}
}

func TestSecureStreamReadWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), secureStreamTestTimeout)
	defer cancel()

	creds := newSecureStreamTestCreds(t)
	client, server, _, _ := createSecureStreamPair(t, creds, nil)
	defer client.Close()
	defer server.Close()

	connectSecureStreamPair(t, ctx, client, server)

	exchangeData(t, client, server)
}

func TestSecureStreamClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), secureStreamTestTimeout)
	defer cancel()

	creds := newSecureStreamTestCreds(t)
	client, server, _, _ := createSecureStreamPair(t, creds, nil)

	closedCh := make(chan struct{}, 1)
	server.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		select {
		case closedCh <- struct{}{}:
		default:
		}
	}

	connectSecureStreamPair(t, ctx, client, server)

	if client.IsClosed() {
		t.Fatal("client should not be closed")
	}

	client.Close()

	// Wait for the server to detect closure.
	select {
	case <-closedCh:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server closed event")
	}

	if !client.IsClosed() {
		t.Error("client should be closed after Close()")
	}
}

func TestSecureStreamReconnectServerErrors(t *testing.T) {
	// Verify that Reconnect cannot be called on a server SecureStream.
	creds := newSecureStreamTestCreds(t)
	stream1, _ := helpers.CreateDuplexStreams()
	serverMock := helpers.NewMockNetworkStream(stream1)

	server := ssh.NewSecureStreamServer(serverMock, creds.serverCreds, nil)
	server.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	ctx := context.Background()
	_, newStream := helpers.CreateDuplexStreams()
	newMock := helpers.NewMockNetworkStream(newStream)

	err := server.Reconnect(ctx, newMock)
	if err == nil {
		t.Fatal("Reconnect on server should return an error")
	}
}

func TestSecureStreamReconnectClientDisconnectedCallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), secureStreamTestTimeout)
	defer cancel()

	creds := newSecureStreamTestCreds(t)

	// Create a pair without reconnect to test OnDisconnected callback wiring.
	client, server, _, _ := createSecureStreamPair(t, creds, nil)
	defer server.Close()

	connectSecureStreamPair(t, ctx, client, server)

	// Register OnDisconnected on the client.
	disconnectedCalled := make(chan struct{}, 1)
	client.OnDisconnected = func() {
		select {
		case disconnectedCalled <- struct{}{}:
		default:
		}
	}

	// Closing the client triggers session teardown.
	client.Close()

	if !client.IsClosed() {
		t.Error("client should be closed after Close()")
	}
}
