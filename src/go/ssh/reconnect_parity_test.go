// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// --- Encrypted reconnect pair for parity tests needing real crypto ---

// encryptedReconnectPair creates a session pair with real encryption
// (ECDSA P-256 + AES-256-CTR + HMAC-SHA-256) and reconnect enabled.
type encryptedReconnectPair struct {
	client         *ClientSession
	server         *ServerSession
	hostKey        KeyPair
	reconnSessions *ReconnectableSessions
	clientStream   io.ReadWriteCloser
	serverStream   io.ReadWriteCloser
}

func newEncryptedReconnectPair(t *testing.T, clientConfig, serverConfig *SessionConfig) *encryptedReconnectPair {
	t.Helper()

	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	reconnSessions := NewReconnectableSessions()

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewServerSession(serverConfig)
	server.Credentials = &ServerCredentials{PublicKeys: []KeyPair{hostKey}}
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	server.ReconnectableSessions = reconnSessions

	clientStream, serverStream := duplexPipe()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
		t.Fatalf("client connect: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server connect: %v", serverErr)
	}

	// Wait for reconnect to be fully negotiated via extension info.
	if err := WaitUntilReconnectEnabled(ctx, &client.Session, &server.Session); err != nil {
		t.Fatalf("reconnect not enabled: %v", err)
	}

	reconnSessions.add(server)

	return &encryptedReconnectPair{
		client:         client,
		server:         server,
		hostKey:        hostKey,
		reconnSessions: reconnSessions,
		clientStream:   clientStream,
		serverStream:   serverStream,
	}
}

func (p *encryptedReconnectPair) disconnect() {
	p.clientStream.Close()
	p.serverStream.Close()
}

func (p *encryptedReconnectPair) waitDisconnected(t *testing.T) {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		if !p.client.IsConnected() && !p.server.IsConnected() {
			return
		}
		select {
		case <-timeout:
			t.Fatalf("timed out waiting for disconnect (client=%v, server=%v)",
				p.client.IsConnected(), p.server.IsConnected())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (p *encryptedReconnectPair) reconnect(t *testing.T) {
	t.Helper()

	clientStream, serverStream := duplexPipe()
	p.clientStream = clientStream
	p.serverStream = serverStream

	serverConfig := NewDefaultConfigWithReconnect()
	newServer := NewServerSession(serverConfig)
	newServer.Credentials = &ServerCredentials{PublicKeys: []KeyPair{p.hostKey}}
	newServer.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	newServer.ReconnectableSessions = p.reconnSessions

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var serverErr, clientErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		serverErr = newServer.Connect(ctx, serverStream)
	}()
	go func() {
		defer wg.Done()
		clientErr = p.client.Reconnect(ctx, clientStream)
	}()
	wg.Wait()

	if serverErr != nil {
		t.Fatalf("server connect: %v", serverErr)
	}
	if clientErr != nil {
		t.Fatalf("client reconnect: %v", clientErr)
	}
}

// --- Parity tests matching C#/TS ReconnectTests ---

// TestReconnectAfterExplicitClose verifies that closing the transport stream
// (not the session) leaves the session in disconnected state and that
// reconnection with a new stream restores data flow.
func TestReconnectAfterExplicitClose(t *testing.T) {
	pair := newReconnectTestPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientCh, serverCh := openChannelPair(t, pair.client, pair.server)

	receivedData := make(chan []byte, 10)
	serverCh.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		receivedData <- buf
		serverCh.AdjustWindow(uint32(len(data)))
	})

	// Send data before disconnect.
	testData := []byte("before-disconnect")
	if err := clientCh.Send(ctx, testData); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	select {
	case data := <-receivedData:
		if string(data) != string(testData) {
			t.Errorf("data mismatch: got %q, want %q", data, testData)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for data before disconnect")
	}

	// Explicitly close the transport stream (NOT the session).
	pair.disconnect()
	pair.waitDisconnected(t)

	// Session should be disconnected but NOT closed.
	if pair.client.IsClosed() {
		t.Error("client should not be closed after transport close")
	}
	if pair.server.IsClosed() {
		t.Error("server should not be closed after transport close")
	}

	// Reconnect with a new stream.
	pair.reconnect(t)

	if !pair.client.IsConnected() {
		t.Error("client should be connected after reconnect")
	}
	if !pair.server.IsConnected() {
		t.Error("server should be connected after reconnect")
	}

	// Verify data flows on the same channel after reconnect.
	postData := []byte("after-reconnect")
	if err := clientCh.Send(ctx, postData); err != nil {
		t.Fatalf("post-reconnect send failed: %v", err)
	}

	select {
	case data := <-receivedData:
		if string(data) != string(postData) {
			t.Errorf("post-reconnect data: got %q, want %q", data, postData)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for post-reconnect data")
	}
}

// TestReconnectServerRetransmitsData verifies that data sent by the server
// before a disconnect is retransmitted and received after reconnect.
func TestReconnectServerRetransmitsData(t *testing.T) {
	pair := newMockReconnectTestPair(t)

	clientCh, serverCh := openChannelPair(t, pair.client, pair.server)

	clientReceived := make(chan []byte, 10)
	clientCh.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		clientReceived <- buf
		clientCh.AdjustWindow(uint32(len(data)))
	})

	serverReceived := make(chan []byte, 10)
	serverCh.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		serverReceived <- buf
		serverCh.AdjustWindow(uint32(len(data)))
	})

	ctx := context.Background()

	// Exchange initial data to confirm both directions work.
	testData := []byte{1, 2, 3}
	if err := serverCh.Send(ctx, testData); err != nil {
		t.Fatalf("server send failed: %v", err)
	}
	if err := clientCh.Send(ctx, testData); err != nil {
		t.Fatalf("client send failed: %v", err)
	}

	select {
	case <-clientReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client receive")
	}
	select {
	case <-serverReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server receive")
	}

	// Disconnect: client stream closes immediately, server stream drops
	// 36 bytes before failing — simulates a server message being partially
	// delivered to the network.
	pair.clientMock.mockDisconnect(errors.New("client disconnect"))
	pair.serverMock.mockDisconnectWithDrop(errors.New("server disconnect"), 36)

	// Server sends data that will be partially dropped.
	_ = serverCh.Send(ctx, testData)

	pair.waitDisconnected(t)

	// Reconnect — the dropped server message should be retransmitted.
	pair.reconnect(t)

	select {
	case data := <-clientReceived:
		if len(data) != len(testData) {
			t.Errorf("retransmitted data length: got %d, want %d", len(data), len(testData))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for retransmitted server data")
	}

	// Verify continued operation after reconnect.
	postData := []byte{7, 8, 9}
	if err := serverCh.Send(ctx, postData); err != nil {
		t.Fatalf("post-reconnect send failed: %v", err)
	}

	select {
	case data := <-clientReceived:
		if len(data) != len(postData) {
			t.Errorf("post-reconnect data length: got %d, want %d", len(data), len(postData))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for post-reconnect server data")
	}
}

// TestReconnectWrongSessionIDParity creates two separate encrypted sessions
// with distinct session IDs and verifies that reconnecting client A against
// server B's reconnectable sessions fails with SessionNotFound.
func TestReconnectWrongSessionIDParity(t *testing.T) {
	pairA := newEncryptedReconnectPair(t,
		NewDefaultConfigWithReconnect(),
		NewDefaultConfigWithReconnect(),
	)
	pairB := newEncryptedReconnectPair(t,
		NewDefaultConfigWithReconnect(),
		NewDefaultConfigWithReconnect(),
	)

	// Disconnect pair A.
	pairA.disconnect()
	pairA.waitDisconnected(t)

	// Try to reconnect client A against pair B's reconnectable sessions.
	// Use pair A's host key so the host key check passes.
	clientStream, serverStream := duplexPipe()

	serverConfig := NewDefaultConfigWithReconnect()
	newServer := NewServerSession(serverConfig)
	newServer.Credentials = &ServerCredentials{PublicKeys: []KeyPair{pairA.hostKey}}
	newServer.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	newServer.ReconnectableSessions = pairB.reconnSessions

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var serverErr, clientErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		serverErr = newServer.Connect(ctx, serverStream)
	}()
	go func() {
		defer wg.Done()
		clientErr = pairA.client.Reconnect(ctx, clientStream)
	}()
	wg.Wait()

	if serverErr != nil {
		t.Fatalf("server connect: %v", serverErr)
	}

	if clientErr == nil {
		t.Fatal("expected reconnect to fail with wrong session")
	}

	var reconnErr *ReconnectError
	if !errors.As(clientErr, &reconnErr) {
		t.Fatalf("expected *ReconnectError, got %T: %v", clientErr, clientErr)
	}

	if reconnErr.Reason != messages.ReconnectFailureSessionNotFound {
		t.Errorf("expected SessionNotFound (%d), got %d",
			messages.ReconnectFailureSessionNotFound, reconnErr.Reason)
	}
}

// TestReconnectWrongHostKeyParity verifies that reconnecting to a server
// with a different host key fails with DifferentServerHostKey.
func TestReconnectWrongHostKeyParity(t *testing.T) {
	pair := newEncryptedReconnectPair(t,
		NewDefaultConfigWithReconnect(),
		NewDefaultConfigWithReconnect(),
	)

	pair.disconnect()
	pair.waitDisconnected(t)

	// Create a new server with a DIFFERENT host key.
	differentHostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	clientStream, serverStream := duplexPipe()

	serverConfig := NewDefaultConfigWithReconnect()
	newServer := NewServerSession(serverConfig)
	newServer.Credentials = &ServerCredentials{PublicKeys: []KeyPair{differentHostKey}}
	newServer.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	newServer.ReconnectableSessions = pair.reconnSessions

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var serverErr, clientErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		serverErr = newServer.Connect(ctx, serverStream)
	}()
	go func() {
		defer wg.Done()
		clientErr = pair.client.Reconnect(ctx, clientStream)
	}()
	wg.Wait()

	// Server may error when client disconnects after detecting host key mismatch.
	_ = serverErr

	if clientErr == nil {
		t.Fatal("expected reconnect to fail with different host key")
	}

	var reconnErr *ReconnectError
	if !errors.As(clientErr, &reconnErr) {
		t.Fatalf("expected *ReconnectError, got %T: %v", clientErr, clientErr)
	}

	if reconnErr.Reason != messages.ReconnectFailureDifferentServerHostKey {
		t.Errorf("expected DifferentServerHostKey (%d), got %d",
			messages.ReconnectFailureDifferentServerHostKey, reconnErr.Reason)
	}
}

// TestReconnectDuringKeyExchange triggers a rekey via low KeyRotationThreshold,
// disconnects during or right after the key exchange, reconnects, and verifies
// the session recovers without corruption.
func TestReconnectDuringKeyExchange(t *testing.T) {
	const threshold = 8 * 1024 // 8 KB — triggers rekey quickly

	clientConfig := NewDefaultConfigWithReconnect()
	clientConfig.KeyRotationThreshold = threshold

	serverConfig := NewDefaultConfigWithReconnect()
	serverConfig.KeyRotationThreshold = threshold

	pair := newEncryptedReconnectPair(t, clientConfig, serverConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientCh, serverCh := openChannelPair(t, pair.client, pair.server)

	var serverTotalReceived int64
	serverCh.SetDataReceivedHandler(func(data []byte) {
		atomic.AddInt64(&serverTotalReceived, int64(len(data)))
		serverCh.AdjustWindow(uint32(len(data)))
	})

	// Send data asynchronously to trigger key rotation.
	// With 8KB threshold, sends may block during rekey — use a goroutine.
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for i := 0; i < 16; i++ {
			if err := clientCh.Send(ctx, data); err != nil {
				return // Error during disconnect is expected.
			}
		}
	}()

	// Wait for some data to flow (enough for key rotation to trigger).
	// Don't wait for all 16KB — sends may block during rekey.
	deadline := time.After(10 * time.Second)
	for atomic.LoadInt64(&serverTotalReceived) < 2048 {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for initial data: got %d",
				atomic.LoadInt64(&serverTotalReceived))
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Disconnect during or shortly after key exchange.
	pair.disconnect()
	pair.waitDisconnected(t)

	// Wait for send goroutine to exit (it will error on disconnect).
	select {
	case <-sendDone:
	case <-time.After(5 * time.Second):
	}

	// Reconnect.
	pair.reconnect(t)

	if !pair.client.IsConnected() {
		t.Error("client should be connected after reconnect")
	}
	if !pair.server.IsConnected() {
		t.Error("server should be connected after reconnect")
	}

	// Verify data flows after reconnect (session recovered without corruption).
	var postReceived int64
	serverCh.SetDataReceivedHandler(func(data []byte) {
		atomic.AddInt64(&postReceived, int64(len(data)))
		serverCh.AdjustWindow(uint32(len(data)))
	})

	postData := make([]byte, 1024)
	for i := range postData {
		postData[i] = byte((i + 42) & 0xFF)
	}

	if err := clientCh.Send(ctx, postData); err != nil {
		t.Fatalf("post-reconnect send failed: %v", err)
	}

	deadline = time.After(10 * time.Second)
	for atomic.LoadInt64(&postReceived) < int64(len(postData)) {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for post-reconnect data: got %d, want %d",
				atomic.LoadInt64(&postReceived), len(postData))
		case <-time.After(10 * time.Millisecond):
		}
	}
}
