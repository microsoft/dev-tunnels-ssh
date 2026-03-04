// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// createEncryptedSessionPair creates a connected client/server session pair
// with real encryption (ECDSA P-256 + AES-256-CTR + HMAC-SHA-256) for testing
// features that require actual key exchange (e.g., key rotation).
func createEncryptedSessionPair(t *testing.T, clientConfig, serverConfig *SessionConfig) (*ClientSession, *ServerSession) {
	t.Helper()

	// Generate an ECDSA P-256 host key for the server (fast to generate).
	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewServerSession(serverConfig)
	server.Credentials = &ServerCredentials{
		PublicKeys: []KeyPair{hostKey},
	}
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

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

// TestProtocolByteCountersIncrement verifies that protocol byte counters
// are incremented after send and receive operations.
func TestProtocolByteCountersIncrement(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	// Byte counters start at 0.
	if got := atomic.LoadUint64(&p1.BytesSent); got != 0 {
		t.Errorf("initial BytesSent = %d, want 0", got)
	}
	if got := atomic.LoadUint64(&p2.BytesReceived); got != 0 {
		t.Errorf("initial BytesReceived = %d, want 0", got)
	}

	// Send some messages.
	payload := []byte{0x05, 0x01, 0x02, 0x03} // 4-byte payload
	const numMessages = 5

	done := make(chan error, 1)
	go func() {
		for i := 0; i < numMessages; i++ {
			if err := p1.sendMessage(payload); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i := 0; i < numMessages; i++ {
		if _, err := p2.receiveMessage(); err != nil {
			t.Fatalf("receiveMessage %d failed: %v", i, err)
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	// Verify counters are non-zero.
	sentBytes := atomic.LoadUint64(&p1.BytesSent)
	receivedBytes := atomic.LoadUint64(&p2.BytesReceived)

	if sentBytes == 0 {
		t.Error("BytesSent should be > 0 after sending messages")
	}
	if receivedBytes == 0 {
		t.Error("BytesReceived should be > 0 after receiving messages")
	}

	// Both sides should report the same wire bytes for the same messages.
	if sentBytes != receivedBytes {
		t.Errorf("BytesSent (%d) != BytesReceived (%d)", sentBytes, receivedBytes)
	}
}

// TestKeyRotationTriggersReExchange verifies that sending data exceeding
// the KeyRotationThreshold triggers a re-keying, which resets the byte counters.
func TestKeyRotationTriggersReExchange(t *testing.T) {
	// Use a small threshold to trigger re-keying quickly.
	const threshold = 8 * 1024

	clientConfig := NewDefaultConfig()
	clientConfig.KeyRotationThreshold = threshold

	serverConfig := NewDefaultConfig()
	serverConfig.KeyRotationThreshold = threshold

	client, server := createEncryptedSessionPair(t, clientConfig, serverConfig)

	// Open a channel for data transfer.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var clientCh, serverCh *Channel
	var openErr, acceptErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, openErr = client.OpenChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		serverCh, acceptErr = server.AcceptChannel(ctx)
	}()
	wg.Wait()

	if openErr != nil {
		t.Fatalf("OpenChannel failed: %v", openErr)
	}
	if acceptErr != nil {
		t.Fatalf("AcceptChannel failed: %v", acceptErr)
	}

	// Set up a data handler to consume received data (prevents backpressure).
	serverCh.SetDataReceivedHandler(func(d []byte) {})

	// Send data exceeding the threshold. Use a separate goroutine so we
	// can continue even if a send blocks during re-keying.
	const chunkSize = 1024
	const numChunks = 32
	sendDone := make(chan error, 1)
	go func() {
		data := make([]byte, chunkSize)
		for i := range data {
			data[i] = byte(i % 256)
		}
		for i := 0; i < numChunks; i++ {
			if err := clientCh.Send(ctx, data); err != nil {
				sendDone <- err
				return
			}
		}
		sendDone <- nil
	}()

	// Poll for evidence of re-keying: the protocol byte counters should be
	// reset (smaller than accumulated metrics) once re-keying completes.
	reKeyDetected := false
	deadline := time.After(15 * time.Second)
	for !reKeyDetected {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for re-keying to occur (metrics=%d, counter=%d)",
				client.Metrics().BytesSent(), atomic.LoadUint64(&client.protocol.BytesSent))
		case err := <-sendDone:
			if err != nil {
				t.Fatalf("Send failed: %v", err)
			}
			// Send completed, give re-keying time to finish.
			time.Sleep(1 * time.Second)
			metricsSent := client.Metrics().BytesSent()
			counterSent := atomic.LoadUint64(&client.protocol.BytesSent)
			if metricsSent > 0 && counterSent < uint64(metricsSent) {
				reKeyDetected = true
			} else {
				t.Fatalf("all data sent but no re-keying detected (metrics=%d, counter=%d)",
					metricsSent, counterSent)
			}
		case <-time.After(200 * time.Millisecond):
			metricsSent := client.Metrics().BytesSent()
			counterSent := atomic.LoadUint64(&client.protocol.BytesSent)
			if metricsSent > 0 && counterSent < uint64(metricsSent) {
				reKeyDetected = true
			}
		}
	}

	// Drain the send goroutine.
	select {
	case <-sendDone:
	default:
	}

	t.Logf("key rotation verified: protocol BytesSent = %d, metrics BytesSent = %d, threshold = %d",
		atomic.LoadUint64(&client.protocol.BytesSent), client.Metrics().BytesSent(), threshold)

	// Session should still be connected after re-keying.
	if !client.IsConnected() {
		t.Error("client should still be connected after re-keying")
	}
	if !server.IsConnected() {
		t.Error("server should still be connected after re-keying")
	}
}

// TestKeyRotationDisabledWithZeroThreshold verifies that setting
// KeyRotationThreshold to 0 disables automatic key rotation.
func TestKeyRotationDisabledWithZeroThreshold(t *testing.T) {
	clientConfig := NewDefaultConfig()
	clientConfig.KeyRotationThreshold = 0 // disabled

	serverConfig := NewDefaultConfig()
	serverConfig.KeyRotationThreshold = 0 // disabled

	client, server := createEncryptedSessionPair(t, clientConfig, serverConfig)

	// Open a channel.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var clientCh, serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		clientCh, err = client.OpenChannel(ctx)
		if err != nil {
			t.Errorf("OpenChannel failed: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		var err error
		serverCh, err = server.AcceptChannel(ctx)
		if err != nil {
			t.Errorf("AcceptChannel failed: %v", err)
		}
	}()
	wg.Wait()

	if clientCh == nil || serverCh == nil {
		t.Fatal("failed to open channel")
	}

	// Set handler before sending.
	var totalReceived int64
	allReceived := make(chan struct{}, 1)
	const totalExpected = 8 * 1024

	serverCh.SetDataReceivedHandler(func(d []byte) {
		n := atomic.AddInt64(&totalReceived, int64(len(d)))
		if n >= totalExpected {
			select {
			case allReceived <- struct{}{}:
			default:
			}
		}
	})

	// Record baseline.
	baselineBytesSent := atomic.LoadUint64(&client.protocol.BytesSent)

	// Send data.
	data := make([]byte, 1024)
	for i := 0; i < 8; i++ {
		if err := clientCh.Send(ctx, data); err != nil {
			t.Fatalf("Send failed: %v", err)
		}
	}

	// Wait for data on server.
	select {
	case <-allReceived:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out waiting for data")
	}

	time.Sleep(200 * time.Millisecond)

	// With threshold disabled, byte counters should NOT be reset.
	// The counter should accumulate and be >= the data we sent (wire bytes
	// are more than payload due to framing).
	currentBytesSent := atomic.LoadUint64(&client.protocol.BytesSent) - baselineBytesSent
	if currentBytesSent < uint64(totalExpected) {
		t.Errorf("with rotation disabled, expected BytesSent >= %d, got %d",
			totalExpected, currentBytesSent)
	}
}

// TestKeyRotationCounterResetOnReKey verifies that byte counters on the
// protocol are reset to values less than total metrics after re-keying occurs.
func TestKeyRotationCounterResetOnReKey(t *testing.T) {
	const threshold = 8 * 1024

	clientConfig := NewDefaultConfig()
	clientConfig.KeyRotationThreshold = threshold

	serverConfig := NewDefaultConfig()
	serverConfig.KeyRotationThreshold = threshold

	client, server := createEncryptedSessionPair(t, clientConfig, serverConfig)

	// Open a channel.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var clientCh, serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		clientCh, err = client.OpenChannel(ctx)
		if err != nil {
			t.Errorf("OpenChannel failed: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		var err error
		serverCh, err = server.AcceptChannel(ctx)
		if err != nil {
			t.Errorf("AcceptChannel failed: %v", err)
		}
	}()
	wg.Wait()

	if clientCh == nil || serverCh == nil {
		t.Fatal("failed to open channel")
	}

	// Set handler to consume data.
	serverCh.SetDataReceivedHandler(func(d []byte) {})

	// Send data in a goroutine.
	const chunkSize = 1024
	const numChunks = 32
	sendDone := make(chan error, 1)
	go func() {
		data := make([]byte, chunkSize)
		for i := 0; i < numChunks; i++ {
			if err := clientCh.Send(ctx, data); err != nil {
				sendDone <- err
				return
			}
		}
		sendDone <- nil
	}()

	// Poll for re-keying evidence on the server side (BytesReceived reset).
	reKeyDetected := false
	deadline := time.After(15 * time.Second)
	for !reKeyDetected {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for server-side re-keying evidence")
		case <-time.After(200 * time.Millisecond):
			metricsRecv := server.Metrics().BytesReceived()
			counterRecv := atomic.LoadUint64(&server.protocol.BytesReceived)
			if metricsRecv > 0 && counterRecv < uint64(metricsRecv) {
				reKeyDetected = true
			}
		}
	}

	// Drain send goroutine.
	select {
	case err := <-sendDone:
		if err != nil {
			t.Logf("send finished with error (may be expected during re-keying): %v", err)
		}
	case <-time.After(5 * time.Second):
		// Send might be blocked; that's OK for this test.
	}

	t.Logf("server re-key verified: protocol BytesReceived = %d, metrics BytesReceived = %d",
		atomic.LoadUint64(&server.protocol.BytesReceived), server.Metrics().BytesReceived())
}
