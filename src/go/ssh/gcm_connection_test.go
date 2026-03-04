// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tamperStream wraps an io.ReadWriteCloser and corrupts the next write
// after Arm() is called.
type tamperStream struct {
	inner   io.ReadWriteCloser
	armed   int32 // atomic: 0 = pass-through, 1 = tamper next write
	fired   int32 // atomic: 1 after tampering occurred
}

func newTamperStream(inner io.ReadWriteCloser) *tamperStream {
	return &tamperStream{inner: inner}
}

func (t *tamperStream) Read(p []byte) (int, error) {
	return t.inner.Read(p)
}

func (t *tamperStream) Write(p []byte) (int, error) {
	if atomic.CompareAndSwapInt32(&t.armed, 1, 0) && len(p) > 4 {
		atomic.StoreInt32(&t.fired, 1)
		// Create a copy with tampered data.
		tampered := make([]byte, len(p))
		copy(tampered, p)
		// Flip bits in the encrypted portion (skip 4-byte packet length in GCM mode).
		tampered[5] ^= 0xFF
		tampered[6] ^= 0xFF
		tampered[7] ^= 0xFF
		return t.inner.Write(tampered)
	}
	return t.inner.Write(p)
}

func (t *tamperStream) Close() error {
	return t.inner.Close()
}

// Arm causes the next write to be tampered.
func (t *tamperStream) Arm() {
	atomic.StoreInt32(&t.armed, 1)
}

// TestGCMDecryptConnectionTerminatesOnAuthFailure verifies that when a tampered
// GCM-encrypted packet is injected mid-stream, the connection terminates
// rather than silently continuing.
func TestGCMDecryptConnectionTerminatesOnAuthFailure(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	// Use GCM-only encryption config.
	clientConfig := NewDefaultConfig()
	clientConfig.EncryptionAlgorithms = []string{AlgoEncAes256Gcm}

	serverConfig := NewDefaultConfig()
	serverConfig.EncryptionAlgorithms = []string{AlgoEncAes256Gcm}

	// Create the raw pipe pair.
	clientStream, serverStream := duplexPipe()

	// Wrap the client's stream to tamper with data after we arm it.
	tamper := newTamperStream(clientStream)

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewServerSession(serverConfig)
	server.Credentials = &ServerCredentials{PublicKeys: []KeyPair{serverKey}}
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
		clientErr = client.Connect(ctx, tamper)
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

	// Authenticate first (normal unmodified traffic).
	ok, err := client.Authenticate(ctx, nil)
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if !ok {
		t.Fatal("authenticate returned false")
	}

	// Track when the server session closes.
	serverClosed := make(chan struct{})
	server.SetClosedHandler(func(args *SessionClosedEventArgs) {
		close(serverClosed)
	})

	// Arm the tamper — the next message from client will be corrupted.
	tamper.Arm()

	// Open a channel — this sends encrypted data from client to server,
	// which will be corrupted by the tamperStream, causing a GCM auth failure
	// on the server's receive path.
	_, _ = client.OpenChannel(ctx)

	// Wait for the server session to close due to the tampered packet.
	select {
	case <-serverClosed:
		// Server detected the tampered packet and closed — expected behavior.
	case <-time.After(5 * time.Second):
		t.Fatal("server session did not close after receiving tampered GCM packet")
	}

	// Verify the server is closed.
	if !server.IsClosed() {
		t.Error("server should be closed after GCM authentication failure")
	}
}
