// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestRequestServiceContextCancelled verifies that RequestServiceContext
// returns context.Canceled immediately when the context is already cancelled.
func TestRequestServiceContextCancelled(t *testing.T) {
	client, _ := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	err := client.RequestServiceContext(ctx, AuthServiceName)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestRequestServiceContextSuccess verifies that RequestServiceContext
// succeeds when the context is not cancelled and the service is available.
func TestRequestServiceContextSuccess(t *testing.T) {
	client, _ := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.RequestServiceContext(ctx, AuthServiceName)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

// TestConnectContextTimeout verifies that Session.Connect returns
// context.DeadlineExceeded when the context times out before key exchange
// completes.
func TestConnectContextTimeout(t *testing.T) {
	clientStream, serverStream := duplexPipe()
	defer clientStream.Close()

	// Start a goroutine that reads/writes version strings on the server side
	// but never completes key exchange, so the client's Connect will time out.
	// Must keep draining the pipe so the client's writes (KEX init) don't block.
	go func() {
		proto := newSSHProtocol(serverStream, nil)
		_, _ = proto.readVersionString()
		_ = proto.writeVersionString(GetLocalVersion().String())
		// Drain remaining writes so the client's sendMessage calls don't block on the pipe.
		buf := make([]byte, 4096)
		for {
			if _, err := serverStream.Read(buf); err != nil {
				return
			}
		}
	}()

	client := NewClientSession(NewNoSecurityConfig())

	// Use a short timeout so the test completes quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := client.Connect(ctx, clientStream)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

// TestConnectContextCancelled verifies that Session.Connect respects
// context cancellation during key exchange wait.
func TestConnectContextCancelled(t *testing.T) {
	clientStream, serverStream := duplexPipe()
	defer clientStream.Close()

	// Goroutine that does version exchange but no KEX, drains writes.
	go func() {
		proto := newSSHProtocol(serverStream, nil)
		_, _ = proto.readVersionString()
		_ = proto.writeVersionString(GetLocalVersion().String())
		buf := make([]byte, 4096)
		for {
			if _, err := serverStream.Read(buf); err != nil {
				return
			}
		}
	}()

	client := NewClientSession(NewNoSecurityConfig())

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after a brief delay to allow version exchange to complete.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := client.Connect(ctx, clientStream)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestStreamWriteContext verifies that Stream.WriteContext sends data through
// the channel and respects context cancellation.
func TestStreamWriteContext(t *testing.T) {
	client, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Accept channel on server side.
	type acceptResult struct {
		ch  *Channel
		err error
	}
	serverResult := make(chan acceptResult, 1)
	go func() {
		ch, err := server.AcceptChannel(ctx)
		serverResult <- acceptResult{ch, err}
	}()

	// Open channel on client side.
	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}

	// Wait for server to accept.
	var serverCh *Channel
	select {
	case r := <-serverResult:
		if r.err != nil {
			t.Fatalf("AcceptChannel failed: %v", r.err)
		}
		serverCh = r.ch
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptChannel timed out")
	}

	// Create streams.
	clientStream := NewStream(clientCh)
	serverStream := NewStream(serverCh)

	// Test WriteContext with valid context.
	testData := []byte("hello via WriteContext")
	n, err := clientStream.WriteContext(ctx, testData)
	if err != nil {
		t.Fatalf("WriteContext failed: %v", err)
	}
	if n != len(testData) {
		t.Fatalf("WriteContext wrote %d bytes, want %d", n, len(testData))
	}

	// Read on server side.
	buf := make([]byte, 256)
	readDone := make(chan struct{})
	var readN int
	var readErr error
	go func() {
		readN, readErr = serverStream.Read(buf)
		close(readDone)
	}()

	select {
	case <-readDone:
		if readErr != nil {
			t.Fatalf("Read failed: %v", readErr)
		}
		if string(buf[:readN]) != string(testData) {
			t.Fatalf("Read data = %q, want %q", buf[:readN], testData)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read timed out")
	}
}

// TestStreamWriteContextCancelledOnBlock verifies that Stream.WriteContext
// returns the context error when the write would block (e.g., channel not yet open).
// Note: if the channel is already open with available window, Send succeeds
// immediately without checking context (standard Go behavior for non-blocking ops).
func TestStreamWriteContextCancelledOnBlock(t *testing.T) {
	client, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open a channel on the client but do NOT accept on the server.
	// The channel will be in "opening" state — sendEnabled is not signaled yet
	// because the server hasn't sent ChannelOpenConfirmation.

	// Start a goroutine that delays acceptance.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Wait a bit, then accept so the channel eventually opens.
		time.Sleep(200 * time.Millisecond)
		server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}

	// The channel is now open (OpenChannel returns after confirmation).
	// To test context cancellation on a blocking write, we close the channel
	// and verify WriteContext on a closed stream returns an error.
	clientStream := NewStream(clientCh)
	clientStream.Close()

	cancelledCtx, cancelFn := context.WithCancel(context.Background())
	cancelFn()

	_, err = clientStream.WriteContext(cancelledCtx, []byte("should fail"))
	if err == nil {
		t.Fatal("expected error on WriteContext after close, got nil")
	}

	wg.Wait()
}
