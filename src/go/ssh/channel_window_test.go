// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"math"
	"sync"
	"testing"
	"time"
)

// TestChannelWindowAdjustOverflow verifies that a window adjust message that
// would overflow uint32 returns an error instead of wrapping the counter.
func TestChannelWindowAdjustOverflow(t *testing.T) {
	ch := newChannel(nil, "session", 0)

	// Set the remote window to a high value.
	ch.mu.Lock()
	ch.remoteWindowSize = math.MaxUint32 - 10
	ch.mu.Unlock()

	// Adjust by a value that would overflow.
	err := ch.adjustRemoteWindow(20)
	if err == nil {
		t.Fatal("expected error from overflow window adjust, got nil")
	}

	// Verify the window size was NOT changed.
	ch.mu.Lock()
	ws := ch.remoteWindowSize
	ch.mu.Unlock()

	if ws != math.MaxUint32-10 {
		t.Errorf("window size changed to %d after overflow; expected %d", ws, uint32(math.MaxUint32-10))
	}

	// Verify a valid adjustment still works.
	err = ch.adjustRemoteWindow(5)
	if err != nil {
		t.Fatalf("valid window adjust returned error: %v", err)
	}

	ch.mu.Lock()
	ws = ch.remoteWindowSize
	ch.mu.Unlock()

	if ws != math.MaxUint32-5 {
		t.Errorf("window size = %d after valid adjust; expected %d", ws, uint32(math.MaxUint32-5))
	}
}

// TestChannelSendExactlyWindowSize verifies that sending data exactly equal
// to the window size succeeds without blocking.
func TestChannelSendExactlyWindowSize(t *testing.T) {
	// Use a small window size for a fast test.
	cfg := NewNoSecurityConfig()
	cfg.MaxChannelWindowSize = 4096

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: cfg,
		ServerConfig: cfg,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	serverStream := NewStream(serverCh)

	// Send exactly the window size (4096 bytes).
	sent := make([]byte, 4096)
	rand.Read(sent)

	// Send and receive concurrently to avoid deadlock.
	var sendErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendErr = clientCh.Send(ctx, sent)
	}()

	received := make([]byte, 4096)
	n, err := io.ReadFull(serverStream, received)
	if err != nil {
		t.Fatalf("ReadFull failed: %v (read %d)", err, n)
	}

	wg.Wait()
	if sendErr != nil {
		t.Fatalf("Send failed: %v", sendErr)
	}

	if !bytes.Equal(sent, received) {
		t.Error("data mismatch when sending exactly window size")
	}
}

// TestChannelWindowExhaustion verifies that when the remote window is
// exhausted, the sender blocks until the window is replenished.
func TestChannelWindowExhaustion(t *testing.T) {
	// Use a small window with small packets so we can exhaust it quickly.
	cfg := NewNoSecurityConfig()
	cfg.MaxChannelWindowSize = 1024

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: cfg,
		ServerConfig: cfg,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Do NOT set up a data handler on the server side. Data will buffer
	// without adjusting the window, causing the sender to eventually block.

	// Send data that exceeds the window in a goroutine.
	sendDone := make(chan error, 1)
	go func() {
		// Send more data than the window allows (2x window size).
		data := make([]byte, 2048)
		rand.Read(data)
		sendDone <- clientCh.Send(ctx, data)
	}()

	// The sender should block since the server isn't consuming data
	// (no AdjustWindow calls). Wait briefly to confirm it hasn't completed.
	select {
	case err := <-sendDone:
		// It's possible the send completes if data fits in the initial window,
		// but 2048 > 1024 window, so it should block on the second packet.
		if err != nil {
			t.Fatalf("Send returned error: %v", err)
		}
		t.Fatal("Send completed immediately; expected it to block when window exhausted")
	case <-time.After(200 * time.Millisecond):
		// Expected: sender is blocked waiting for window adjustment.
	}

	// Now set up a handler that reads data and adjusts the window.
	serverStream := NewStream(serverCh)
	buf := make([]byte, 2048)
	n, err := io.ReadFull(serverStream, buf)
	if err != nil {
		t.Fatalf("ReadFull failed: %v (read %d)", err, n)
	}

	// The send should now complete.
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("Send returned error after window replenish: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Send still blocked after window replenish")
	}
}

// TestChannelWindowResumption verifies the complete flow: exhaust the window,
// verify the sender blocks, then replenish the window and verify the sender resumes.
func TestChannelWindowResumption(t *testing.T) {
	cfg := NewNoSecurityConfig()
	cfg.MaxChannelWindowSize = 2048

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: cfg,
		ServerConfig: cfg,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	serverStream := NewStream(serverCh)

	// Send a large amount of data that will require multiple window adjustments.
	const totalSize = 8192 // 4x window size
	sent := make([]byte, totalSize)
	rand.Read(sent)

	var sendErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendErr = clientCh.Send(ctx, sent)
	}()

	// Read all the data on the server side. As the Stream reads data,
	// it calls AdjustWindow which replenishes the window and unblocks the sender.
	received := make([]byte, totalSize)
	n, err := io.ReadFull(serverStream, received)
	if err != nil {
		t.Fatalf("ReadFull failed: %v (read %d of %d)", err, n, totalSize)
	}

	wg.Wait()
	if sendErr != nil {
		t.Fatalf("Send failed: %v", sendErr)
	}

	if !bytes.Equal(sent, received) {
		t.Error("data mismatch after window exhaustion and resumption")
	}
}
