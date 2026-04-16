// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"context"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

// TestMultiChannelStreamDoubleClose verifies that closing a MultiChannelStream
// twice does not panic and returns nil on both calls.
func TestMultiChannelStreamDoubleClose(t *testing.T) {
	client, server := helpers.CreateMultiChannelStreamPair(t)

	// First close should succeed.
	if err := client.Close(); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}

	// Second close should be a no-op (not panic).
	if err := client.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}

	// Third close for good measure.
	if err := client.Close(); err != nil {
		t.Fatalf("third Close returned error: %v", err)
	}

	if !client.IsClosed() {
		t.Error("expected IsClosed() == true after double close")
	}

	// Also double-close the server side.
	if err := server.Close(); err != nil {
		t.Fatalf("server first Close returned error: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("server second Close returned error: %v", err)
	}
}

// TestSecureStreamDoubleClose verifies that closing a SecureStream twice
// does not panic and returns nil on both calls.
func TestSecureStreamDoubleClose(t *testing.T) {
	client, server := helpers.CreateSecureStreamPair(t)

	// First close should succeed.
	if err := client.Close(); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}

	// Second close should be a no-op (not panic).
	if err := client.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}

	// Third close for good measure.
	if err := client.Close(); err != nil {
		t.Fatalf("third Close returned error: %v", err)
	}

	if !client.IsClosed() {
		t.Error("expected IsClosed() == true after double close")
	}

	// Also double-close the server side.
	if err := server.Close(); err != nil {
		t.Fatalf("server first Close returned error: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("server second Close returned error: %v", err)
	}
}

// TestChannelCloseAfterSessionClose verifies that closing a channel after
// its parent session is already closed does not panic.
func TestChannelCloseAfterSessionClose(t *testing.T) {
	client, server := helpers.CreateConnectedSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Accept channel on server side.
	acceptDone := make(chan struct{})
	var serverCh *ssh.Channel
	var acceptErr error
	go func() {
		defer close(acceptDone)
		serverCh, acceptErr = server.AcceptChannel(ctx)
	}()

	// Open channel from client.
	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}

	<-acceptDone
	if acceptErr != nil {
		t.Fatalf("AcceptChannel failed: %v", acceptErr)
	}

	// Close the session first.
	client.Close()

	// Wait for both sides to register the close.
	deadline := time.After(5 * time.Second)
	for !client.IsClosed() || !server.IsClosed() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for sessions to close")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Now close the channels after the session is already closed.
	// This must not panic.
	if err := clientCh.Close(); err != nil {
		// Close may return nil or an error; either is fine. No panic is the requirement.
		_ = err
	}
	if err := serverCh.Close(); err != nil {
		_ = err
	}

	// Verify channels report as closed.
	if !clientCh.IsClosed() {
		t.Error("expected client channel IsClosed() == true")
	}
	if !serverCh.IsClosed() {
		t.Error("expected server channel IsClosed() == true")
	}
}

// TestSessionCloseWhileChannelActive verifies that closing a session with
// active channels cleans up all channels without panicking.
func TestSessionCloseWhileChannelActive(t *testing.T) {
	client, server := helpers.CreateConnectedSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	numChannels := 3

	// Accept channels on server side.
	serverChannels := make([]*ssh.Channel, numChannels)
	var acceptWg sync.WaitGroup
	acceptWg.Add(numChannels)

	var mu sync.Mutex
	acceptIdx := 0

	go func() {
		for i := 0; i < numChannels; i++ {
			ch, err := server.AcceptChannel(ctx)
			if err != nil {
				t.Errorf("AcceptChannel %d failed: %v", i, err)
				acceptWg.Done()
				continue
			}
			mu.Lock()
			serverChannels[acceptIdx] = ch
			acceptIdx++
			mu.Unlock()
			acceptWg.Done()
		}
	}()

	// Open channels from client.
	clientChannels := make([]*ssh.Channel, numChannels)
	for i := 0; i < numChannels; i++ {
		ch, err := client.OpenChannel(ctx)
		if err != nil {
			t.Fatalf("OpenChannel %d failed: %v", i, err)
		}
		clientChannels[i] = ch

		// Send some data to make the channel "active".
		if err := ch.Send(ctx, []byte("test data")); err != nil {
			t.Fatalf("Send on channel %d failed: %v", i, err)
		}
	}

	acceptWg.Wait()

	// Track which channels fire OnClosed.
	closedCount := int32(0)
	var closedMu sync.Mutex
	for i := 0; i < numChannels; i++ {
		clientChannels[i].SetClosedHandler(func(args *ssh.ChannelClosedEventArgs) {
			closedMu.Lock()
			closedCount++
			closedMu.Unlock()
		})
	}

	// Close the client session while channels are active.
	// This must not panic.
	client.Close()

	// Wait for the session close to propagate.
	deadline := time.After(5 * time.Second)
	for !client.IsClosed() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for client session to close")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Verify all client channels are closed.
	for i, ch := range clientChannels {
		if !ch.IsClosed() {
			t.Errorf("client channel %d IsClosed() == false after session close", i)
		}
	}

	// Verify OnClosed was called for all channels.
	closedMu.Lock()
	count := closedCount
	closedMu.Unlock()
	if count != int32(numChannels) {
		t.Errorf("expected %d channel OnClosed callbacks, got %d", numChannels, count)
	}

	// Clean up server side.
	server.Close()
}
