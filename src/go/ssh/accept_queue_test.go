// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"
)

// createNoSecuritySessionPair creates a connected client/server session pair
// using no-security config (kex:none) for fast, simple testing.
func createNoSecuritySessionPair(t *testing.T) (*ClientSession, *ServerSession) {
	t.Helper()

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

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	return client, server
}

// TestAcceptQueueUnbounded verifies that opening 20+ channels without any
// goroutine calling AcceptChannel does not block the dispatch loop.
// The session must remain responsive (able to process close, etc.).
func TestAcceptQueueUnbounded(t *testing.T) {
	client, server := createNoSecuritySessionPair(t)

	const numChannels = 25

	// Open 25 channels from the client side.
	// The server is NOT calling AcceptChannel, so all channels queue up.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	channels := make([]*Channel, numChannels)
	for i := 0; i < numChannels; i++ {
		ch, err := client.OpenChannel(ctx)
		if err != nil {
			t.Fatalf("OpenChannel %d failed: %v", i, err)
		}
		channels[i] = ch
	}

	// Verify session is still responsive: close should complete promptly.
	closeDone := make(chan struct{})
	go func() {
		client.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		// Success: session closed normally despite 25 unaccepted channels.
	case <-time.After(5 * time.Second):
		t.Fatal("session close timed out — dispatch loop is likely blocked")
	}

	// Verify server also detects the close.
	if !server.IsClosed() {
		// Give a brief moment for close to propagate.
		time.Sleep(100 * time.Millisecond)
		if !server.IsClosed() {
			t.Error("server session did not close after client close")
		}
	}
}

// TestAcceptQueueAcceptStillBlocks verifies that AcceptChannel blocks the
// caller until a channel is available, then returns it.
func TestAcceptQueueAcceptStillBlocks(t *testing.T) {
	client, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start accepting on the server before any channel is opened.
	acceptDone := make(chan *Channel, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ch, err := server.AcceptChannel(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		acceptDone <- ch
	}()

	// Give the accept goroutine time to block.
	time.Sleep(50 * time.Millisecond)

	// Verify accept hasn't returned yet (no channel to accept).
	select {
	case <-acceptDone:
		t.Fatal("AcceptChannel returned before any channel was opened")
	case err := <-acceptErr:
		t.Fatalf("AcceptChannel returned error before channel opened: %v", err)
	default:
		// Expected: still blocking.
	}

	// Now open a channel from the client.
	_, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}

	// Accept should now return.
	select {
	case ch := <-acceptDone:
		if ch == nil {
			t.Fatal("AcceptChannel returned nil channel")
		}
	case err := <-acceptErr:
		t.Fatalf("AcceptChannel failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptChannel did not return after channel was opened")
	}
}

// TestChannelOpenPreservesType verifies that when a channel is opened with a
// custom type, the confirmed Channel has the correct ChannelType set on both
// the opener (client) and acceptor (server) sides.
func TestChannelOpenPreservesType(t *testing.T) {
	client, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const customType = "test-custom-type"

	// Accept on the server in a goroutine.
	type acceptResult struct {
		ch  *Channel
		err error
	}
	serverResult := make(chan acceptResult, 1)
	go func() {
		ch, err := server.AcceptChannel(ctx)
		serverResult <- acceptResult{ch, err}
	}()

	// Open a channel with a custom type from the client.
	clientCh, err := client.OpenChannelWithType(ctx, customType)
	if err != nil {
		t.Fatalf("OpenChannelWithType failed: %v", err)
	}

	// Verify client-side channel has correct type.
	if clientCh.ChannelType != customType {
		t.Errorf("client channel type = %q, want %q", clientCh.ChannelType, customType)
	}

	// Verify server-side channel has correct type.
	select {
	case result := <-serverResult:
		if result.err != nil {
			t.Fatalf("server AcceptChannel failed: %v", result.err)
		}
		if result.ch.ChannelType != customType {
			t.Errorf("server channel type = %q, want %q", result.ch.ChannelType, customType)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server AcceptChannel timed out")
	}
}

// TestAcceptQueueCancelledContext verifies that AcceptChannel returns
// promptly when the context is cancelled.
func TestAcceptQueueCancelledContext(t *testing.T) {
	_, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := server.AcceptChannel(ctx)
		done <- err
	}()

	// Cancel the context.
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptChannel did not return after context cancellation")
	}
}

// TestAcceptChannelWithTypeConcurrent verifies that two goroutines accepting
// different channel types concurrently both receive their expected type without
// CPU spin or livelock. This is the core regression test for the broadcast
// notification fix.
func TestAcceptChannelWithTypeConcurrent(t *testing.T) {
	client, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const typeA = "type-alpha"
	const typeB = "type-beta"

	type acceptResult struct {
		ch  *Channel
		err error
	}

	// Start two goroutines each waiting for a different channel type.
	resultA := make(chan acceptResult, 1)
	resultB := make(chan acceptResult, 1)

	go func() {
		ch, err := server.AcceptChannelWithType(ctx, typeA)
		resultA <- acceptResult{ch, err}
	}()
	go func() {
		ch, err := server.AcceptChannelWithType(ctx, typeB)
		resultB <- acceptResult{ch, err}
	}()

	// Give the goroutines time to block.
	time.Sleep(50 * time.Millisecond)

	// Open channels in reverse order: typeB first, then typeA.
	// This ensures the goroutine waiting for typeA isn't just lucky to be first.
	_, err := client.OpenChannelWithType(ctx, typeB)
	if err != nil {
		t.Fatalf("OpenChannelWithType(%q) failed: %v", typeB, err)
	}
	_, err = client.OpenChannelWithType(ctx, typeA)
	if err != nil {
		t.Fatalf("OpenChannelWithType(%q) failed: %v", typeA, err)
	}

	// Both goroutines should return their expected channel type.
	for _, tc := range []struct {
		name   string
		ch     <-chan acceptResult
		expect string
	}{
		{"alpha", resultA, typeA},
		{"beta", resultB, typeB},
	} {
		select {
		case r := <-tc.ch:
			if r.err != nil {
				t.Fatalf("AcceptChannelWithType(%q) failed: %v", tc.expect, r.err)
			}
			if r.ch.ChannelType != tc.expect {
				t.Errorf("goroutine %s: got channel type %q, want %q", tc.name, r.ch.ChannelType, tc.expect)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("AcceptChannelWithType(%q) timed out — possible livelock", tc.expect)
		}
	}
}

// TestAcceptChannelWithTypeCancelledContext verifies that AcceptChannelWithType
// with a specific type returns the context error promptly when cancelled.
func TestAcceptChannelWithTypeCancelledContext(t *testing.T) {
	_, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := server.AcceptChannelWithType(ctx, "some-type")
		done <- err
	}()

	// Cancel the context.
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptChannelWithType did not return after context cancellation")
	}
}
