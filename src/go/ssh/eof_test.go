// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestOnEofCallbackFires verifies that setting an OnEof handler on a channel
// causes it to fire when the peer sends EOF.
func TestOnEofCallbackFires(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Accept the channel on the server side.
	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		serverCh, err = server.AcceptChannel(ctx)
		if err != nil {
			t.Errorf("AcceptChannel failed: %v", err)
		}
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Set the OnEof handler on the server-side channel.
	eofReceived := make(chan struct{})
	serverCh.SetEofHandler(func() {
		close(eofReceived)
	})

	// Client sends EOF (by sending nil/empty data).
	if err := clientCh.Send(ctx, nil); err != nil {
		t.Fatalf("Send EOF failed: %v", err)
	}

	// Verify the callback fires.
	select {
	case <-eofReceived:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("OnEof callback did not fire within timeout")
	}
}

// TestPipeForwardsEof verifies that when two channels are piped together,
// an EOF sent on one side is forwarded through the pipe to the other side.
func TestPipeForwardsEof(t *testing.T) {
	client1, server1 := createSessionPair(t, nil)
	client2, server2 := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open channels on both session pairs.
	var serverCh1, serverCh2 *Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		serverCh1, err = server1.AcceptChannel(ctx)
		if err != nil {
			t.Errorf("AcceptChannel 1 failed: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		var err error
		serverCh2, err = server2.AcceptChannel(ctx)
		if err != nil {
			t.Errorf("AcceptChannel 2 failed: %v", err)
		}
	}()

	clientCh1, err := client1.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 1 failed: %v", err)
	}
	clientCh2, err := client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 2 failed: %v", err)
	}
	wg.Wait()

	// Set an OnEof handler on client2's channel to detect the forwarded EOF.
	eofReceived := make(chan struct{})
	clientCh2.SetEofHandler(func() {
		close(eofReceived)
	})

	// Pipe the two server-side channels together.
	pipeReady := make(chan struct{})
	go func() {
		// Signal that we're about to call Pipe (handlers will be installed
		// synchronously at the start of Pipe before it blocks).
		close(pipeReady)
		_ = serverCh1.Pipe(ctx, serverCh2)
	}()
	// Wait for the goroutine to start, then allow time for Pipe's synchronous
	// handler installation to complete.
	<-pipeReady
	time.Sleep(50 * time.Millisecond)

	// Client1 sends EOF.
	if err := clientCh1.Send(ctx, nil); err != nil {
		t.Fatalf("Send EOF failed: %v", err)
	}

	// Verify the EOF arrives on client2's side (forwarded through the pipe).
	select {
	case <-eofReceived:
		// Success — EOF was forwarded through the pipe.
	case <-time.After(5 * time.Second):
		t.Fatal("Forwarded EOF did not arrive on client2 within timeout")
	}
}
