// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLastIncomingSequenceZero verifies that LastIncomingSequence returns 0
// when no messages have been received (MED-04: prevents uint64 underflow).
func TestLastIncomingSequenceZero(t *testing.T) {
	p := newSSHProtocol(nil, nil)
	seq := p.LastIncomingSequence()
	if seq != 0 {
		t.Errorf("LastIncomingSequence with 0 received = %d, want 0", seq)
	}
}

// TestLastIncomingSequenceAfterReceive verifies normal behavior after messages.
func TestLastIncomingSequenceAfterReceive(t *testing.T) {
	p := newSSHProtocol(nil, nil)
	atomic.StoreUint64(&p.ReceiveSequence, 5)
	seq := p.LastIncomingSequence()
	if seq != 4 {
		t.Errorf("LastIncomingSequence with 5 received = %d, want 4", seq)
	}
}

// TestPipeTerminatesOnContextCancel verifies that pipe goroutines terminate
// when the context is cancelled (MED-05: pipe must not be stuck on context.Background()).
func TestPipeTerminatesOnContextCancel(t *testing.T) {
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
		serverCh1, _ = server1.AcceptChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		serverCh2, _ = server2.AcceptChannel(ctx)
	}()

	_, err := client1.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 1 failed: %v", err)
	}
	_, err = client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 2 failed: %v", err)
	}
	wg.Wait()

	// Create a cancellable context for the pipe.
	pipeCtx, pipeCancel := context.WithCancel(context.Background())
	pipeDone := make(chan error, 1)
	go func() {
		pipeDone <- serverCh1.Pipe(pipeCtx, serverCh2)
	}()

	// Give the pipe a moment to start.
	time.Sleep(50 * time.Millisecond)

	// Cancel the pipe context — pipe should terminate.
	pipeCancel()

	select {
	case err := <-pipeDone:
		if err != context.Canceled {
			t.Errorf("Pipe returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not terminate after context cancellation")
	}
}

// TestPipeTerminatesOnSessionClose verifies that closing a session with an
// active pipe causes the pipe to terminate (MED-05).
func TestPipeTerminatesOnSessionClose(t *testing.T) {
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
		serverCh1, _ = server1.AcceptChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		serverCh2, _ = server2.AcceptChannel(ctx)
	}()

	_, err := client1.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 1 failed: %v", err)
	}
	_, err = client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 2 failed: %v", err)
	}
	wg.Wait()

	// Pipe the two server-side channels together.
	pipeDone := make(chan error, 1)
	go func() {
		pipeDone <- serverCh1.Pipe(ctx, serverCh2)
	}()

	// Give the pipe a moment to start.
	time.Sleep(50 * time.Millisecond)

	// Close server1's session — should cause the pipe to terminate
	// because the channel close will propagate through the pipe.
	server1.Close()

	select {
	case <-pipeDone:
		// Pipe terminated as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not terminate after session close")
	}
}

// TestCurrentAlgorithmsConcurrentAccess verifies that reading currentAlgorithms
// via reconnectSigner/reconnectVerifier is safe when activateNewKeys updates it
// concurrently (MED-09: session lock protects currentAlgorithms).
func TestCurrentAlgorithmsConcurrentAccess(t *testing.T) {
	session := &Session{}

	// Set up initial algorithms.
	session.mu.Lock()
	session.currentAlgorithms = &sessionAlgorithms{
		PublicKeyAlgorithmName: "initial",
	}
	session.mu.Unlock()

	// Concurrently read and write currentAlgorithms.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			// Simulate activateNewKeys writing currentAlgorithms.
			session.mu.Lock()
			session.currentAlgorithms = &sessionAlgorithms{
				PublicKeyAlgorithmName: "updated",
			}
			session.mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			// Simulate reconnectSigner reading currentAlgorithms.
			_ = session.reconnectSigner()
			_ = session.reconnectVerifier()
		}()
	}
	wg.Wait()
}
