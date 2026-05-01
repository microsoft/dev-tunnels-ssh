// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// createPipedSessionPairs creates two session pairs and pipes the server of the
// first pair to the client of the second pair. This simulates a relay:
//
//	clientA <-> serverA --[pipe]--> clientB <-> serverB
//
// Returns clientA (the external client) and serverB (the external server), plus
// a cleanup function that should be deferred.
func createPipedSessionPairs(t *testing.T) (clientA *ClientSession, serverB *ServerSession, pipeDone <-chan error) {
	t.Helper()

	// Pair 1: clientA <-> serverA
	clientA, serverA := createSessionPair(t, nil)

	// Pair 2: clientB <-> serverB
	clientB, serverB := createSessionPair(t, nil)

	// Pipe serverA to clientB in a goroutine.
	pipeErrCh := make(chan error, 1)
	pipeCtx, pipeCancel := context.WithCancel(context.Background())
	t.Cleanup(pipeCancel)

	// Use a ready channel so the caller knows handlers are installed.
	ready := make(chan struct{})
	go func() {
		pipeErrCh <- PipeSession(pipeCtx, &serverA.Session, &clientB.Session)
	}()

	// Wait for PipeSession to install handlers on serverA. Poll until
	// OnRequest is non-nil (PipeSession installs it synchronously).
	go func() {
		for {
			serverA.mu.Lock()
			h := serverA.OnRequest
			serverA.mu.Unlock()
			if h != nil {
				close(ready)
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe handler not installed in time")
	}

	return clientA, serverB, pipeErrCh
}

// TestPipeSessionForwardRequest verifies that a session request sent through
// clientA arrives at serverB via the pipe relay.
func TestPipeSessionForwardRequest(t *testing.T) {
	clientA, serverB, _ := createPipedSessionPairs(t)

	// Set up serverB to accept requests.
	receivedCh := make(chan string, 1)
	serverB.OnRequest = func(args *RequestEventArgs) {
		receivedCh <- args.RequestType
		args.IsAuthorized = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Send a session request from clientA.
	reqMsg := &messages.SessionRequestMessage{
		RequestType: "test-pipe-request",
		WantReply:   true,
	}
	success, err := clientA.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !success {
		t.Error("Request returned false, want true")
	}

	// Verify serverB received the request.
	select {
	case reqType := <-receivedCh:
		if reqType != "test-pipe-request" {
			t.Errorf("received request type = %q, want %q", reqType, "test-pipe-request")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for forwarded request")
	}
}

// TestPipeSessionForwardChannelOpen verifies that a channel opened on clientA
// appears on serverB via the pipe, and data flows end-to-end.
func TestPipeSessionForwardChannelOpen(t *testing.T) {
	clientA, serverB, _ := createPipedSessionPairs(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Open a channel from clientA.
	chA, err := clientA.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel on clientA failed: %v", err)
	}

	// Accept the channel on serverB (it should appear via the pipe).
	chB, err := serverB.AcceptChannel(ctx)
	if err != nil {
		t.Fatalf("AcceptChannel on serverB failed: %v", err)
	}

	// Send data from clientA's channel to serverB's channel.
	testData := []byte("hello through pipe")
	receivedCh := make(chan []byte, 1)
	chB.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		receivedCh <- buf
		chB.AdjustWindow(uint32(len(data)))
	})

	if err := chA.Send(ctx, testData); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	select {
	case received := <-receivedCh:
		if string(received) != string(testData) {
			t.Errorf("received %q, want %q", received, testData)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for data through pipe")
	}

	// Send data in the reverse direction (serverB -> clientA).
	reverseData := []byte("response through pipe")
	reverseReceivedCh := make(chan []byte, 1)
	chA.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		reverseReceivedCh <- buf
		chA.AdjustWindow(uint32(len(data)))
	})

	if err := chB.Send(ctx, reverseData); err != nil {
		t.Fatalf("Reverse send failed: %v", err)
	}

	select {
	case received := <-reverseReceivedCh:
		if string(received) != string(reverseData) {
			t.Errorf("reverse received %q, want %q", received, reverseData)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for reverse data through pipe")
	}
}

// TestPipeSessionClose verifies that closing one side of the pipe causes the
// other side to close, and PipeSession returns.
func TestPipeSessionClose(t *testing.T) {
	// Create the pairs manually so we can observe the pipe result.
	clientA, serverA := createSessionPair(t, nil)
	clientB, serverB := createSessionPair(t, nil)

	pipeErrCh := make(chan error, 1)
	pipeCtx, pipeCancel := context.WithCancel(context.Background())
	defer pipeCancel()
	go func() {
		pipeErrCh <- PipeSession(pipeCtx, &serverA.Session, &clientB.Session)
	}()

	// Give the pipe goroutines time to start.
	time.Sleep(50 * time.Millisecond)

	// Track when serverB closes.
	serverBClosed := make(chan struct{})
	var closeOnce sync.Once
	serverB.OnClosed = func(args *SessionClosedEventArgs) {
		closeOnce.Do(func() { close(serverBClosed) })
	}

	// Close clientA. This should cascade:
	// clientA closes -> serverA closes -> pipe -> clientB closes -> serverB closes.
	_ = clientA.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Verify serverB closes.
	select {
	case <-serverBClosed:
		// OK
	case <-ctx.Done():
		t.Fatal("timed out waiting for serverB to close")
	}

	// Verify PipeSession returned.
	select {
	case err := <-pipeErrCh:
		if err != nil {
			t.Errorf("PipeSession returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for PipeSession to return")
	}
}
