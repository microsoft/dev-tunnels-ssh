// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// TestStandaloneSignalDeliveredToOnRequest verifies that a standalone "signal"
// channel request (e.g. TERM) is delivered to the OnRequest handler, not consumed
// internally by handleSignal.
func TestStandaloneSignalDeliveredToOnRequest(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		t.Fatalf("client.OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Set up OnRequest handler on the server channel to capture the signal.
	var mu sync.Mutex
	var receivedRequestType string
	var receivedSignalMsg *messages.ChannelSignalMessage
	requestReceived := make(chan struct{})

	serverCh.OnRequest = func(args *RequestEventArgs) {
		mu.Lock()
		receivedRequestType = args.RequestType
		if msg, ok := args.Request.(*messages.ChannelSignalMessage); ok {
			receivedSignalMsg = msg
		}
		args.IsAuthorized = true
		mu.Unlock()
		close(requestReceived)
	}

	// Send a standalone signal from client.
	signalMsg := &messages.ChannelSignalMessage{
		RecipientChannel: clientCh.RemoteChannelID,
		RequestType:      "signal",
		WantReply:        false,
		Signal:           "TERM",
	}
	if err := client.SendMessage(signalMsg); err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}

	select {
	case <-requestReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for signal to arrive at OnRequest")
	}

	mu.Lock()
	defer mu.Unlock()

	if receivedRequestType != "signal" {
		t.Errorf("RequestType = %q, want %q", receivedRequestType, "signal")
	}
	if receivedSignalMsg == nil {
		t.Fatal("expected ChannelSignalMessage in Request, got nil")
	}
	if receivedSignalMsg.Signal != "TERM" {
		t.Errorf("Signal = %q, want %q", receivedSignalMsg.Signal, "TERM")
	}
}

// TestSendSignalMethod verifies that Channel.SendSignal sends a properly
// formatted signal channel request that the peer receives via OnRequest.
func TestSendSignalMethod(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		t.Fatalf("client.OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Set up OnRequest handler on the server channel.
	var mu sync.Mutex
	var receivedRequestType string
	var receivedSignalName string
	requestReceived := make(chan struct{})

	serverCh.OnRequest = func(args *RequestEventArgs) {
		mu.Lock()
		receivedRequestType = args.RequestType
		if msg, ok := args.Request.(*messages.ChannelSignalMessage); ok {
			receivedSignalName = msg.Signal
		}
		args.IsAuthorized = true
		mu.Unlock()
		close(requestReceived)
	}

	// Use SendSignal method.
	if err := clientCh.SendSignal(ctx, "TERM"); err != nil {
		t.Fatalf("SendSignal failed: %v", err)
	}

	select {
	case <-requestReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for signal to arrive at OnRequest")
	}

	mu.Lock()
	defer mu.Unlock()

	if receivedRequestType != "signal" {
		t.Errorf("RequestType = %q, want %q", receivedRequestType, "signal")
	}
	if receivedSignalName != "TERM" {
		t.Errorf("Signal = %q, want %q", receivedSignalName, "TERM")
	}
}

// TestExitStatusStillConsumedInternally verifies that exit-status messages
// are still consumed internally by handleSignal (not passed to OnRequest).
func TestExitStatusStillConsumedInternally(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		t.Fatalf("client.OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Set up OnRequest handler — exit-status should NOT arrive here.
	onRequestCalled := make(chan struct{}, 1)
	serverCh.OnRequest = func(args *RequestEventArgs) {
		onRequestCalled <- struct{}{}
	}

	serverClosed := make(chan *ChannelClosedEventArgs, 1)
	serverCh.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		serverClosed <- args
	})

	// Close from client with exit status — this sends exit-status internally.
	if err := clientCh.CloseWithStatus(ctx, 42); err != nil {
		t.Fatalf("CloseWithStatus failed: %v", err)
	}

	// Wait for server channel to close.
	select {
	case args := <-serverClosed:
		if args.ExitStatus == nil {
			t.Fatal("ExitStatus is nil, want 42")
		}
		if *args.ExitStatus != 42 {
			t.Errorf("ExitStatus = %d, want 42", *args.ExitStatus)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server channel close")
	}

	// Verify OnRequest was NOT called for exit-status.
	select {
	case <-onRequestCalled:
		t.Error("OnRequest was called for exit-status — it should be consumed internally")
	default:
		// Good — OnRequest was not called.
	}
}

// TestExitSignalStillConsumedInternally verifies that exit-signal messages
// are still consumed internally by handleSignal (not passed to OnRequest).
func TestExitSignalStillConsumedInternally(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
		t.Fatalf("client.OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Set up OnRequest handler — exit-signal should NOT arrive here.
	onRequestCalled := make(chan struct{}, 1)
	serverCh.OnRequest = func(args *RequestEventArgs) {
		onRequestCalled <- struct{}{}
	}

	serverClosed := make(chan *ChannelClosedEventArgs, 1)
	serverCh.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		serverClosed <- args
	})

	// Close from client with signal.
	if err := clientCh.CloseWithSignal(ctx, "KILL", "process killed"); err != nil {
		t.Fatalf("CloseWithSignal failed: %v", err)
	}

	// Wait for server channel to close.
	select {
	case args := <-serverClosed:
		if args.ExitSignal != "KILL" {
			t.Errorf("ExitSignal = %q, want %q", args.ExitSignal, "KILL")
		}
		if args.ErrorMessage != "process killed" {
			t.Errorf("ErrorMessage = %q, want %q", args.ErrorMessage, "process killed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server channel close")
	}

	// Verify OnRequest was NOT called for exit-signal.
	select {
	case <-onRequestCalled:
		t.Error("OnRequest was called for exit-signal — it should be consumed internally")
	default:
		// Good — OnRequest was not called.
	}
}
