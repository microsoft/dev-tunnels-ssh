// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestClientOpenChannelServerAccept verifies that when a client opens a channel,
// the server can accept it, and both sides get valid channels with matching IDs.
func TestClientOpenChannelServerAccept(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var serverCh *Channel
	var acceptErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, acceptErr = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("client.OpenChannel failed: %v", err)
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("server.AcceptChannel failed: %v", acceptErr)
	}

	// Both sides should have valid channels.
	if clientCh == nil {
		t.Fatal("client channel is nil")
	}
	if serverCh == nil {
		t.Fatal("server channel is nil")
	}

	// Client's RemoteChannelID should match server's ChannelID and vice versa.
	if clientCh.RemoteChannelID != serverCh.ChannelID {
		t.Errorf("client.RemoteChannelID = %d, want %d (server.ChannelID)", clientCh.RemoteChannelID, serverCh.ChannelID)
	}
	if serverCh.RemoteChannelID != clientCh.ChannelID {
		t.Errorf("server.RemoteChannelID = %d, want %d (client.ChannelID)", serverCh.RemoteChannelID, clientCh.ChannelID)
	}
}

// TestServerOpenChannelClientAccept verifies that when a server opens a channel,
// the client can accept it (reverse direction).
func TestServerOpenChannelClientAccept(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var clientCh *Channel
	var acceptErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientCh, acceptErr = client.AcceptChannel(ctx)
	}()

	serverCh, err := server.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("server.OpenChannel failed: %v", err)
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("client.AcceptChannel failed: %v", acceptErr)
	}

	if serverCh == nil {
		t.Fatal("server channel is nil")
	}
	if clientCh == nil {
		t.Fatal("client channel is nil")
	}

	if serverCh.RemoteChannelID != clientCh.ChannelID {
		t.Errorf("server.RemoteChannelID = %d, want %d (client.ChannelID)", serverCh.RemoteChannelID, clientCh.ChannelID)
	}
	if clientCh.RemoteChannelID != serverCh.ChannelID {
		t.Errorf("client.RemoteChannelID = %d, want %d (server.ChannelID)", clientCh.RemoteChannelID, serverCh.ChannelID)
	}
}

// TestOpenChannelWithCustomType verifies that a channel opened with a custom type
// preserves the ChannelType on both sides.
func TestOpenChannelWithCustomType(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const customType = "my-custom-channel"

	var serverCh *Channel
	var acceptErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, acceptErr = server.AcceptChannelWithType(ctx, customType)
	}()

	clientCh, err := client.OpenChannelWithType(ctx, customType)
	if err != nil {
		t.Fatalf("client.OpenChannelWithType failed: %v", err)
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("server.AcceptChannelWithType failed: %v", acceptErr)
	}

	if clientCh.ChannelType != customType {
		t.Errorf("client ChannelType = %q, want %q", clientCh.ChannelType, customType)
	}
	if serverCh.ChannelType != customType {
		t.Errorf("server ChannelType = %q, want %q", serverCh.ChannelType, customType)
	}
}

// TestCloseChannelOnClosedFires verifies that closing a channel fires the OnClosed
// callback on both sides.
func TestCloseChannelOnClosedFires(t *testing.T) {
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

	// Set up OnClosed callbacks.
	clientClosed := make(chan struct{})
	serverClosed := make(chan struct{})

	clientCh.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		close(clientClosed)
	})
	serverCh.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		close(serverClosed)
	})

	// Close from client side.
	if err := clientCh.Close(); err != nil {
		t.Fatalf("clientCh.Close failed: %v", err)
	}

	// Wait for both sides to fire OnClosed.
	select {
	case <-clientClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for client channel OnClosed")
	}
	select {
	case <-serverClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server channel OnClosed")
	}

	if !clientCh.IsClosed() {
		t.Error("client channel IsClosed() = false, want true")
	}
	if !serverCh.IsClosed() {
		t.Error("server channel IsClosed() = false, want true")
	}
}

// TestCloseChannelWithExitStatus verifies that closing a channel with an exit status
// delivers the correct ExitStatus via the OnClosed callback.
func TestCloseChannelWithExitStatus(t *testing.T) {
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

	// Set up OnClosed callback on the server side to capture exit status.
	var mu sync.Mutex
	var receivedStatus *uint32
	serverClosed := make(chan struct{})

	serverCh.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		mu.Lock()
		receivedStatus = args.ExitStatus
		mu.Unlock()
		close(serverClosed)
	})

	// Close from client side with exit status 42.
	if err := clientCh.CloseWithStatus(ctx, 42); err != nil {
		t.Fatalf("clientCh.CloseWithStatus failed: %v", err)
	}

	select {
	case <-serverClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server channel OnClosed")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedStatus == nil {
		t.Fatal("ExitStatus is nil, want 42")
	}
	if *receivedStatus != 42 {
		t.Errorf("ExitStatus = %d, want 42", *receivedStatus)
	}
}

// TestCloseChannelWithExitSignal verifies that closing a channel with a signal
// delivers the correct ExitSignal and ErrorMessage via the OnClosed callback.
func TestCloseChannelWithExitSignal(t *testing.T) {
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

	// Set up OnClosed callback on the server side to capture exit signal.
	var mu sync.Mutex
	var receivedSignal string
	var receivedErrorMsg string
	serverClosed := make(chan struct{})

	serverCh.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		mu.Lock()
		receivedSignal = args.ExitSignal
		receivedErrorMsg = args.ErrorMessage
		mu.Unlock()
		close(serverClosed)
	})

	// Close from client side with signal.
	if err := clientCh.CloseWithSignal(ctx, "KILL", "process killed"); err != nil {
		t.Fatalf("clientCh.CloseWithSignal failed: %v", err)
	}

	select {
	case <-serverClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server channel OnClosed")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedSignal != "KILL" {
		t.Errorf("ExitSignal = %q, want %q", receivedSignal, "KILL")
	}
	if receivedErrorMsg != "process killed" {
		t.Errorf("ErrorMessage = %q, want %q", receivedErrorMsg, "process killed")
	}
}

// TestCloseSessionClosesChannels verifies that closing the session closes all
// open channels and fires their OnClosed callbacks.
func TestCloseSessionClosesChannels(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Open multiple channels.
	const numChannels = 3
	clientChannels := make([]*Channel, numChannels)
	serverChannels := make([]*Channel, numChannels)

	for i := 0; i < numChannels; i++ {
		var wg sync.WaitGroup
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			ch, err := server.AcceptChannel(ctx)
			if err != nil {
				t.Errorf("server.AcceptChannel[%d] failed: %v", idx, err)
				return
			}
			serverChannels[idx] = ch
		}()

		ch, err := client.OpenChannel(ctx)
		if err != nil {
			t.Fatalf("client.OpenChannel[%d] failed: %v", i, err)
		}
		clientChannels[i] = ch
		wg.Wait()
	}

	// Set up OnClosed callbacks on all channels.
	clientClosed := make([]chan struct{}, numChannels)
	serverClosed := make([]chan struct{}, numChannels)
	for i := 0; i < numChannels; i++ {
		clientClosed[i] = make(chan struct{})
		serverClosed[i] = make(chan struct{})

		idx := i
		clientChannels[i].SetClosedHandler(func(args *ChannelClosedEventArgs) {
			close(clientClosed[idx])
		})
		serverChannels[i].SetClosedHandler(func(args *ChannelClosedEventArgs) {
			close(serverClosed[idx])
		})
	}

	// Close the client session — all channels should close.
	client.Close()

	// Wait for all channel OnClosed callbacks to fire.
	for i := 0; i < numChannels; i++ {
		select {
		case <-clientClosed[i]:
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for client channel[%d] OnClosed", i)
		}
		select {
		case <-serverClosed[i]:
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for server channel[%d] OnClosed", i)
		}
	}
}

// TestCancelChannelOpen verifies that cancelling the context during a channel
// open returns a context error.
func TestCancelChannelOpen(t *testing.T) {
	client, _ := createSessionPair(t, nil)

	// Use a context that is already cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.OpenChannel(ctx)
	if err == nil {
		t.Fatal("OpenChannel with cancelled context should return error")
	}
	if err != context.Canceled {
		t.Errorf("OpenChannel error = %v, want context.Canceled", err)
	}
}
