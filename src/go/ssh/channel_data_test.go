// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// TestChannelSendSmallData verifies that a client can send 100 bytes through
// a channel and the server receives the exact same data.
func TestChannelSendSmallData(t *testing.T) {
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
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Set up a stream on the server side to read data.
	serverStream := NewStream(serverCh)

	// Send 100 bytes.
	sent := make([]byte, 100)
	rand.Read(sent)
	if err := clientCh.Send(ctx, sent); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Read on server side.
	received := make([]byte, 100)
	n, err := io.ReadFull(serverStream, received)
	if err != nil {
		t.Fatalf("ReadFull failed: %v (read %d bytes)", err, n)
	}

	if !bytes.Equal(sent, received) {
		t.Errorf("data mismatch: sent %d bytes, received %d bytes", len(sent), len(received))
	}
}

// TestChannelSendLargeData verifies that sending >1MB of data works with
// flow control window management. All data should arrive correctly.
func TestChannelSendLargeData(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	// Send 1.5MB of data (exceeds the default 1MB window, forces window adjust).
	const dataSize = 1536 * 1024
	sent := make([]byte, dataSize)
	rand.Read(sent)

	// Send and receive concurrently to avoid deadlock due to flow control.
	var sendErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendErr = clientCh.Send(ctx, sent)
	}()

	received := make([]byte, dataSize)
	n, err := io.ReadFull(serverStream, received)
	if err != nil {
		t.Fatalf("ReadFull failed: %v (read %d of %d bytes)", err, n, dataSize)
	}

	wg.Wait()
	if sendErr != nil {
		t.Fatalf("Send failed: %v", sendErr)
	}

	if !bytes.Equal(sent, received) {
		t.Error("data mismatch for large data transfer")
	}
}

// TestChannelSendIncreasingSizes verifies that data of increasing sizes
// (1B, 1KB, 32KB, 64KB) all arrive correctly through a channel.
func TestChannelSendIncreasingSizes(t *testing.T) {
	client, server := createSessionPair(t, nil)

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

	sizes := []int{1, 1024, 32 * 1024, 64 * 1024}

	for _, size := range sizes {
		sent := make([]byte, size)
		rand.Read(sent)

		if err := clientCh.Send(ctx, sent); err != nil {
			t.Fatalf("Send(%d bytes) failed: %v", size, err)
		}

		received := make([]byte, size)
		n, err := io.ReadFull(serverStream, received)
		if err != nil {
			t.Fatalf("ReadFull(%d bytes) failed: %v (read %d)", size, err, n)
		}

		if !bytes.Equal(sent, received) {
			t.Errorf("data mismatch at size %d", size)
		}
	}
}

// TestParallelChannelData verifies that 10 channels opened in parallel can each
// independently send/receive data without cross-contamination.
func TestParallelChannelData(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const numChannels = 10
	const dataSize = 4096

	type channelPair struct {
		clientCh *Channel
		serverCh *Channel
	}
	pairs := make([]channelPair, numChannels)

	// Open all channels.
	for i := 0; i < numChannels; i++ {
		var wg sync.WaitGroup
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			ch, err := server.AcceptChannel(ctx)
			if err != nil {
				t.Errorf("AcceptChannel[%d] failed: %v", idx, err)
				return
			}
			pairs[idx].serverCh = ch
		}()

		ch, err := client.OpenChannel(ctx)
		if err != nil {
			t.Fatalf("OpenChannel[%d] failed: %v", i, err)
		}
		pairs[i].clientCh = ch
		wg.Wait()
	}

	// Each channel sends unique data and verifies it arrives correctly.
	var wg sync.WaitGroup
	for i := 0; i < numChannels; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			sent := make([]byte, dataSize)
			rand.Read(sent)
			// Tag data with channel index for debugging.
			sent[0] = byte(idx)

			serverStream := NewStream(pairs[idx].serverCh)

			if err := pairs[idx].clientCh.Send(ctx, sent); err != nil {
				t.Errorf("Send[%d] failed: %v", idx, err)
				return
			}

			received := make([]byte, dataSize)
			n, err := io.ReadFull(serverStream, received)
			if err != nil {
				t.Errorf("ReadFull[%d] failed: %v (read %d)", idx, err, n)
				return
			}

			if !bytes.Equal(sent, received) {
				t.Errorf("data mismatch on channel %d", idx)
			}
		}(i)
	}
	wg.Wait()
}

// TestChannelRequestSuccessAndFailure verifies that channel requests return
// true on success and false on failure based on the OnRequest handler.
func TestChannelRequestSuccessAndFailure(t *testing.T) {
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
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Set up the server channel to approve "allowed" requests and reject others.
	serverCh.OnRequest = func(args *RequestEventArgs) {
		if args.RequestType == "allowed" {
			args.IsAuthorized = true
		}
	}

	// Test: allowed request returns true.
	success, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "allowed",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("Request(allowed) error: %v", err)
	}
	if !success {
		t.Error("Request(allowed) = false, want true")
	}

	// Test: denied request returns false.
	success, err = clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "denied",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("Request(denied) error: %v", err)
	}
	if success {
		t.Error("Request(denied) = true, want false")
	}
}

// TestOpenChannelWithInitialRequest verifies that OpenChannelWithRequest
// bundles a channel open and request, and both succeed.
func TestOpenChannelWithInitialRequest(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const channelType = "test-channel"
	const requestType = "test-request"

	var serverCh *Channel
	var mu sync.Mutex

	// Set up the server channel's OnRequest handler during OnChannelOpening,
	// so it's in place before the initial-channel-request extension is processed.
	server.SetChannelOpeningHandler(func(args *ChannelOpeningEventArgs) {
		args.Channel.OnRequest = func(reqArgs *RequestEventArgs) {
			reqArgs.IsAuthorized = true
		}
	})

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ch, err := server.AcceptChannelWithType(ctx, channelType)
		if err != nil {
			t.Errorf("AcceptChannelWithType failed: %v", err)
			return
		}
		mu.Lock()
		serverCh = ch
		mu.Unlock()
	}()

	openMsg := &messages.ChannelOpenMessage{
		ChannelType: channelType,
	}
	initialRequest := &messages.ChannelRequestMessage{
		RequestType: requestType,
		WantReply:   true,
	}

	clientCh, err := client.OpenChannelWithRequest(ctx, openMsg, initialRequest)
	if err != nil {
		t.Fatalf("OpenChannelWithRequest failed: %v", err)
	}

	wg.Wait()

	if clientCh == nil {
		t.Fatal("client channel is nil")
	}

	mu.Lock()
	defer mu.Unlock()

	if serverCh == nil {
		t.Fatal("server channel is nil")
	}

	if clientCh.ChannelType != channelType {
		t.Errorf("client ChannelType = %q, want %q", clientCh.ChannelType, channelType)
	}
	if serverCh.ChannelType != channelType {
		t.Errorf("server ChannelType = %q, want %q", serverCh.ChannelType, channelType)
	}
}
