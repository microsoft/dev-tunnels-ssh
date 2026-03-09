// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

const pipeRequestTestTimeout = 10 * time.Second

// createChannelPipePairs creates two session pairs, opens a channel on each,
// and pipes the server-side channel of pair1 with the client-side channel of
// pair2 to form a relay:
//
//	clientCh1 <-> serverCh1 --[pipe]--> clientCh2 <-> serverCh2
//
// Returns clientCh1 (the external sender) and serverCh2 (the external receiver).
// The pipe goroutine runs in the background until either channel closes.
func createChannelPipePairs(t *testing.T) (clientCh1, serverCh2 *Channel) {
	t.Helper()

	// Session pair 1.
	client1, server1 := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), pipeRequestTestTimeout)
	defer cancel()

	var serverCh1 *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var acceptErr error
		serverCh1, acceptErr = server1.AcceptChannel(ctx)
		if acceptErr != nil {
			t.Errorf("server1.AcceptChannel failed: %v", acceptErr)
		}
	}()

	var err error
	clientCh1, err = client1.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("client1.OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Session pair 2.
	client2, server2 := createSessionPair(t, nil)

	var clientCh2 *Channel
	wg.Add(1)
	go func() {
		defer wg.Done()
		var acceptErr error
		serverCh2, acceptErr = server2.AcceptChannel(ctx)
		if acceptErr != nil {
			t.Errorf("server2.AcceptChannel failed: %v", acceptErr)
		}
	}()

	clientCh2, err = client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("client2.OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Pipe serverCh1 <-> clientCh2 in the background.
	go func() {
		_ = serverCh1.Pipe(context.Background(), clientCh2)
	}()

	// Give the pipe handlers a moment to be installed.
	time.Sleep(20 * time.Millisecond)

	return clientCh1, serverCh2
}

// TestPipeForwardsChannelRequest pipes two channels on separate session pairs,
// sends a channel request on channel A (clientCh1), and verifies it arrives on
// channel B's remote end (serverCh2). Matches C# PipeChannelPendingRequest.
func TestPipeForwardsChannelRequest(t *testing.T) {
	clientCh1, serverCh2 := createChannelPipePairs(t)

	ctx, cancel := context.WithTimeout(context.Background(), pipeRequestTestTimeout)
	defer cancel()

	// Install a request handler on the far end that records the request type.
	receivedCh := make(chan string, 1)
	serverCh2.SetRequestHandler(func(args *RequestEventArgs) {
		receivedCh <- args.RequestType
		args.IsAuthorized = true
	})

	// Send a channel request from clientCh1.
	reqMsg := &messages.ChannelRequestMessage{
		RequestType: "test-pipe-forward",
		WantReply:   true,
	}
	success, err := clientCh1.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !success {
		t.Error("Request returned false, want true")
	}

	// Verify the request was forwarded to serverCh2.
	select {
	case reqType := <-receivedCh:
		if reqType != "test-pipe-forward" {
			t.Errorf("received request type = %q, want %q", reqType, "test-pipe-forward")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for forwarded channel request")
	}
}

// TestPipeForwardsRequestBidirectionally pipes two channels and sends channel
// requests in both directions. Verifies both are forwarded correctly.
func TestPipeForwardsRequestBidirectionally(t *testing.T) {
	client1, server1 := createSessionPair(t, nil)
	client2, server2 := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), pipeRequestTestTimeout)
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

	clientCh1, err := client1.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("client1.OpenChannel failed: %v", err)
	}
	clientCh2, err := client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("client2.OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Pipe serverCh1 <-> clientCh2 in the background.
	go func() {
		_ = serverCh1.Pipe(context.Background(), clientCh2)
	}()

	// Give the pipe handlers time to install.
	time.Sleep(20 * time.Millisecond)

	// Install handlers on both external ends.
	received1 := make(chan string, 1)
	serverCh2.SetRequestHandler(func(args *RequestEventArgs) {
		received1 <- args.RequestType
		args.IsAuthorized = true
	})

	received2 := make(chan string, 1)
	clientCh1.SetRequestHandler(func(args *RequestEventArgs) {
		received2 <- args.RequestType
		args.IsAuthorized = true
	})

	// Direction 1: clientCh1 -> serverCh2 (through pipe).
	success, err := clientCh1.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "forward-direction",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("forward request failed: %v", err)
	}
	if !success {
		t.Error("forward request returned false, want true")
	}

	select {
	case reqType := <-received1:
		if reqType != "forward-direction" {
			t.Errorf("forward: received request type = %q, want %q", reqType, "forward-direction")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for forward direction request")
	}

	// Direction 2: clientCh2 -> clientCh1 (reverse through pipe).
	// clientCh2 sends a request, which goes to serverCh2 (remote of clientCh2),
	// but what we want is: serverCh2 sends to the pipe, which sends to clientCh1.
	// Actually, the reverse direction: send request from serverCh2's client side.
	// In the pipe setup, requests arriving on clientCh2 are forwarded to serverCh1,
	// and serverCh1's response goes back to clientCh2.
	// But for bidirectional test, we need to test: request from clientCh2 side.
	// Actually, channel requests come from the remote end. Let's send from serverCh2.
	success, err = serverCh2.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "reverse-direction",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("reverse request failed: %v", err)
	}
	if !success {
		t.Error("reverse request returned false, want true")
	}

	select {
	case reqType := <-received2:
		if reqType != "reverse-direction" {
			t.Errorf("reverse: received request type = %q, want %q", reqType, "reverse-direction")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for reverse direction request")
	}
}

// TestPipeForwardsRequestWithReply sends a want_reply channel request through
// a piped channel. The far-end handler rejects the request (IsAuthorized=false),
// and verifies the failure reply propagates back to the original sender.
func TestPipeForwardsRequestWithReply(t *testing.T) {
	clientCh1, serverCh2 := createChannelPipePairs(t)

	ctx, cancel := context.WithTimeout(context.Background(), pipeRequestTestTimeout)
	defer cancel()

	// Handler on the far end rejects the request.
	serverCh2.SetRequestHandler(func(args *RequestEventArgs) {
		args.IsAuthorized = false
	})

	// Send a want-reply request that should be rejected.
	success, err := clientCh1.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "reject-me",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if success {
		t.Error("Request returned true, want false (handler rejected)")
	}

	// Now test with an approving handler.
	serverCh2.SetRequestHandler(func(args *RequestEventArgs) {
		args.IsAuthorized = true
	})

	success, err = clientCh1.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "approve-me",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !success {
		t.Error("Request returned false, want true (handler approved)")
	}

	// Test fire-and-forget (want_reply = false).
	success, err = clientCh1.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "fire-and-forget",
		WantReply:   false,
	})
	if err != nil {
		t.Fatalf("fire-and-forget Request failed: %v", err)
	}
	if !success {
		t.Error("fire-and-forget should return true")
	}
}

// TestPipeForwardsRequestWithPayload pipes two channels and sends a channel
// request with type-specific payload data. Verifies the payload arrives intact
// on the far end, matching C#'s behavior of forwarding the complete message
// including type-specific fields.
func TestPipeForwardsRequestWithPayload(t *testing.T) {
	clientCh1, serverCh2 := createChannelPipePairs(t)

	ctx, cancel := context.WithTimeout(context.Background(), pipeRequestTestTimeout)
	defer cancel()

	// Construct a payload with recognizable data.
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

	// Install a handler on the far end that captures the full request message.
	receivedCh := make(chan *messages.ChannelRequestMessage, 1)
	serverCh2.SetRequestHandler(func(args *RequestEventArgs) {
		reqMsg, ok := args.Request.(*messages.ChannelRequestMessage)
		if ok {
			receivedCh <- reqMsg
		}
		args.IsAuthorized = true
	})

	// Send a channel request with payload from clientCh1.
	reqMsg := &messages.ChannelRequestMessage{
		RequestType: "test-with-payload",
		WantReply:   true,
		Payload:     payload,
	}
	success, err := clientCh1.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !success {
		t.Error("Request returned false, want true")
	}

	// Verify the request was forwarded with payload intact.
	select {
	case received := <-receivedCh:
		if received.RequestType != "test-with-payload" {
			t.Errorf("received request type = %q, want %q", received.RequestType, "test-with-payload")
		}
		if len(received.Payload) != len(payload) {
			t.Fatalf("received payload length = %d, want %d", len(received.Payload), len(payload))
		}
		for i, b := range received.Payload {
			if b != payload[i] {
				t.Errorf("payload[%d] = 0x%02X, want 0x%02X", i, b, payload[i])
			}
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for forwarded channel request with payload")
	}
}

// TestPipeForwardsRequestPayloadBidirectionally pipes two channels and verifies
// payload data is preserved in both directions through the pipe.
func TestPipeForwardsRequestPayloadBidirectionally(t *testing.T) {
	client1, server1 := createSessionPair(t, nil)
	client2, server2 := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), pipeRequestTestTimeout)
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

	clientCh1, err := client1.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("client1.OpenChannel failed: %v", err)
	}
	clientCh2, err := client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("client2.OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Pipe serverCh1 <-> clientCh2 in the background.
	go func() {
		_ = serverCh1.Pipe(context.Background(), clientCh2)
	}()

	// Give the pipe handlers time to install.
	time.Sleep(20 * time.Millisecond)

	// Install handlers on both external ends to capture payload.
	received1 := make(chan []byte, 1)
	serverCh2.SetRequestHandler(func(args *RequestEventArgs) {
		reqMsg, ok := args.Request.(*messages.ChannelRequestMessage)
		if ok {
			payloadCopy := make([]byte, len(reqMsg.Payload))
			copy(payloadCopy, reqMsg.Payload)
			received1 <- payloadCopy
		}
		args.IsAuthorized = true
	})

	received2 := make(chan []byte, 1)
	clientCh1.SetRequestHandler(func(args *RequestEventArgs) {
		reqMsg, ok := args.Request.(*messages.ChannelRequestMessage)
		if ok {
			payloadCopy := make([]byte, len(reqMsg.Payload))
			copy(payloadCopy, reqMsg.Payload)
			received2 <- payloadCopy
		}
		args.IsAuthorized = true
	})

	// Direction 1: clientCh1 -> serverCh2 (through pipe).
	forwardPayload := []byte("forward-payload-data")
	_, err = clientCh1.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "fwd",
		WantReply:   true,
		Payload:     forwardPayload,
	})
	if err != nil {
		t.Fatalf("forward request failed: %v", err)
	}

	select {
	case got := <-received1:
		if string(got) != string(forwardPayload) {
			t.Errorf("forward payload = %q, want %q", got, forwardPayload)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for forward direction payload")
	}

	// Direction 2: serverCh2 -> clientCh1 (reverse through pipe).
	reversePayload := []byte("reverse-payload-data")
	_, err = serverCh2.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "rev",
		WantReply:   true,
		Payload:     reversePayload,
	})
	if err != nil {
		t.Fatalf("reverse request failed: %v", err)
	}

	select {
	case got := <-received2:
		if string(got) != string(reversePayload) {
			t.Errorf("reverse payload = %q, want %q", got, reversePayload)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for reverse direction payload")
	}
}

// TestPipeRequestForwardWithClose pipes channels, sends a request, then closes.
// Verifies clean shutdown with no hanging goroutines.
func TestPipeRequestForwardWithClose(t *testing.T) {
	client1, server1 := createSessionPair(t, nil)
	client2, server2 := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), pipeRequestTestTimeout)
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

	clientCh1, err := client1.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("client1.OpenChannel failed: %v", err)
	}
	clientCh2, err := client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("client2.OpenChannel failed: %v", err)
	}
	wg.Wait()

	// Pipe serverCh1 <-> clientCh2 in the background.
	pipeDone := make(chan error, 1)
	go func() {
		pipeDone <- serverCh1.Pipe(context.Background(), clientCh2)
	}()

	// Give the pipe handlers time to install.
	time.Sleep(20 * time.Millisecond)

	// Install a handler on the far end and send a request to prove forwarding works.
	receivedCh := make(chan struct{}, 1)
	serverCh2.SetRequestHandler(func(args *RequestEventArgs) {
		receivedCh <- struct{}{}
		args.IsAuthorized = true
	})

	success, err := clientCh1.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "pre-close-request",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("Request before close failed: %v", err)
	}
	if !success {
		t.Error("pre-close request should have succeeded")
	}

	select {
	case <-receivedCh:
		// OK — request was forwarded.
	case <-ctx.Done():
		t.Fatal("timed out waiting for pre-close request")
	}

	// Close clientCh1 — should propagate through the pipe and cleanly shut down.
	if err := clientCh1.CloseWithContext(ctx); err != nil {
		t.Fatalf("Close clientCh1 failed: %v", err)
	}

	// Verify the pipe terminates cleanly.
	select {
	case err := <-pipeDone:
		if err != nil {
			t.Errorf("Pipe returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not terminate after close")
	}

	// Verify both piped channels are closed.
	if !serverCh1.IsClosed() {
		t.Error("serverCh1 should be closed after pipe shutdown")
	}
}
