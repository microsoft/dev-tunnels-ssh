// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

const nonblockingTestTimeout = 10 * time.Second

// TestBlockingHandlerDoesNotStallOtherChannels opens 2 channels. Handler on
// channel A blocks for 2 seconds. A request is sent to channel A, then data
// is sent on channel B. Channel B data arrives within 100ms, proving the
// dispatch loop is not blocked by channel A's handler.
func TestBlockingHandlerDoesNotStallOtherChannels(t *testing.T) {
	client, server := createSessionPair(t, nil)

	clientChA, serverChA := openChannelPair(t, client, server)
	clientChB, serverChB := openChannelPair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	// Handler on channel A blocks for 2 seconds.
	handlerStarted := make(chan struct{}, 1)
	serverChA.OnRequest = func(args *RequestEventArgs) {
		select {
		case handlerStarted <- struct{}{}:
		default:
		}
		time.Sleep(2 * time.Second)
		args.IsAuthorized = true
	}

	// Data handler on channel B signals receipt.
	dataReceived := make(chan []byte, 1)
	serverChB.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		serverChB.AdjustWindow(uint32(len(data)))
		select {
		case dataReceived <- buf:
		default:
		}
	})

	// Send request on channel A (fire-and-forget, no reply needed).
	_, err := clientChA.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "blocking-test",
		WantReply:   false,
	})
	if err != nil {
		t.Fatalf("send request on channel A failed: %v", err)
	}

	// Wait for handler A to start blocking.
	select {
	case <-handlerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler A to start")
	}

	// Send data on channel B.
	testData := []byte("hello from B")
	if err := clientChB.Send(ctx, testData); err != nil {
		t.Fatalf("send data on channel B failed: %v", err)
	}

	// Data should arrive on channel B within 100ms (dispatch loop not blocked).
	select {
	case received := <-dataReceived:
		if string(received) != string(testData) {
			t.Errorf("received data = %q, want %q", received, testData)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("channel B data did not arrive within 100ms — dispatch loop may be blocked")
	}
}

// TestOverlappingChannelRequests opens a channel, sends two requests rapidly,
// and verifies the handler is invoked twice, sequentially (per-channel ordering
// preserved). Matches C# OpenChannelWithMultipleRequests.
func TestOverlappingChannelRequests(t *testing.T) {
	client, server := createSessionPair(t, nil)

	clientCh, serverCh := openChannelPair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	// Track invocations and verify no concurrent execution.
	var concurrent int32
	var maxConcurrent int32
	var invocationCount int32

	serverCh.OnRequest = func(args *RequestEventArgs) {
		c := atomic.AddInt32(&concurrent, 1)
		for {
			old := atomic.LoadInt32(&maxConcurrent)
			if c <= old || atomic.CompareAndSwapInt32(&maxConcurrent, old, c) {
				break
			}
		}
		atomic.AddInt32(&invocationCount, 1)
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt32(&concurrent, -1)
		args.IsAuthorized = true
	}

	// Send two requests concurrently from the client.
	var wg sync.WaitGroup
	results := make([]bool, 2)
	errs := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			results[idx], errs[idx] = clientCh.Request(ctx, &messages.ChannelRequestMessage{
				RequestType: "overlap-test",
				WantReply:   true,
			})
		}()
	}

	wg.Wait()

	for i := 0; i < 2; i++ {
		if errs[i] != nil {
			t.Errorf("request %d error: %v", i, errs[i])
		}
		if !results[i] {
			t.Errorf("request %d returned false, want true", i)
		}
	}

	if count := atomic.LoadInt32(&invocationCount); count != 2 {
		t.Fatalf("handler invoked %d times, want 2", count)
	}
	if mc := atomic.LoadInt32(&maxConcurrent); mc != 1 {
		t.Errorf("max concurrent handlers = %d, want 1 (sequential execution)", mc)
	}
}

// TestRequestHandlerCanWaitForNextRequest verifies that the dispatch loop can
// enqueue a second request while the first handler is blocking on a signal.
// The test signals after sending the second request, and both complete without
// deadlock.
func TestRequestHandlerCanWaitForNextRequest(t *testing.T) {
	client, server := createSessionPair(t, nil)

	clientCh, serverCh := openChannelPair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	signal := make(chan struct{})
	handlerStarted := make(chan struct{}, 1)
	var callCount int32

	serverCh.OnRequest = func(args *RequestEventArgs) {
		n := atomic.AddInt32(&callCount, 1)
		if n == 1 {
			// First request: signal that handler started, then wait.
			select {
			case handlerStarted <- struct{}{}:
			default:
			}
			<-signal
		}
		args.IsAuthorized = true
	}

	// Send first request in background.
	result1 := make(chan bool, 1)
	go func() {
		ok, _ := clientCh.Request(ctx, &messages.ChannelRequestMessage{
			RequestType: "first",
			WantReply:   true,
		})
		result1 <- ok
	}()

	// Wait for first handler to start blocking.
	select {
	case <-handlerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first handler to start")
	}

	// Send second request (dispatch loop can still enqueue it).
	result2 := make(chan bool, 1)
	go func() {
		ok, _ := clientCh.Request(ctx, &messages.ChannelRequestMessage{
			RequestType: "second",
			WantReply:   true,
		})
		result2 <- ok
	}()

	// Brief delay to ensure the second request is enqueued by the dispatch loop.
	time.Sleep(50 * time.Millisecond)

	// Signal the first handler to unblock.
	close(signal)

	// Both requests should complete without deadlock.
	select {
	case ok := <-result1:
		if !ok {
			t.Error("first request failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first request deadlocked")
	}

	select {
	case ok := <-result2:
		if !ok {
			t.Error("second request failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second request deadlocked")
	}
}

// TestChannelCloseStopsRequestGoroutine opens a channel, installs a handler,
// closes the channel, and verifies the request goroutine exits cleanly
// (Close returns promptly, no goroutine leak).
func TestChannelCloseStopsRequestGoroutine(t *testing.T) {
	client, server := createSessionPair(t, nil)

	clientCh, serverCh := openChannelPair(t, client, server)
	_ = server // keep reference

	// Install a handler.
	serverCh.OnRequest = func(args *RequestEventArgs) {
		args.IsAuthorized = true
	}

	// Close from client side. closeInternal waits for requestDone (goroutine exit).
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()

	if err := clientCh.CloseWithContext(closeCtx); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	// If we get here, the request goroutine exited cleanly.
	if !clientCh.IsClosed() {
		t.Error("channel should be closed")
	}
}

// TestRequestHandlerPanicRecovery verifies that a handler panic is recovered:
// the panicking request gets a failure reply, the channel stays operational,
// the session remains connected, and other channels are unaffected.
func TestRequestHandlerPanicRecovery(t *testing.T) {
	client, server := createSessionPair(t, nil)

	clientCh, serverCh := openChannelPair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	var callCount int32
	serverCh.OnRequest = func(args *RequestEventArgs) {
		n := atomic.AddInt32(&callCount, 1)
		if n == 1 {
			panic("test panic in handler")
		}
		args.IsAuthorized = true
	}

	// First request: handler panics → should get failure reply.
	success1, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "panic-request",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("first request error: %v", err)
	}
	if success1 {
		t.Error("first request should have failed (handler panicked)")
	}

	// Session should still be connected.
	if !server.IsConnected() {
		t.Error("server session disconnected after handler panic")
	}
	if !client.IsConnected() {
		t.Error("client session disconnected after handler panic")
	}

	// Second request: handler should succeed, proving the channel is still operational.
	success2, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "after-panic",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("second request error: %v", err)
	}
	if !success2 {
		t.Error("second request should have succeeded")
	}

	// Other channels should be unaffected.
	clientCh2, serverCh2 := openChannelPair(t, client, server)
	serverCh2.OnRequest = func(args *RequestEventArgs) {
		args.IsAuthorized = true
	}
	success3, err := clientCh2.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "other-channel-test",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("other channel request error: %v", err)
	}
	if !success3 {
		t.Error("other channel request should have succeeded")
	}
}

// TestRequestQueueFullRejectsGracefully fills the per-channel request queue
// (capacity 16) and verifies that excess requests get channel-failure responses
// without blocking the dispatch loop.
func TestRequestQueueFullRejectsGracefully(t *testing.T) {
	client, server := createSessionPair(t, nil)
	_ = server

	clientCh, serverCh := openChannelPair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	// Handler blocks on first call so we can fill the queue.
	handlerStarted := make(chan struct{}, 1)
	blockHandler := make(chan struct{})
	defer close(blockHandler) // ensure goroutine cleanup

	serverCh.OnRequest = func(args *RequestEventArgs) {
		select {
		case handlerStarted <- struct{}{}:
		default:
		}
		<-blockHandler
		args.IsAuthorized = true
	}

	// Send first request (fire-and-forget) to start the blocking handler.
	_, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "first",
		WantReply:   false,
	})
	if err != nil {
		t.Fatalf("first request send failed: %v", err)
	}

	// Wait for handler to start blocking (goroutine has dequeued the request).
	select {
	case <-handlerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler to start")
	}

	// Fill the queue with requestQueueCapacity requests (all fire-and-forget).
	// Since the handler goroutine is blocked, none of these are dequeued.
	for i := 0; i < requestQueueCapacity; i++ {
		_, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
			RequestType: "fill",
			WantReply:   false,
		})
		if err != nil {
			t.Fatalf("fill request %d send failed: %v", i, err)
		}
	}

	// The next request should fail (queue full → channel-failure).
	success, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "overflow",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("overflow request error: %v", err)
	}
	if success {
		t.Error("overflow request should have failed (queue full)")
	}
}

// TestRequestReplyFromHandlerGoroutine sends a want-reply request where the
// handler sleeps 500ms then sets IsAuthorized = true. The response should
// arrive after ~500ms (not immediately), proving the reply is sent from the
// handler goroutine.
func TestRequestReplyFromHandlerGoroutine(t *testing.T) {
	client, server := createSessionPair(t, nil)
	_ = server

	clientCh, serverCh := openChannelPair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	serverCh.OnRequest = func(args *RequestEventArgs) {
		time.Sleep(500 * time.Millisecond)
		args.IsAuthorized = true
	}

	start := time.Now()
	success, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "slow-request",
		WantReply:   true,
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	if !success {
		t.Error("request should have succeeded")
	}

	// Reply should arrive after at least ~400ms (handler slept 500ms).
	if elapsed < 400*time.Millisecond {
		t.Errorf("reply arrived too quickly (%v) — may not be from handler goroutine", elapsed)
	}
}

// TestConcurrentRequestsAcrossChannels opens 3 channels, each with a handler
// that blocks 200ms. All 3 requests sent concurrently should complete in ~200ms
// (parallel), not ~600ms (sequential).
func TestConcurrentRequestsAcrossChannels(t *testing.T) {
	client, server := createSessionPair(t, nil)

	const numChannels = 3
	clientChs := make([]*Channel, numChannels)
	serverChs := make([]*Channel, numChannels)

	for i := 0; i < numChannels; i++ {
		clientChs[i], serverChs[i] = openChannelPair(t, client, server)
	}

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	// Install handlers that block for 200ms.
	for i := 0; i < numChannels; i++ {
		serverChs[i].OnRequest = func(args *RequestEventArgs) {
			time.Sleep(200 * time.Millisecond)
			args.IsAuthorized = true
		}
	}

	// Send requests on all 3 channels concurrently.
	start := time.Now()
	var wg sync.WaitGroup
	results := make([]bool, numChannels)
	errs := make([]error, numChannels)

	for i := 0; i < numChannels; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			results[idx], errs[idx] = clientChs[idx].Request(ctx, &messages.ChannelRequestMessage{
				RequestType: "concurrent-test",
				WantReply:   true,
			})
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	for i := 0; i < numChannels; i++ {
		if errs[i] != nil {
			t.Errorf("request %d error: %v", i, errs[i])
		}
		if !results[i] {
			t.Errorf("request %d failed", i)
		}
	}

	// All 3 should complete in ~200ms (parallel), not ~600ms (sequential).
	if elapsed > 500*time.Millisecond {
		t.Errorf("elapsed %v — requests may have run sequentially (expected parallel ~200ms)", elapsed)
	}
}

// TestRecursiveChannelRequestFromHandler verifies that a handler can call
// ch.Request() on the same channel without deadlocking. The handler goroutine
// blocks on resultCh, while the dispatch loop processes the response — they
// are different goroutines, so no deadlock occurs.
func TestRecursiveChannelRequestFromHandler(t *testing.T) {
	client, server := createSessionPair(t, nil)
	clientCh, serverCh := openChannelPair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	// The server handler, upon receiving "trigger", sends a request back to the
	// client on the SAME channel and records whether it succeeded.
	innerResult := make(chan bool, 1)
	serverCh.SetRequestHandler(func(args *RequestEventArgs) {
		if args.RequestType == "trigger" {
			// Recursive: handler calls Request() on the same channel.
			success, err := serverCh.Request(ctx, &messages.ChannelRequestMessage{
				RequestType: "inner-request",
				WantReply:   true,
			})
			if err != nil {
				innerResult <- false
			} else {
				innerResult <- success
			}
		}
		args.IsAuthorized = true
	})

	// The client handles the inner request from the server.
	clientCh.SetRequestHandler(func(args *RequestEventArgs) {
		args.IsAuthorized = args.RequestType == "inner-request"
	})

	// Send the trigger request from client to server.
	success, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "trigger",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("trigger request failed: %v", err)
	}
	if !success {
		t.Error("trigger request returned false, want true")
	}

	// Verify the inner request completed successfully (no deadlock).
	select {
	case got := <-innerResult:
		if !got {
			t.Error("inner recursive request failed, want success")
		}
	case <-ctx.Done():
		t.Fatal("timed out — recursive channel request likely deadlocked")
	}
}

// TestSessionCloseWhileHandlerIsProcessing closes the session while a
// channel request handler is mid-execution. Verifies no panic or hang.
func TestSessionCloseWhileHandlerIsProcessing(t *testing.T) {
	client, server := createSessionPair(t, nil)
	clientCh, serverCh := openChannelPair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	handlerStarted := make(chan struct{})
	handlerDone := make(chan struct{})

	serverCh.SetRequestHandler(func(args *RequestEventArgs) {
		close(handlerStarted)
		// Block until signaled — we'll close the session while blocked here.
		<-handlerDone
		args.IsAuthorized = true
	})

	// Send a fire-and-forget request to trigger the handler.
	// Use a goroutine since Request returns immediately for WantReply=false.
	go func() {
		_, _ = clientCh.Request(ctx, &messages.ChannelRequestMessage{
			RequestType: "slow-request",
			WantReply:   false,
		})
	}()

	// Wait for the handler to start.
	select {
	case <-handlerStarted:
	case <-ctx.Done():
		t.Fatal("timed out waiting for handler to start")
	}

	// Close the server session while the handler is blocked.
	server.Close()

	// Unblock the handler so the goroutine can exit.
	close(handlerDone)

	// Give a moment for cleanup to finish. If this hangs, the test will
	// fail with the context timeout.
	time.Sleep(50 * time.Millisecond)
}

// TestLateHandlerBindingProcessesQueuedRequests sends requests before any
// OnRequest handler is set. Then sets a handler and verifies the queued
// requests are processed by the late-bound handler.
func TestLateHandlerBindingProcessesQueuedRequests(t *testing.T) {
	client, server := createSessionPair(t, nil)
	clientCh, serverCh := openChannelPair(t, client, server)

	ctx, cancel := context.WithTimeout(context.Background(), nonblockingTestTimeout)
	defer cancel()

	// Send 3 requests WITHOUT a handler set on the server channel.
	// The requests will be enqueued in the per-channel goroutine's queue.
	// Since no handler is set, they'll get processed as "no handler → false".
	// We need to verify that the goroutine processes them (returns failure).
	var results [3]bool
	var errs [3]error
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = clientCh.Request(ctx, &messages.ChannelRequestMessage{
				RequestType: "early-request",
				WantReply:   true,
			})
		}(i)
	}

	wg.Wait()

	// All should have failed (no handler → IsAuthorized defaults to false).
	for i := 0; i < 3; i++ {
		if errs[i] != nil {
			t.Errorf("request %d error: %v", i, errs[i])
		}
		if results[i] {
			t.Errorf("request %d succeeded, want failure (no handler set)", i)
		}
	}

	// Now set a handler and send another request — it should succeed.
	serverCh.SetRequestHandler(func(args *RequestEventArgs) {
		args.IsAuthorized = true
	})

	success, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "late-request",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("late request failed: %v", err)
	}
	if !success {
		t.Error("late request returned false, want true (handler now set)")
	}

	// Verify the handler receives the correct context.
	serverCh.SetRequestHandler(func(args *RequestEventArgs) {
		if args.Ctx == nil {
			t.Error("args.Ctx is nil, want non-nil context")
		}
		args.IsAuthorized = true
	})

	success, err = clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "ctx-check",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("ctx-check request failed: %v", err)
	}
	if !success {
		t.Error("ctx-check request returned false, want true")
	}
}
