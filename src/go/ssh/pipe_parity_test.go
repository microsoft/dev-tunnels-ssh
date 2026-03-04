// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

const pipeParityTimeout = 10 * time.Second

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

	ctx, cancel := context.WithTimeout(context.Background(), pipeParityTimeout)
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

// TestChannelPipeForwardData pipes two channels on separate session pairs, sends
// 1KB data on channel A, and verifies it arrives on channel B.
// Matches C#/TS PipeTests.ChannelPipeForwardData.
func TestChannelPipeForwardData(t *testing.T) {
	clientCh1, serverCh2 := createChannelPipePairs(t)

	ctx, cancel := context.WithTimeout(context.Background(), pipeParityTimeout)
	defer cancel()

	// Send 1KB of random data from clientCh1.
	payload := make([]byte, 1024)
	rand.Read(payload)

	receivedCh := make(chan []byte, 1)
	serverCh2.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		receivedCh <- buf
		serverCh2.AdjustWindow(uint32(len(data)))
	})

	if err := clientCh1.Send(ctx, payload); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Collect received data (may arrive in chunks).
	var received []byte
	deadline := time.After(5 * time.Second)
	for len(received) < len(payload) {
		select {
		case chunk := <-receivedCh:
			received = append(received, chunk...)
		case <-deadline:
			t.Fatalf("timed out waiting for data: received %d/%d bytes", len(received), len(payload))
		}
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("data mismatch: received %d bytes, want %d bytes", len(received), len(payload))
	}
}

// TestSessionPipeForwardRequest pipes two sessions via PipeSession, sends a
// session request on one, and verifies it arrives on the other's OnRequest.
// Depends on US-009. Matches C#/TS PipeTests.SessionPipeForwardRequest.
func TestSessionPipeForwardRequest(t *testing.T) {
	clientA, serverB, _ := createPipedSessionPairs(t)

	receivedCh := make(chan string, 1)
	serverB.OnRequest = func(args *RequestEventArgs) {
		receivedCh <- args.RequestType
		args.IsAuthorized = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), pipeParityTimeout)
	defer cancel()

	reqMsg := &messages.SessionRequestMessage{
		RequestType: "parity-pipe-request",
		WantReply:   true,
	}
	success, err := clientA.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !success {
		t.Error("Request returned false, want true")
	}

	select {
	case reqType := <-receivedCh:
		if reqType != "parity-pipe-request" {
			t.Errorf("received request type = %q, want %q", reqType, "parity-pipe-request")
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for forwarded request")
	}
}

// TestSessionPipeForwardChannelOpen pipes two sessions, opens a channel on
// session A's remote side, and verifies a corresponding channel appears on
// session B's remote side with data flowing end-to-end.
// Depends on US-009. Matches C#/TS PipeTests.SessionPipeForwardChannelOpen.
func TestSessionPipeForwardChannelOpen(t *testing.T) {
	clientA, serverB, _ := createPipedSessionPairs(t)

	ctx, cancel := context.WithTimeout(context.Background(), pipeParityTimeout)
	defer cancel()

	// Open channel from clientA.
	chA, err := clientA.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel on clientA failed: %v", err)
	}

	// Accept the channel on serverB (should appear via the pipe relay).
	chB, err := serverB.AcceptChannel(ctx)
	if err != nil {
		t.Fatalf("AcceptChannel on serverB failed: %v", err)
	}

	// Send data clientA → serverB.
	testData := []byte("pipe-parity-channel-data")
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
		if !bytes.Equal(received, testData) {
			t.Errorf("received %q, want %q", received, testData)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for data through pipe")
	}

	// Send data serverB → clientA (reverse direction).
	reverseData := []byte("pipe-parity-reverse")
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
		if !bytes.Equal(received, reverseData) {
			t.Errorf("reverse received %q, want %q", received, reverseData)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for reverse data through pipe")
	}
}

// TestSessionPipeClose pipes two sessions, closes session A, and verifies
// session B also closes and PipeSession returns.
// Depends on US-009. Matches C#/TS PipeTests.SessionPipeClose.
func TestSessionPipeClose(t *testing.T) {
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

	// Close clientA — should cascade through pipe to serverB.
	_ = clientA.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case <-serverBClosed:
		// OK — serverB closed as expected.
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

// TestPipeExtendedData pipes two channels, sends extended data on one, and
// verifies it arrives on the other with the type code preserved.
// Depends on US-008. Matches C#/TS PipeTests.PipeExtendedData.
func TestPipeExtendedData(t *testing.T) {
	clientCh1, serverCh2 := createChannelPipePairs(t)

	ctx, cancel := context.WithTimeout(context.Background(), pipeParityTimeout)
	defer cancel()

	// Set up extended data handler on the receiving end.
	receivedCh := make(chan struct {
		dataType SSHExtendedDataType
		data     []byte
	}, 1)

	serverCh2.SetExtendedDataReceivedHandler(func(dataType SSHExtendedDataType, data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		receivedCh <- struct {
			dataType SSHExtendedDataType
			data     []byte
		}{dataType, buf}
		serverCh2.AdjustWindow(uint32(len(data)))
	})

	// Send extended data (stderr) from clientCh1.
	stderrPayload := []byte("piped stderr output")
	if err := clientCh1.SendExtendedData(ctx, ExtendedDataStderr, stderrPayload); err != nil {
		t.Fatalf("SendExtendedData failed: %v", err)
	}

	select {
	case got := <-receivedCh:
		if got.dataType != ExtendedDataStderr {
			t.Errorf("data type = %d, want %d (ExtendedDataStderr)", got.dataType, ExtendedDataStderr)
		}
		if !bytes.Equal(got.data, stderrPayload) {
			t.Errorf("data = %q, want %q", got.data, stderrPayload)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for extended data through pipe")
	}
}

// TestPipeLargeDataSequence pipes two channels, sends 100 sequential messages
// numbered 0-99, and verifies all arrive on the other side in order.
// Matches C#/TS PipeTests.PipeLargeDataSequence.
func TestPipeLargeDataSequence(t *testing.T) {
	clientCh1, serverCh2 := createChannelPipePairs(t)

	ctx, cancel := context.WithTimeout(context.Background(), pipeParityTimeout)
	defer cancel()

	const messageCount = 100

	// Collect received messages on the far end.
	var mu sync.Mutex
	var receivedMessages []string
	allReceived := make(chan struct{})

	serverCh2.SetDataReceivedHandler(func(data []byte) {
		mu.Lock()
		receivedMessages = append(receivedMessages, string(data))
		done := len(receivedMessages) >= messageCount
		mu.Unlock()
		serverCh2.AdjustWindow(uint32(len(data)))
		if done {
			select {
			case <-allReceived:
			default:
				close(allReceived)
			}
		}
	})

	// Send 100 sequential messages.
	for i := 0; i < messageCount; i++ {
		msg := fmt.Sprintf("MSG_%03d", i)
		if err := clientCh1.Send(ctx, []byte(msg)); err != nil {
			t.Fatalf("Send message %d failed: %v", i, err)
		}
	}

	// Wait for all messages to arrive.
	select {
	case <-allReceived:
	case <-ctx.Done():
		mu.Lock()
		got := len(receivedMessages)
		mu.Unlock()
		t.Fatalf("timed out: received %d/%d messages", got, messageCount)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(receivedMessages) != messageCount {
		t.Fatalf("received %d messages, want %d", len(receivedMessages), messageCount)
	}

	// Verify order. Messages may be concatenated (the pipe forwards raw bytes,
	// not framed messages), so join and compare against expected sequence.
	got := ""
	for _, m := range receivedMessages {
		got += m
	}

	expected := ""
	for i := 0; i < messageCount; i++ {
		expected += fmt.Sprintf("MSG_%03d", i)
	}

	if got != expected {
		// Show first mismatch location for debugging.
		for i := 0; i < len(got) && i < len(expected); i++ {
			if got[i] != expected[i] {
				t.Fatalf("data mismatch at byte %d: got %q..., want %q...",
					i, got[max(0, i-5):min(len(got), i+20)],
					expected[max(0, i-5):min(len(expected), i+20)])
			}
		}
		t.Fatalf("data length mismatch: got %d bytes, want %d bytes", len(got), len(expected))
	}
}

// Note: C# has PipeChannelPendingRequest which tests request forwarding through
// a channel pipe. This is a feature gap in Go — Channel.Pipe() forwards data,
// extended data, EOF, and close events, but not channel requests. The equivalent
// test is TestOpenChannelWithMultipleRequests in channel_request_test.go which
// tests the same overlapping-request pattern without pipe relay.

// TestPipeSessionChannelOpenAndClose opens a channel through piped sessions,
// closes it from one side, and verifies the Closed event fires on the far side.
// Matches C# PipeTests.PipeSessionChannelOpenAndClose.
func TestPipeSessionChannelOpenAndClose(t *testing.T) {
	clientA, serverB, _ := createPipedSessionPairs(t)

	ctx, cancel := context.WithTimeout(context.Background(), pipeParityTimeout)
	defer cancel()

	// Open channel from clientA.
	chA, err := clientA.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel on clientA failed: %v", err)
	}

	// Accept on serverB.
	chB, err := serverB.AcceptChannel(ctx)
	if err != nil {
		t.Fatalf("AcceptChannel on serverB failed: %v", err)
	}

	// Track close event on chA.
	closedCh := make(chan struct{})
	chA.OnClosed = func(args *ChannelClosedEventArgs) {
		close(closedCh)
	}

	// Close chB — should propagate through the pipe to chA.
	if err := chB.Close(); err != nil {
		t.Fatalf("Close chB failed: %v", err)
	}

	select {
	case <-closedCh:
		// OK — chA received close event.
	case <-ctx.Done():
		t.Fatal("timed out waiting for channel close through pipe")
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
