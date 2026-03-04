// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

const channelParityTimeout = 10 * time.Second

// TestServerOpensChannel verifies that the server can open a channel to the
// client, the client accepts, and data flows bidirectionally.
// Matches C#/TS ChannelTests.ServerOpensChannel.
func TestServerOpensChannel(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), channelParityTimeout)
	defer cancel()

	// Client accepts in background.
	var clientCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		clientCh, err = client.AcceptChannel(ctx)
		if err != nil {
			t.Errorf("client.AcceptChannel failed: %v", err)
		}
	}()

	// Server opens channel.
	serverCh, err := server.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("server.OpenChannel failed: %v", err)
	}
	wg.Wait()

	if clientCh == nil || serverCh == nil {
		t.Fatal("one of the channels is nil")
	}

	// Send data server → client.
	serverData := []byte("hello from server")
	clientStream := NewStream(clientCh)

	if err := serverCh.Send(ctx, serverData); err != nil {
		t.Fatalf("server Send failed: %v", err)
	}

	buf := make([]byte, len(serverData))
	if _, err := io.ReadFull(clientStream, buf); err != nil {
		t.Fatalf("client ReadFull failed: %v", err)
	}
	if !bytes.Equal(buf, serverData) {
		t.Errorf("server→client data mismatch: got %q, want %q", buf, serverData)
	}

	// Send data client → server.
	clientData := []byte("hello from client")
	serverStream := NewStream(serverCh)

	if err := clientCh.Send(ctx, clientData); err != nil {
		t.Fatalf("client Send failed: %v", err)
	}

	buf = make([]byte, len(clientData))
	if _, err := io.ReadFull(serverStream, buf); err != nil {
		t.Fatalf("server ReadFull failed: %v", err)
	}
	if !bytes.Equal(buf, clientData) {
		t.Errorf("client→server data mismatch: got %q, want %q", buf, clientData)
	}
}

// TestChannelRequestFailure sends a channel request that the peer does not
// handle, verifying Request() returns false.
// Matches C#/TS ChannelTests.ChannelRequestFailure.
func TestChannelRequestFailure(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), channelParityTimeout)
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

	// Server has no OnRequest handler — all requests should fail.
	_ = serverCh // keep reference alive

	success, err := clientCh.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "unhandled-request",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("Request error: %v", err)
	}
	if success {
		t.Error("expected request to fail (success=false), got success=true")
	}
}

// TestChannelDataMultipleSizes sends payloads of 1B, 1KB, 32KB, 64KB through
// a channel and verifies each arrives intact with the correct length.
// Matches C#/TS ChannelTests.ChannelDataMultipleSizes.
func TestChannelDataMultipleSizes(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), channelParityTimeout)
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
		t.Run(fmt.Sprintf("%dB", size), func(t *testing.T) {
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

			if n != size {
				t.Errorf("received %d bytes, want %d", n, size)
			}
			if !bytes.Equal(sent, received) {
				t.Errorf("data mismatch at size %d", size)
			}
		})
	}
}

// TestChannelExitStatus closes a channel with CloseWithStatus(ctx, 42) and
// verifies the peer's channel has ExitStatus == 42.
// Matches C#/TS ChannelTests.ChannelExitStatus.
func TestChannelExitStatus(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), channelParityTimeout)
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

	// Set up OnClosed callback on server channel to capture exit status.
	serverClosed := make(chan *ChannelClosedEventArgs, 1)
	serverCh.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		serverClosed <- args
	})

	// Close from client with exit status 42.
	if err := clientCh.CloseWithStatus(ctx, 42); err != nil {
		t.Fatalf("CloseWithStatus failed: %v", err)
	}

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
}

// TestChannelExitSignal closes a channel with CloseWithSignal(ctx, "TERM", "terminated")
// and verifies the peer's ExitSignal == "TERM" and error message matches.
// Matches C#/TS ChannelTests.ChannelExitSignal.
func TestChannelExitSignal(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), channelParityTimeout)
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

	// Set up OnClosed callback on server channel.
	serverClosed := make(chan *ChannelClosedEventArgs, 1)
	serverCh.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		serverClosed <- args
	})

	// Close from client with signal.
	if err := clientCh.CloseWithSignal(ctx, "TERM", "terminated"); err != nil {
		t.Fatalf("CloseWithSignal failed: %v", err)
	}

	select {
	case args := <-serverClosed:
		if args.ExitSignal != "TERM" {
			t.Errorf("ExitSignal = %q, want %q", args.ExitSignal, "TERM")
		}
		if args.ErrorMessage != "terminated" {
			t.Errorf("ErrorMessage = %q, want %q", args.ErrorMessage, "terminated")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server channel close")
	}
}

// TestChannelStandaloneSignal sends a standalone "signal" channel request with
// signal name HUP and verifies it arrives at the peer's OnRequest handler (not
// consumed as exit signal). Depends on US-005.
// Matches C#/TS ChannelTests.ChannelStandaloneSignal.
func TestChannelStandaloneSignal(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), channelParityTimeout)
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

	// Set up OnRequest handler to capture the signal.
	var mu sync.Mutex
	var receivedType string
	var receivedSignal string
	requestReceived := make(chan struct{})

	serverCh.OnRequest = func(args *RequestEventArgs) {
		mu.Lock()
		receivedType = args.RequestType
		if msg, ok := args.Request.(*messages.ChannelSignalMessage); ok {
			receivedSignal = msg.Signal
		}
		args.IsAuthorized = true
		mu.Unlock()
		close(requestReceived)
	}

	// Send standalone signal using SendSignal method.
	if err := clientCh.SendSignal(ctx, "HUP"); err != nil {
		t.Fatalf("SendSignal failed: %v", err)
	}

	select {
	case <-requestReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for signal to arrive at OnRequest")
	}

	mu.Lock()
	defer mu.Unlock()

	if receivedType != "signal" {
		t.Errorf("RequestType = %q, want %q", receivedType, "signal")
	}
	if receivedSignal != "HUP" {
		t.Errorf("Signal = %q, want %q", receivedSignal, "HUP")
	}
}

// TestChannelExtendedData sends extended data with ExtendedDataStderr and
// verifies OnExtendedDataReceived fires with the correct type code and data.
// Depends on US-008.
// Matches C#/TS ChannelTests.ChannelExtendedData.
func TestChannelExtendedData(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), channelParityTimeout)
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

	// Set up extended data handler on server channel.
	receivedCh := make(chan struct{}, 1)
	var receivedType SSHExtendedDataType
	var receivedData []byte
	serverCh.SetExtendedDataReceivedHandler(func(dataType SSHExtendedDataType, data []byte) {
		receivedType = dataType
		receivedData = make([]byte, len(data))
		copy(receivedData, data)
		serverCh.AdjustWindow(uint32(len(data)))
		select {
		case receivedCh <- struct{}{}:
		default:
		}
	})

	testData := []byte("stderr output for parity test")
	if err := clientCh.SendExtendedData(ctx, ExtendedDataStderr, testData); err != nil {
		t.Fatalf("SendExtendedData failed: %v", err)
	}

	select {
	case <-receivedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for extended data")
	}

	if receivedType != ExtendedDataStderr {
		t.Errorf("received type = %d, want %d (ExtendedDataStderr)", receivedType, ExtendedDataStderr)
	}
	if !bytes.Equal(receivedData, testData) {
		t.Errorf("received data = %q, want %q", receivedData, testData)
	}
}

// TestOpenChannelWithInitialRequestParity opens a channel with the
// open-channel-request extension (using OpenChannelWithRequest), verifying both
// the channel and the initial request succeed on the peer.
// Matches C#/TS ChannelTests.OpenChannelWithInitialRequest.
func TestOpenChannelWithInitialRequestParity(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), channelParityTimeout)
	defer cancel()

	const channelType = "test-parity-channel"
	const requestType = "test-parity-request"

	var mu sync.Mutex
	var requestReceived bool
	var requestTypeReceived string

	// Install OnRequest handler during channel opening so it is in place
	// before the initial-channel-request extension message arrives.
	server.SetChannelOpeningHandler(func(args *ChannelOpeningEventArgs) {
		args.Channel.OnRequest = func(reqArgs *RequestEventArgs) {
			mu.Lock()
			requestReceived = true
			requestTypeReceived = reqArgs.RequestType
			mu.Unlock()
			reqArgs.IsAuthorized = true
		}
	})

	var serverCh *Channel
	var wg sync.WaitGroup
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
	if !requestReceived {
		t.Error("initial channel request was not received by server")
	}
	if requestTypeReceived != requestType {
		t.Errorf("request type = %q, want %q", requestTypeReceived, requestType)
	}
}
