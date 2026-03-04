// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const mcsParityTimeout = 10 * time.Second

// TestMultiChannelStreamSingleChannel connects two MCS instances over io.Pipe,
// opens a channel from one side, accepts on the other, sends/receives data, and
// verifies a round-trip. Matches C#/TS MultiChannelStreamTests.SingleChannelConnect
// + SingleChannelReadWrite.
func TestMultiChannelStreamSingleChannel(t *testing.T) {
	client, server := createMultiChannelStreamPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), mcsParityTimeout)
	defer cancel()

	// Accept on server side concurrently.
	var serverCh *Channel
	var acceptErr error
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		serverCh, acceptErr = server.AcceptChannel(ctx, "")
	}()

	// Open channel from client.
	clientCh, err := client.OpenChannel(ctx, "session")
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	<-accepted
	if acceptErr != nil {
		t.Fatalf("AcceptChannel failed: %v", acceptErr)
	}

	// Send data from client to server.
	payload := []byte("Hello from client!")
	if err := clientCh.Send(ctx, payload); err != nil {
		t.Fatalf("client Send failed: %v", err)
	}

	serverStream := NewStream(serverCh)
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(serverStream, buf); err != nil {
		t.Fatalf("server ReadFull failed: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("client->server data mismatch: got %q, want %q", buf, payload)
	}

	// Send reply from server to client.
	reply := []byte("Hello from server!")
	if err := serverCh.Send(ctx, reply); err != nil {
		t.Fatalf("server Send failed: %v", err)
	}

	clientStream := NewStream(clientCh)
	replyBuf := make([]byte, len(reply))
	if _, err := io.ReadFull(clientStream, replyBuf); err != nil {
		t.Fatalf("client ReadFull failed: %v", err)
	}
	if !bytes.Equal(replyBuf, reply) {
		t.Fatalf("server->client data mismatch: got %q, want %q", replyBuf, reply)
	}
}

// TestMultiChannelStreamMultipleChannelsIsolation opens 3 channels between MCS
// instances, sends distinct data on each, and verifies each channel receives
// only its own data (isolation). Matches C#/TS MultiChannelStreamTests.
// MultiChannelConnect + MultiChannelReadWrite.
func TestMultiChannelStreamMultipleChannelsIsolation(t *testing.T) {
	client, server := createMultiChannelStreamPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), mcsParityTimeout)
	defer cancel()

	numChannels := 3

	// Accept channels on server side.
	serverChannels := make([]*Channel, numChannels)
	var acceptWg sync.WaitGroup
	acceptWg.Add(numChannels)
	acceptIdx := 0
	var mu sync.Mutex

	go func() {
		for i := 0; i < numChannels; i++ {
			ch, err := server.AcceptChannel(ctx, "")
			if err != nil {
				t.Errorf("AcceptChannel %d failed: %v", i, err)
				acceptWg.Done()
				continue
			}
			mu.Lock()
			serverChannels[acceptIdx] = ch
			acceptIdx++
			mu.Unlock()
			acceptWg.Done()
		}
	}()

	// Open channels from client sequentially (io.Pipe is synchronous).
	clientChannels := make([]*Channel, numChannels)
	for i := 0; i < numChannels; i++ {
		ch, err := client.OpenChannel(ctx, "session")
		if err != nil {
			t.Fatalf("OpenChannel %d failed: %v", i, err)
		}
		clientChannels[i] = ch
	}
	acceptWg.Wait()

	// Send distinct data on each client channel.
	for i := 0; i < numChannels; i++ {
		data := []byte(fmt.Sprintf("CH%d_DATA", i+1))
		if err := clientChannels[i].Send(ctx, data); err != nil {
			t.Fatalf("Send on channel %d failed: %v", i, err)
		}
	}

	// Verify each server channel receives only its own data.
	// Channels may be accepted in different order, so match by channel remote ID.
	mu.Lock()
	srvChans := make([]*Channel, numChannels)
	copy(srvChans, serverChannels)
	mu.Unlock()

	for _, sCh := range srvChans {
		stream := NewStream(sCh)
		// Each message is "CHn_DATA" — max 8 bytes.
		buf := make([]byte, 8)
		n, err := io.ReadFull(stream, buf)
		if err != nil {
			t.Fatalf("ReadFull failed: %v", err)
		}
		got := string(buf[:n])
		// Verify it's one of the expected payloads.
		if got != "CH1_DATA" && got != "CH2_DATA" && got != "CH3_DATA" {
			t.Fatalf("unexpected data on channel: %q", got)
		}
	}

	// Verify isolation: send a second round from server to client on each channel,
	// making sure each client channel gets exactly its own data.
	for i := 0; i < numChannels; i++ {
		data := []byte(fmt.Sprintf("SRV%d", i+1))
		if err := srvChans[i].Send(ctx, data); err != nil {
			t.Fatalf("server Send on channel %d failed: %v", i, err)
		}
	}

	for i := 0; i < numChannels; i++ {
		stream := NewStream(clientChannels[i])
		// Find the matching server channel (same remote channel ID).
		expected := ""
		for j := 0; j < numChannels; j++ {
			if srvChans[j].RemoteChannelID == clientChannels[i].ChannelID {
				expected = fmt.Sprintf("SRV%d", j+1)
				break
			}
		}
		if expected == "" {
			t.Fatalf("no matching server channel for client channel %d", i)
		}

		buf := make([]byte, len(expected))
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Fatalf("client ReadFull on channel %d failed: %v", i, err)
		}
		if string(buf) != expected {
			t.Fatalf("channel %d isolation failed: got %q, want %q", i, buf, expected)
		}
	}
}

// TestMultiChannelStreamOpenChannelEvent sets OnChannelOpening callback on MCS,
// opens a channel, and verifies the callback fires with the channel and correct
// metadata. Matches C#/TS MultiChannelStreamTests.OpenChannelEvent.
func TestMultiChannelStreamOpenChannelEvent(t *testing.T) {
	client, server := createMultiChannelStreamPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), mcsParityTimeout)
	defer cancel()

	var eventFired atomic.Bool
	var eventIsRemote atomic.Bool
	var eventChannelType atomic.Value

	server.OnChannelOpening = func(args *ChannelOpeningEventArgs) {
		eventFired.Store(true)
		eventIsRemote.Store(args.IsRemoteRequest)
		eventChannelType.Store(args.Channel.ChannelType)
	}

	// Accept on server side.
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		server.AcceptChannel(ctx, "")
	}()

	// Open from client.
	_, err := client.OpenChannel(ctx, "test-channel")
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	<-acceptDone

	if !eventFired.Load() {
		t.Error("expected OnChannelOpening to fire")
	}
	if !eventIsRemote.Load() {
		t.Error("expected IsRemoteRequest to be true on server side")
	}
	if ct, ok := eventChannelType.Load().(string); !ok || ct != "test-channel" {
		t.Errorf("expected channel type 'test-channel', got %q", ct)
	}
}

// TestMultiChannelStreamConnectedState verifies that a newly created MCS is not
// yet closed, that after connecting operations work, and that after closing
// IsClosed returns true. Matches C#/TS MultiChannelStreamTests state transitions.
func TestMultiChannelStreamConnectedState(t *testing.T) {
	s1, s2 := duplexPipe()

	client := NewMultiChannelStream(s1, true)
	server := NewMultiChannelStream(s2, false)

	// Before connecting: IsClosed should be false.
	if client.IsClosed() {
		t.Error("expected IsClosed() == false before connect")
	}

	// Start server with ConnectAndRunUntilClosed.
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.ConnectAndRunUntilClosed(context.Background())
	}()

	// Connect client.
	ctx, cancel := context.WithTimeout(context.Background(), mcsParityTimeout)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("client Connect failed: %v", err)
	}

	// After connecting: should still not be closed, and operations should work.
	if client.IsClosed() {
		t.Error("expected IsClosed() == false after connect")
	}

	// Verify we can open a channel (proves the connection is active).
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		server.AcceptChannel(ctx, "")
	}()
	ch, err := client.OpenChannel(ctx, "session")
	if err != nil {
		t.Fatalf("OpenChannel failed after connect: %v", err)
	}
	<-acceptDone
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}

	// Close client.
	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// After closing: IsClosed should be true.
	if !client.IsClosed() {
		t.Error("expected IsClosed() == true after Close()")
	}

	// Wait for server to finish.
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server ConnectAndRunUntilClosed did not return")
	}

	if !server.IsClosed() {
		t.Error("expected server IsClosed() == true after client closed")
	}
}

// TestMultiChannelStreamExtendedData sends extended data through an MCS channel
// and verifies OnExtendedDataReceived fires with the correct type code and data.
// Depends on US-008 (extended data support). Matches C#/TS extended data tests.
func TestMultiChannelStreamExtendedData(t *testing.T) {
	client, server := createMultiChannelStreamPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), mcsParityTimeout)
	defer cancel()

	// Accept on server side.
	var serverCh *Channel
	var acceptErr error
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		serverCh, acceptErr = server.AcceptChannel(ctx, "")
	}()

	clientCh, err := client.OpenChannel(ctx, "session")
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	<-accepted
	if acceptErr != nil {
		t.Fatalf("AcceptChannel failed: %v", acceptErr)
	}

	// Set up extended data handler on server channel.
	var receivedType atomic.Uint32
	var receivedData atomic.Value
	extDataDone := make(chan struct{})

	serverCh.SetExtendedDataReceivedHandler(func(dataType SSHExtendedDataType, data []byte) {
		receivedType.Store(uint32(dataType))
		cp := make([]byte, len(data))
		copy(cp, data)
		receivedData.Store(cp)
		close(extDataDone)
	})

	// Send extended data (stderr) from client.
	stderrPayload := []byte("error output from client")
	if err := clientCh.SendExtendedData(ctx, ExtendedDataStderr, stderrPayload); err != nil {
		t.Fatalf("SendExtendedData failed: %v", err)
	}

	// Wait for the handler to fire.
	select {
	case <-extDataDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for OnExtendedDataReceived")
	}

	if SSHExtendedDataType(receivedType.Load()) != ExtendedDataStderr {
		t.Errorf("expected data type %d (stderr), got %d", ExtendedDataStderr, receivedType.Load())
	}

	gotData, ok := receivedData.Load().([]byte)
	if !ok {
		t.Fatal("receivedData not set")
	}
	if !bytes.Equal(gotData, stderrPayload) {
		t.Errorf("extended data mismatch: got %q, want %q", gotData, stderrPayload)
	}
}
