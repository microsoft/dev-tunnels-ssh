// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

// createMultiChannelStreamPair creates a connected pair of MultiChannelStreams.
func createMultiChannelStreamPair() (*ssh.MultiChannelStream, *ssh.MultiChannelStream) {
	s1, s2 := helpers.CreateDuplexStreams()
	client := ssh.NewMultiChannelStream(s1, true)
	server := ssh.NewMultiChannelStream(s2, false)
	return client, server
}

func TestMultiChannelStreamClose(t *testing.T) {
	client, server := createMultiChannelStreamPair()

	closedCh := make(chan struct{}, 2)
	client.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		closedCh <- struct{}{}
	}
	server.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		closedCh <- struct{}{}
	}

	// Connect both sides.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := client.Connect(ctx); err != nil {
			t.Errorf("client connect: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := server.Connect(ctx); err != nil {
			t.Errorf("server connect: %v", err)
		}
	}()
	wg.Wait()

	// Close client side.
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	if !client.IsClosed() {
		t.Fatal("client should be closed")
	}

	// Wait for server to detect close.
	select {
	case <-closedCh:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for close event")
	}

	// Clean up server.
	server.Close()
}

func TestMultiChannelStreamCloseFiresEvent(t *testing.T) {
	client, server := createMultiChannelStreamPair()

	closedCh := make(chan *ssh.SessionClosedEventArgs, 1)
	client.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		closedCh <- args
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		client.Connect(ctx)
	}()
	go func() {
		defer wg.Done()
		server.Connect(ctx)
	}()
	wg.Wait()

	client.Close()

	select {
	case args := <-closedCh:
		if args == nil {
			t.Fatal("expected non-nil close event args")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for close event")
	}

	server.Close()
}

func TestMultiChannelStreamSingleChannel(t *testing.T) {
	client, server := createMultiChannelStreamPair()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var clientCh, serverCh *ssh.Channel
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, clientErr = client.OpenChannel(ctx, "")
	}()
	go func() {
		defer wg.Done()
		serverCh, serverErr = server.AcceptChannel(ctx, "")
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client open channel: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server accept channel: %v", serverErr)
	}
	if clientCh == nil {
		t.Fatal("client channel is nil")
	}
	if serverCh == nil {
		t.Fatal("server channel is nil")
	}
}

func TestMultiChannelStreamChannelOpeningEvent(t *testing.T) {
	client, server := createMultiChannelStreamPair()
	defer client.Close()
	defer server.Close()

	serverEventCh := make(chan *ssh.ChannelOpeningEventArgs, 1)
	server.OnChannelOpening = func(args *ssh.ChannelOpeningEventArgs) {
		serverEventCh <- args
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		client.OpenChannel(ctx, "test-channel")
	}()
	go func() {
		defer wg.Done()
		server.AcceptChannel(ctx, "")
	}()

	select {
	case args := <-serverEventCh:
		if args == nil {
			t.Fatal("expected non-nil channel opening event")
		}
		if args.Channel == nil {
			t.Fatal("expected non-nil channel in event")
		}
		if args.Channel.ChannelType != "test-channel" {
			t.Errorf("expected channel type 'test-channel', got %q", args.Channel.ChannelType)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for channel opening event")
	}

	wg.Wait()
}

func TestMultiChannelStreamReadWrite(t *testing.T) {
	client, server := createMultiChannelStreamPair()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var clientStream, serverStream *ssh.Stream
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientStream, clientErr = client.OpenStream(ctx, "")
	}()
	go func() {
		defer wg.Done()
		serverStream, serverErr = server.AcceptStream(ctx, "")
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client open stream: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server accept stream: %v", serverErr)
	}

	// Client writes, server reads.
	testData := []byte("Hello from client!")
	readDone := make(chan struct{})
	var readData []byte

	go func() {
		defer close(readDone)
		buf := make([]byte, 256)
		n, err := serverStream.Read(buf)
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		readData = buf[:n]
	}()

	_, err := clientStream.Write(testData)
	if err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case <-readDone:
		if !bytes.Equal(readData, testData) {
			t.Errorf("data mismatch: got %q, want %q", readData, testData)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server read")
	}

	// Server writes, client reads.
	responseData := []byte("Hello from server!")
	readDone2 := make(chan struct{})
	var readData2 []byte

	go func() {
		defer close(readDone2)
		buf := make([]byte, 256)
		n, err := clientStream.Read(buf)
		if err != nil {
			t.Errorf("client read: %v", err)
			return
		}
		readData2 = buf[:n]
	}()

	_, err = serverStream.Write(responseData)
	if err != nil {
		t.Fatalf("server write: %v", err)
	}

	select {
	case <-readDone2:
		if !bytes.Equal(readData2, responseData) {
			t.Errorf("data mismatch: got %q, want %q", readData2, responseData)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client read")
	}
}

func TestMultiChannelStreamConnectAndRunUntilClosed(t *testing.T) {
	client, server := createMultiChannelStreamPair()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.ConnectAndRunUntilClosed(ctx)
	}()

	// Connect client.
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("client connect: %v", err)
	}

	// Open a channel.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.AcceptChannel(ctx, "")
	}()

	ch, err := client.OpenChannel(ctx, "")
	if err != nil {
		t.Fatalf("client open channel: %v", err)
	}
	wg.Wait()

	if ch == nil {
		t.Fatal("client channel is nil")
	}

	// Close client, which should cause server's ConnectAndRunUntilClosed to return.
	client.Close()

	select {
	case err := <-serverDone:
		// ConnectAndRunUntilClosed may return nil or an error on close.
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server ConnectAndRunUntilClosed to return")
	}
}

func TestMultiChannelStreamMultipleChannels(t *testing.T) {
	client, server := createMultiChannelStreamPair()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const numChannels = 20

	var wg sync.WaitGroup
	clientChannels := make([]*ssh.Channel, numChannels)
	serverChannels := make([]*ssh.Channel, numChannels)
	clientErrors := make([]error, numChannels)
	serverErrors := make([]error, numChannels)

	// Open channels from client.
	for i := 0; i < numChannels; i++ {
		wg.Add(2)
		idx := i
		go func() {
			defer wg.Done()
			ch, err := client.OpenChannel(ctx, "")
			clientChannels[idx] = ch
			clientErrors[idx] = err
		}()
		go func() {
			defer wg.Done()
			ch, err := server.AcceptChannel(ctx, "")
			serverChannels[idx] = ch
			serverErrors[idx] = err
		}()
	}
	wg.Wait()

	for i := 0; i < numChannels; i++ {
		if clientErrors[i] != nil {
			t.Fatalf("client channel %d open error: %v", i, clientErrors[i])
		}
		if serverErrors[i] != nil {
			t.Fatalf("server channel %d accept error: %v", i, serverErrors[i])
		}
		if clientChannels[i] == nil {
			t.Fatalf("client channel %d is nil", i)
		}
		if serverChannels[i] == nil {
			t.Fatalf("server channel %d is nil", i)
		}
	}
}

func TestMultiChannelStreamMultiChannelReadWrite(t *testing.T) {
	client, server := createMultiChannelStreamPair()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const numChannels = 20
	const iterations = 10
	testPayload := []byte("Hello from channel!")

	var wg sync.WaitGroup
	for i := 0; i < numChannels; i++ {
		wg.Add(2)
		// Client side: always write first, then read response.
		go func(idx int) {
			defer wg.Done()
			stream, err := client.OpenStream(ctx, "")
			if err != nil {
				t.Errorf("client stream %d: %v", idx, err)
				return
			}
			for j := 0; j < iterations; j++ {
				if _, err := stream.Write(testPayload); err != nil {
					t.Errorf("client stream %d write iter %d: %v", idx, j, err)
					return
				}
				buf := make([]byte, 256)
				n, err := stream.Read(buf)
				if err != nil {
					t.Errorf("client stream %d read iter %d: %v", idx, j, err)
					return
				}
				if !bytes.Equal(buf[:n], testPayload) {
					t.Errorf("client stream %d data mismatch iter %d", idx, j)
					return
				}
			}
		}(i)

		// Server side: always read first, then write response.
		go func(idx int) {
			defer wg.Done()
			stream, err := server.AcceptStream(ctx, "")
			if err != nil {
				t.Errorf("server stream %d: %v", idx, err)
				return
			}
			for j := 0; j < iterations; j++ {
				buf := make([]byte, 256)
				n, err := stream.Read(buf)
				if err != nil {
					t.Errorf("server stream %d read iter %d: %v", idx, j, err)
					return
				}
				if !bytes.Equal(buf[:n], testPayload) {
					t.Errorf("server stream %d data mismatch iter %d", idx, j)
					return
				}
				if _, err := stream.Write(testPayload); err != nil {
					t.Errorf("server stream %d write iter %d: %v", idx, j, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestMultiChannelStreamSequentialChannels(t *testing.T) {
	client, server := createMultiChannelStreamPair()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open first channel.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.AcceptChannel(ctx, "")
	}()

	ch1, err := client.OpenChannel(ctx, "")
	if err != nil {
		t.Fatalf("open channel 1: %v", err)
	}
	wg.Wait()

	// Close it.
	ch1.Close()
	time.Sleep(100 * time.Millisecond) // allow close to propagate

	// Open second channel.
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.AcceptChannel(ctx, "")
	}()

	ch2, err := client.OpenChannel(ctx, "")
	if err != nil {
		t.Fatalf("open channel 2: %v", err)
	}
	wg.Wait()

	if ch2 == nil {
		t.Fatal("channel 2 is nil")
	}
	if ch1.ChannelID == ch2.ChannelID {
		t.Error("expected different channel IDs for sequential channels")
	}
}

func TestMultiChannelStreamChannelMaxWindowSize(t *testing.T) {
	s1, s2 := helpers.CreateDuplexStreams()
	client := ssh.NewMultiChannelStream(s1, true)
	server := ssh.NewMultiChannelStream(s2, false)
	defer client.Close()
	defer server.Close()

	// Set custom window size.
	customWindowSize := uint32(512 * 1024) // 512 KB
	client.ChannelMaxWindowSize = customWindowSize
	server.ChannelMaxWindowSize = customWindowSize

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var clientCh, serverCh *ssh.Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		clientCh, err = client.OpenChannel(ctx, "")
		if err != nil {
			t.Errorf("client open: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		var err error
		serverCh, err = server.AcceptChannel(ctx, "")
		if err != nil {
			t.Errorf("server accept: %v", err)
		}
	}()
	wg.Wait()

	if clientCh == nil || serverCh == nil {
		t.Fatal("channels are nil")
	}

	// Verify window size was applied.
	if clientCh.MaxWindowSize != customWindowSize {
		t.Errorf("client channel window size: got %d, want %d", clientCh.MaxWindowSize, customWindowSize)
	}
	if serverCh.MaxWindowSize != customWindowSize {
		t.Errorf("server channel window size: got %d, want %d", serverCh.MaxWindowSize, customWindowSize)
	}
}
