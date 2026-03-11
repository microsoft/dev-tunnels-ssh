// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

const flowTestTimeout = 30 * time.Second

// --- Large data transfer tests ---

func TestSendLargeChannelData(t *testing.T) {
	testCases := []struct {
		name       string
		windowSize uint32
	}{
		{"default_window", 0},
		{"5x_window", 5 * ssh.DefaultMaxWindowSize},
	}

	dataSize := int(3.5 * 1024 * 1024) // 3.5 MB
	testData := helpers.GenerateDeterministicBytes(42, dataSize)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var config *helpers.SessionPairConfig
			if tc.windowSize > 0 {
				clientConfig := ssh.NewNoSecurityConfig()
				clientConfig.MaxChannelWindowSize = tc.windowSize
				serverConfig := ssh.NewNoSecurityConfig()
				serverConfig.MaxChannelWindowSize = tc.windowSize
				config = &helpers.SessionPairConfig{
					ClientConfig: clientConfig,
					ServerConfig: serverConfig,
				}
			}

			pair := helpers.NewSessionPairWithConfig(t, config)
			defer pair.Close()

			ctx, cancel := context.WithTimeout(context.Background(), flowTestTimeout)
			defer cancel()

			pair.Connect(ctx)
			clientCh, serverCh := pair.OpenChannel(ctx)

			var received bytes.Buffer
			var mu sync.Mutex
			done := make(chan struct{})

			serverCh.OnDataReceived = func(data []byte) {
				mu.Lock()
				received.Write(data)
				total := received.Len()
				mu.Unlock()
				serverCh.AdjustWindow(uint32(len(data)))
				if total >= dataSize {
					select {
					case <-done:
					default:
						close(done)
					}
				}
			}

			if err := clientCh.Send(ctx, testData); err != nil {
				t.Fatalf("send failed: %v", err)
			}

			select {
			case <-done:
			case <-time.After(flowTestTimeout):
				mu.Lock()
				got := received.Len()
				mu.Unlock()
				t.Fatalf("timed out: received %d of %d bytes", got, dataSize)
			}

			mu.Lock()
			receivedData := received.Bytes()
			mu.Unlock()

			if !bytes.Equal(receivedData, testData) {
				t.Errorf("data mismatch: received %d bytes, want %d", len(receivedData), dataSize)
			}
		})
	}
}

func TestSendIncreasingChannelData(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), flowTestTimeout)
	defer cancel()

	pair.Connect(ctx)
	clientCh, serverCh := pair.OpenChannel(ctx)

	// Send increasing sizes from 32 to 4096 bytes.
	var sizes []int
	for size := 32; size <= 4096; size *= 2 {
		sizes = append(sizes, size)
	}

	totalExpected := 0
	for _, s := range sizes {
		totalExpected += s
	}

	var received bytes.Buffer
	var mu sync.Mutex
	done := make(chan struct{})

	serverCh.OnDataReceived = func(data []byte) {
		mu.Lock()
		received.Write(data)
		total := received.Len()
		mu.Unlock()
		serverCh.AdjustWindow(uint32(len(data)))
		if total >= totalExpected {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	}

	var allData bytes.Buffer
	for _, size := range sizes {
		data := helpers.GenerateDeterministicBytes(byte(size), size)
		allData.Write(data)
		if err := clientCh.Send(ctx, data); err != nil {
			t.Fatalf("send %d bytes failed: %v", size, err)
		}
	}

	select {
	case <-done:
	case <-time.After(flowTestTimeout):
		mu.Lock()
		got := received.Len()
		mu.Unlock()
		t.Fatalf("timed out: received %d of %d bytes", got, totalExpected)
	}

	mu.Lock()
	if !bytes.Equal(received.Bytes(), allData.Bytes()) {
		t.Error("received data does not match sent data")
	}
	mu.Unlock()
}

// --- Flow control tests ---

func TestSendBlocksOnClosedWindow(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), flowTestTimeout)
	defer cancel()

	pair.Connect(ctx)
	clientCh, serverCh := pair.OpenChannel(ctx)

	// Data size = 2x default window size (2 MB).
	dataSize := int(ssh.DefaultMaxWindowSize * 2)
	testData := helpers.GenerateDeterministicBytes(42, dataSize)

	var received bytes.Buffer
	var mu sync.Mutex
	firstWindowFull := make(chan struct{})
	allReceived := make(chan struct{})

	// Receive data but DON'T call AdjustWindow — window stays closed.
	serverCh.OnDataReceived = func(data []byte) {
		mu.Lock()
		received.Write(data)
		total := received.Len()
		mu.Unlock()

		if total >= int(ssh.DefaultMaxWindowSize) {
			select {
			case <-firstWindowFull:
			default:
				close(firstWindowFull)
			}
		}

		if total >= dataSize {
			select {
			case <-allReceived:
			default:
				close(allReceived)
			}
		}
	}

	// Start sending in background — will block after first window.
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- clientCh.Send(ctx, testData)
	}()

	// Wait for first window's worth of data to arrive.
	select {
	case <-firstWindowFull:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for first window fill")
	}

	// Give the sender time to potentially complete (it should be blocked).
	time.Sleep(200 * time.Millisecond)

	// Verify send is still blocked.
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("send completed with error (should be blocked): %v", err)
		}
		t.Fatal("send completed but should be blocked (window exhausted)")
	default:
		// Expected: send is blocked.
	}

	// Reopen the window by calling AdjustWindow with the received amount.
	mu.Lock()
	receivedSoFar := uint32(received.Len())
	mu.Unlock()
	serverCh.AdjustWindow(receivedSoFar)

	// Wait for send to complete.
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("send failed after window reopen: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for send to complete after window reopen")
	}

	// Wait for all data to arrive.
	select {
	case <-allReceived:
	case <-time.After(10 * time.Second):
		mu.Lock()
		got := received.Len()
		mu.Unlock()
		t.Fatalf("timed out waiting for all data: received %d of %d", got, dataSize)
	}

	mu.Lock()
	if !bytes.Equal(received.Bytes(), testData) {
		t.Error("received data does not match sent data")
	}
	mu.Unlock()
}

// --- Buffered receive tests ---

func TestChannelReceiveWaitsForListener(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), flowTestTimeout)
	defer cancel()

	pair.Connect(ctx)
	clientCh, serverCh := pair.OpenChannel(ctx)

	// Send data that fits within the default window (< 1MB) WITHOUT setting
	// a handler on the server channel. Without a handler, the channel buffers
	// data and back-pressures the sender (no auto window adjust). Using a size
	// smaller than DefaultMaxWindowSize ensures Send completes without blocking.
	dataSize := int(ssh.DefaultMaxWindowSize / 2) // 512 KB
	testData := helpers.GenerateDeterministicBytes(99, dataSize)

	// Send data — fits within window so should complete without blocking.
	if err := clientCh.Send(ctx, testData); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// Small delay to let dispatch loop finish processing buffered data.
	time.Sleep(200 * time.Millisecond)

	// Now attach a listener using SetDataReceivedHandler — buffered data should flush
	// synchronously during the call to SetDataReceivedHandler.
	var received bytes.Buffer
	var mu sync.Mutex
	done := make(chan struct{})

	serverCh.SetDataReceivedHandler(func(data []byte) {
		mu.Lock()
		received.Write(data)
		total := received.Len()
		mu.Unlock()
		serverCh.AdjustWindow(uint32(len(data)))
		if total >= dataSize {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	})

	// Wait for all data to be received (flush happens synchronously in
	// SetDataReceivedHandler, but use a timeout for safety).
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		mu.Lock()
		got := received.Len()
		mu.Unlock()
		t.Fatalf("timed out: received %d of %d bytes", got, dataSize)
	}

	mu.Lock()
	receivedData := make([]byte, received.Len())
	copy(receivedData, received.Bytes())
	mu.Unlock()

	if !bytes.Equal(receivedData, testData) {
		t.Errorf("buffered data mismatch: received %d bytes, want %d", len(receivedData), dataSize)
	}
}

// --- Multiple channels test ---

func TestSendChannelDataOverMultipleChannels(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pair.Connect(ctx)

	const numChannels = 200
	const dataPerChannel = 128 // small data per channel

	type channelPair struct {
		clientCh *ssh.Channel
		serverCh *ssh.Channel
	}

	// Accept channels in a background goroutine to prevent acceptQueue blocking.
	serverChannels := make([]*ssh.Channel, 0, numChannels)
	var serverMu sync.Mutex
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for i := 0; i < numChannels; i++ {
			ch, err := pair.ServerSession.AcceptChannel(ctx)
			if err != nil {
				t.Errorf("accept channel %d failed: %v", i, err)
				return
			}
			serverMu.Lock()
			serverChannels = append(serverChannels, ch)
			serverMu.Unlock()
		}
	}()

	// Open all channels from client concurrently.
	clientChannels := make([]*ssh.Channel, numChannels)
	var openWg sync.WaitGroup
	for i := 0; i < numChannels; i++ {
		openWg.Add(1)
		go func(i int) {
			defer openWg.Done()
			ch, err := pair.ClientSession.OpenChannel(ctx)
			if err != nil {
				t.Errorf("open channel %d failed: %v", i, err)
				return
			}
			clientChannels[i] = ch
		}(i)
	}
	openWg.Wait()

	// Wait for all channels to be accepted.
	select {
	case <-acceptDone:
	case <-ctx.Done():
		t.Fatal("timed out waiting for channel acceptance")
	}

	serverMu.Lock()
	if len(serverChannels) != numChannels {
		t.Fatalf("expected %d server channels, got %d", numChannels, len(serverChannels))
	}
	serverMu.Unlock()

	// Set up receivers on all server channels and send data on all client channels.
	var completedCount atomic.Int32
	allDone := make(chan struct{})

	serverMu.Lock()
	for i, sCh := range serverChannels {
		sCh.OnDataReceived = func(data []byte) {
			serverChannels[i].AdjustWindow(uint32(len(data)))
			if completedCount.Add(1) >= int32(numChannels) {
				select {
				case <-allDone:
				default:
					close(allDone)
				}
			}
		}
	}
	serverMu.Unlock()

	// Send data on all client channels.
	var sendWg sync.WaitGroup
	for i := 0; i < numChannels; i++ {
		if clientChannels[i] == nil {
			continue
		}
		sendWg.Add(1)
		go func(i int) {
			defer sendWg.Done()
			data := helpers.GenerateDeterministicBytes(byte(i), dataPerChannel)
			if err := clientChannels[i].Send(ctx, data); err != nil {
				t.Errorf("send on channel %d failed: %v", i, err)
			}
		}(i)
	}
	sendWg.Wait()

	select {
	case <-allDone:
	case <-time.After(60 * time.Second):
		t.Fatalf("timed out: %d of %d channels received data", completedCount.Load(), numChannels)
	}
}

// --- Concurrent sends test ---

func TestSendLargeDataWithoutAwait(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pair.Connect(ctx)
	clientCh, serverCh := pair.OpenChannel(ctx)

	const numSends = 256
	const chunksPerSend = 4
	const chunkSize = 1024 // 1 KB per chunk
	expectedTotal := numSends * chunksPerSend * chunkSize

	var received bytes.Buffer
	var mu sync.Mutex
	done := make(chan struct{})

	serverCh.OnDataReceived = func(data []byte) {
		mu.Lock()
		received.Write(data)
		total := received.Len()
		mu.Unlock()
		serverCh.AdjustWindow(uint32(len(data)))
		if total >= expectedTotal {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	}

	// Fire-and-forget: launch all sends concurrently.
	var wg sync.WaitGroup
	for i := 0; i < numSends; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < chunksPerSend; j++ {
				data := helpers.GenerateDeterministicBytes(byte(i*chunksPerSend+j), chunkSize)
				if err := clientCh.Send(ctx, data); err != nil {
					t.Errorf("send %d-%d failed: %v", i, j, err)
					return
				}
			}
		}(i)
	}

	// Wait for all sends to complete (they are serialized by sendMu internally).
	wg.Wait()

	// Wait for all data to arrive at receiver.
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		mu.Lock()
		got := received.Len()
		mu.Unlock()
		t.Fatalf("timed out: received %d of %d bytes", got, expectedTotal)
	}

	mu.Lock()
	if received.Len() != expectedTotal {
		t.Errorf("received %d bytes, want %d", received.Len(), expectedTotal)
	}
	mu.Unlock()
}
