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

const channelTestTimeout = 5 * time.Second

// --- Channel open tests ---

func TestOpenChannelFromClient(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), channelTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	if clientCh == nil {
		t.Fatal("client channel should not be nil")
	}
	if serverCh == nil {
		t.Fatal("server channel should not be nil")
	}

	// Default channel type should be "session".
	if serverCh.ChannelType != "session" {
		t.Errorf("server channel type = %q, want %q", serverCh.ChannelType, "session")
	}
}

func TestOpenChannelFromServer(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), channelTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Open channel from the server side.
	var serverCh, clientCh *ssh.Channel
	var serverErr, clientErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		serverCh, serverErr = pair.ServerSession.OpenChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		clientCh, clientErr = pair.ClientSession.AcceptChannel(ctx)
	}()
	wg.Wait()

	if serverErr != nil {
		t.Fatalf("server open channel failed: %v", serverErr)
	}
	if clientErr != nil {
		t.Fatalf("client accept channel failed: %v", clientErr)
	}

	if serverCh == nil {
		t.Fatal("server channel should not be nil")
	}
	if clientCh == nil {
		t.Fatal("client channel should not be nil")
	}
}

func TestOpenChannelWithCustomType(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), channelTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	var clientCh, serverCh *ssh.Channel
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, clientErr = pair.ClientSession.OpenChannelWithType(ctx, "direct-tcpip")
	}()
	go func() {
		defer wg.Done()
		serverCh, serverErr = pair.ServerSession.AcceptChannel(ctx)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client open channel failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server accept channel failed: %v", serverErr)
	}

	if serverCh.ChannelType != "direct-tcpip" {
		t.Errorf("server channel type = %q, want %q", serverCh.ChannelType, "direct-tcpip")
	}
	if clientCh == nil {
		t.Fatal("client channel should not be nil")
	}
}

func TestOpenChannelWithNilType(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), channelTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Passing empty string should default to "session".
	var clientCh, serverCh *ssh.Channel
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, clientErr = pair.ClientSession.OpenChannelWithType(ctx, "")
	}()
	go func() {
		defer wg.Done()
		serverCh, serverErr = pair.ServerSession.AcceptChannel(ctx)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client open channel failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server accept channel failed: %v", serverErr)
	}

	if serverCh.ChannelType != "session" {
		t.Errorf("server channel type = %q, want %q", serverCh.ChannelType, "session")
	}
	if clientCh == nil {
		t.Fatal("client channel should not be nil")
	}
}

// --- Channel close tests ---

func TestDisposeChannelCloses(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), channelTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	clientClosed := make(chan struct{})
	serverClosed := make(chan struct{})

	clientCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		close(clientClosed)
	}
	serverCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		close(serverClosed)
	}

	// Close from client side.
	if err := clientCh.Close(); err != nil {
		t.Fatalf("client channel close failed: %v", err)
	}

	// Wait for both sides to close.
	select {
	case <-clientClosed:
	case <-time.After(channelTestTimeout):
		t.Fatal("timed out waiting for client channel close event")
	}
	select {
	case <-serverClosed:
	case <-time.After(channelTestTimeout):
		t.Fatal("timed out waiting for server channel close event")
	}

	// Sessions should still be connected.
	if !pair.ClientSession.IsConnected() {
		t.Error("client session should still be connected after channel close")
	}
	if !pair.ServerSession.IsConnected() {
		t.Error("server session should still be connected after channel close")
	}
}

// --- Channel data send tests ---

func TestSendChannelData(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"single_byte_zero", []byte{0}},
		{"test_string", []byte("test")},
		{"boundary_2032", helpers.GenerateDeterministicBytes(42, 2032)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pair := helpers.NewSessionPair(t)
			defer pair.Close()

			ctx, cancel := context.WithTimeout(context.Background(), channelTestTimeout)
			defer cancel()

			pair.Connect(ctx)

			clientCh, serverCh := pair.OpenChannel(ctx)

			if tc.data == nil || len(tc.data) == 0 {
				// Sending empty data should send EOF.
				err := clientCh.Send(ctx, nil)
				if err != nil {
					t.Fatalf("send empty data failed: %v", err)
				}
				return
			}

			received := make(chan []byte, 1)
			serverCh.OnDataReceived = func(data []byte) {
				// Copy data since the buffer may be reused.
				buf := make([]byte, len(data))
				copy(buf, data)
				received <- buf
				serverCh.AdjustWindow(uint32(len(data)))
			}

			// Send data from client to server.
			if err := clientCh.Send(ctx, tc.data); err != nil {
				t.Fatalf("send data failed: %v", err)
			}

			// Wait for data to be received.
			select {
			case data := <-received:
				if !bytes.Equal(data, tc.data) {
					t.Errorf("received data mismatch: got %d bytes, want %d bytes", len(data), len(tc.data))
				}
			case <-time.After(channelTestTimeout):
				t.Fatal("timed out waiting for data")
			}
		})
	}
}

func TestSendServerChannelData(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), channelTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	testData := []byte("hello from server")

	received := make(chan []byte, 1)
	clientCh.OnDataReceived = func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		received <- buf
		clientCh.AdjustWindow(uint32(len(data)))
	}

	// Send data from server to client.
	if err := serverCh.Send(ctx, testData); err != nil {
		t.Fatalf("server send failed: %v", err)
	}

	select {
	case data := <-received:
		if !bytes.Equal(data, testData) {
			t.Errorf("received data mismatch: got %q, want %q", data, testData)
		}
	case <-time.After(channelTestTimeout):
		t.Fatal("timed out waiting for server data")
	}
}

// TestSendWhileOpening verifies that the server can send data during the
// ChannelOpening event and the client receives it.
// Matches C#/TS ChannelTests.SendWhileOpening.
func TestSendWhileOpening(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), channelTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	testData := []byte{1, 2, 3}

	// Server sends data during the ChannelOpening event.
	pair.ServerSession.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
		go func() {
			_ = e.Channel.Send(context.Background(), testData)
		}()
	}

	clientCh, _ := pair.OpenChannel(ctx)

	// Use the thread-safe SetDataReceivedHandler which also delivers any
	// data that was buffered before the handler was installed.
	dataReceivedCh := make(chan []byte, 1)
	clientCh.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		dataReceivedCh <- buf
		clientCh.AdjustWindow(uint32(len(data)))
	})

	select {
	case received := <-dataReceivedCh:
		if !bytes.Equal(received, testData) {
			t.Errorf("received %v, want %v", received, testData)
		}
	case <-time.After(channelTestTimeout):
		t.Fatal("timed out waiting for data sent during channel opening")
	}
}

func TestSendChannelDataWithOffset(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), channelTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	// Create a larger buffer and send from an offset.
	fullBuffer := make([]byte, 20)
	for i := range fullBuffer {
		fullBuffer[i] = byte(i)
	}
	offset := 7
	dataToSend := fullBuffer[offset:] // 13 bytes starting from offset 7

	received := make(chan []byte, 1)
	serverCh.OnDataReceived = func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		received <- buf
		serverCh.AdjustWindow(uint32(len(data)))
	}

	if err := clientCh.Send(ctx, dataToSend); err != nil {
		t.Fatalf("send with offset failed: %v", err)
	}

	select {
	case data := <-received:
		if !bytes.Equal(data, dataToSend) {
			t.Errorf("received data mismatch: got %v, want %v", data, dataToSend)
		}
	case <-time.After(channelTestTimeout):
		t.Fatal("timed out waiting for data with offset")
	}
}
