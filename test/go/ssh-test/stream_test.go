// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

const streamTestTimeout = 10 * time.Second

// --- SshStream tests ---

func TestCloseStreamClosesChannel(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	// Wrap client channel in a stream.
	stream := ssh.NewStream(clientCh)

	serverClosed := make(chan struct{})
	serverCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		close(serverClosed)
	}

	// Close the stream.
	if err := stream.Close(); err != nil {
		t.Fatalf("stream close failed: %v", err)
	}

	// Wait for server channel to close.
	select {
	case <-serverClosed:
	case <-time.After(streamTestTimeout):
		t.Fatal("timed out waiting for server channel close after stream close")
	}

	// Verify client channel is closed.
	if !clientCh.IsClosed() {
		t.Error("client channel should be closed after stream close")
	}
}

func TestClosedStreamCannotReadOrWrite(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, _ := pair.OpenChannel(ctx)

	stream := ssh.NewStream(clientCh)

	// Close the stream.
	if err := stream.Close(); err != nil {
		t.Fatalf("stream close failed: %v", err)
	}

	// Wait briefly for close to propagate.
	time.Sleep(100 * time.Millisecond)

	// Write should fail.
	_, writeErr := stream.Write([]byte("test"))
	if writeErr == nil {
		t.Error("Write on closed stream should return error")
	}

	// Read should return EOF or error.
	buf := make([]byte, 10)
	_, readErr := stream.Read(buf)
	if readErr == nil {
		t.Error("Read on closed stream should return error")
	}
}

func TestStreamData(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	clientStream := ssh.NewStream(clientCh)
	serverStream := ssh.NewStream(serverCh)

	// Test bidirectional data transfer.
	testData := []byte("hello from client")
	serverTestData := []byte("hello from server")

	var wg sync.WaitGroup
	wg.Add(2)

	// Client writes, server reads.
	go func() {
		defer wg.Done()
		n, err := clientStream.Write(testData)
		if err != nil {
			t.Errorf("client write failed: %v", err)
			return
		}
		if n != len(testData) {
			t.Errorf("client write: got %d bytes, want %d", n, len(testData))
		}
	}()

	// Server reads client data.
	serverReceived := make(chan []byte, 1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, err := serverStream.Read(buf)
		if err != nil {
			t.Errorf("server read failed: %v", err)
			return
		}
		result := make([]byte, n)
		copy(result, buf[:n])
		serverReceived <- result
	}()

	wg.Wait()

	select {
	case data := <-serverReceived:
		if !bytes.Equal(data, testData) {
			t.Errorf("server received %q, want %q", data, testData)
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("timed out waiting for server to receive data")
	}

	// Now server writes, client reads.
	var wg2 sync.WaitGroup
	wg2.Add(2)

	go func() {
		defer wg2.Done()
		n, err := serverStream.Write(serverTestData)
		if err != nil {
			t.Errorf("server write failed: %v", err)
			return
		}
		if n != len(serverTestData) {
			t.Errorf("server write: got %d bytes, want %d", n, len(serverTestData))
		}
	}()

	clientReceived := make(chan []byte, 1)
	go func() {
		defer wg2.Done()
		buf := make([]byte, 1024)
		n, err := clientStream.Read(buf)
		if err != nil {
			t.Errorf("client read failed: %v", err)
			return
		}
		result := make([]byte, n)
		copy(result, buf[:n])
		clientReceived <- result
	}()

	wg2.Wait()

	select {
	case data := <-clientReceived:
		if !bytes.Equal(data, serverTestData) {
			t.Errorf("client received %q, want %q", data, serverTestData)
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("timed out waiting for client to receive data")
	}
}

// --- Channel Pipe tests ---

func TestPipeChannelClose(t *testing.T) {
	// Create two session pairs (4 sessions total) to pipe between.
	pair1 := helpers.NewSessionPair(t)
	defer pair1.Close()
	pair2 := helpers.NewSessionPair(t)
	defer pair2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()

	pair1.Connect(ctx)
	pair2.Connect(ctx)

	clientCh1, serverCh1 := pair1.OpenChannel(ctx)
	clientCh2, serverCh2 := pair2.OpenChannel(ctx)

	// Pipe serverCh1 to clientCh2 (relay between sessions).
	pipeDone := make(chan error, 1)
	go func() {
		pipeDone <- serverCh1.Pipe(ctx, clientCh2)
	}()

	// Close one end (clientCh1). The close should propagate through the pipe.
	clientCh1Closed := make(chan struct{})
	clientCh1.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		close(clientCh1Closed)
	}

	serverCh2Closed := make(chan struct{})
	serverCh2.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		close(serverCh2Closed)
	}

	if err := clientCh1.Close(); err != nil {
		t.Fatalf("close clientCh1 failed: %v", err)
	}

	// Wait for close to propagate through pipe to serverCh2.
	select {
	case <-serverCh2Closed:
	case <-time.After(streamTestTimeout):
		t.Fatal("timed out waiting for close to propagate through pipe")
	}

	// Pipe should be done.
	select {
	case err := <-pipeDone:
		if err != nil {
			t.Fatalf("pipe returned error: %v", err)
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("timed out waiting for pipe to finish")
	}
}

func TestPipeChannelSend(t *testing.T) {
	pair1 := helpers.NewSessionPair(t)
	defer pair1.Close()
	pair2 := helpers.NewSessionPair(t)
	defer pair2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()

	pair1.Connect(ctx)
	pair2.Connect(ctx)

	clientCh1, serverCh1 := pair1.OpenChannel(ctx)
	clientCh2, serverCh2 := pair2.OpenChannel(ctx)

	// Pipe serverCh1 to clientCh2.
	go func() {
		_ = serverCh1.Pipe(ctx, clientCh2)
	}()

	// Send data from clientCh1 → serverCh1 → (pipe) → clientCh2 → serverCh2.
	testData := []byte("piped data")

	received := make(chan []byte, 1)
	serverCh2.OnDataReceived = func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		received <- buf
		serverCh2.AdjustWindow(uint32(len(data)))
	}

	if err := clientCh1.Send(ctx, testData); err != nil {
		t.Fatalf("send through pipe failed: %v", err)
	}

	select {
	case data := <-received:
		if !bytes.Equal(data, testData) {
			t.Errorf("received through pipe: got %q, want %q", data, testData)
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("timed out waiting for data through pipe")
	}

	// Test reverse direction: serverCh2 → clientCh2 → (pipe) → serverCh1 → clientCh1.
	reverseData := []byte("reverse piped data")

	reverseReceived := make(chan []byte, 1)
	clientCh1.OnDataReceived = func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		reverseReceived <- buf
		clientCh1.AdjustWindow(uint32(len(data)))
	}

	if err := serverCh2.Send(ctx, reverseData); err != nil {
		t.Fatalf("reverse send through pipe failed: %v", err)
	}

	select {
	case data := <-reverseReceived:
		if !bytes.Equal(data, reverseData) {
			t.Errorf("reverse received through pipe: got %q, want %q", data, reverseData)
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("timed out waiting for reverse data through pipe")
	}
}

func TestPipeChannelSendSequence(t *testing.T) {
	pair1 := helpers.NewSessionPair(t)
	defer pair1.Close()
	pair2 := helpers.NewSessionPair(t)
	defer pair2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), streamTestTimeout)
	defer cancel()

	pair1.Connect(ctx)
	pair2.Connect(ctx)

	clientCh1, serverCh1 := pair1.OpenChannel(ctx)
	clientCh2, serverCh2 := pair2.OpenChannel(ctx)

	// Pipe serverCh1 to clientCh2.
	go func() {
		_ = serverCh1.Pipe(ctx, clientCh2)
	}()

	// Send 1000 sequential messages through the pipe.
	const messageCount = 1000
	allReceived := make(chan struct{})

	var receivedMu sync.Mutex
	var receivedMessages [][]byte

	serverCh2.OnDataReceived = func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		receivedMu.Lock()
		receivedMessages = append(receivedMessages, buf)
		count := len(receivedMessages)
		receivedMu.Unlock()
		serverCh2.AdjustWindow(uint32(len(data)))

		if count >= messageCount {
			select {
			case <-allReceived:
			default:
				close(allReceived)
			}
		}
	}

	for i := 0; i < messageCount; i++ {
		msg := []byte{byte(i >> 8), byte(i & 0xFF)}
		if err := clientCh1.Send(ctx, msg); err != nil {
			t.Fatalf("send message %d failed: %v", i, err)
		}
	}

	select {
	case <-allReceived:
	case <-time.After(streamTestTimeout):
		receivedMu.Lock()
		count := len(receivedMessages)
		receivedMu.Unlock()
		t.Fatalf("timed out: received %d of %d messages", count, messageCount)
	}

	// Verify order is preserved.
	receivedMu.Lock()
	defer receivedMu.Unlock()

	if len(receivedMessages) != messageCount {
		t.Fatalf("received %d messages, want %d", len(receivedMessages), messageCount)
	}

	// Reconstruct and verify message order.
	// Messages may arrive concatenated (multiple messages in one data callback).
	var allBytes []byte
	for _, msg := range receivedMessages {
		allBytes = append(allBytes, msg...)
	}

	if len(allBytes) != messageCount*2 {
		t.Fatalf("total bytes = %d, want %d", len(allBytes), messageCount*2)
	}

	for i := 0; i < messageCount; i++ {
		expectedHi := byte(i >> 8)
		expectedLo := byte(i & 0xFF)
		if allBytes[i*2] != expectedHi || allBytes[i*2+1] != expectedLo {
			t.Fatalf("message %d out of order: got [%d, %d], want [%d, %d]",
				i, allBytes[i*2], allBytes[i*2+1], expectedHi, expectedLo)
		}
	}
}

func TestPipeChannelSendLargeData(t *testing.T) {
	pair1 := helpers.NewSessionPair(t)
	defer pair1.Close()
	pair2 := helpers.NewSessionPair(t)
	defer pair2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pair1.Connect(ctx)
	pair2.Connect(ctx)

	clientCh1, serverCh1 := pair1.OpenChannel(ctx)
	clientCh2, serverCh2 := pair2.OpenChannel(ctx)

	// Pipe serverCh1 to clientCh2.
	go func() {
		_ = serverCh1.Pipe(ctx, clientCh2)
	}()

	// Send 3.5 MB through the pipe.
	const dataSize = 3*1024*1024 + 512*1024 // 3.5 MB
	testData := helpers.GenerateDeterministicBytes(99, dataSize)

	receiveDone := make(chan struct{})
	var receivedData []byte
	var receivedMu sync.Mutex

	serverCh2.OnDataReceived = func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)

		receivedMu.Lock()
		receivedData = append(receivedData, buf...)
		total := len(receivedData)
		receivedMu.Unlock()

		serverCh2.AdjustWindow(uint32(len(data)))

		if total >= dataSize {
			select {
			case <-receiveDone:
			default:
				close(receiveDone)
			}
		}
	}

	// Send in a goroutine since it may block on window.
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- clientCh1.Send(ctx, testData)
	}()

	// Wait for all data to be received.
	select {
	case <-receiveDone:
	case <-time.After(30 * time.Second):
		receivedMu.Lock()
		total := len(receivedData)
		receivedMu.Unlock()
		t.Fatalf("timed out: received %d of %d bytes", total, dataSize)
	}

	// Wait for send to complete.
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("send large data failed: %v", err)
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("timed out waiting for send to complete")
	}

	// Verify data integrity.
	receivedMu.Lock()
	defer receivedMu.Unlock()

	if len(receivedData) != dataSize {
		t.Fatalf("received %d bytes, want %d", len(receivedData), dataSize)
	}

	if !bytes.Equal(receivedData, testData) {
		// Find first difference.
		for i := 0; i < len(testData); i++ {
			if receivedData[i] != testData[i] {
				t.Fatalf("data mismatch at byte %d: got %d, want %d", i, receivedData[i], testData[i])
				break
			}
		}
	}
}

// --- Verify Stream implements io.ReadWriteCloser ---

func TestStreamImplementsInterface(t *testing.T) {
	var _ io.ReadWriteCloser = (*ssh.Stream)(nil)
}
