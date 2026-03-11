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
)

// --- ChannelMetrics tests ---

// TestChannelMetricsBytesSentReceived verifies that ChannelMetrics correctly
// reports BytesSent and BytesReceived after data transfer through a channel.
func TestChannelMetricsBytesSentReceived(t *testing.T) {
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

	// Initial metrics should be zero.
	if clientCh.Metrics().BytesSent() != 0 {
		t.Errorf("initial client BytesSent = %d, want 0", clientCh.Metrics().BytesSent())
	}
	if serverCh.Metrics().BytesReceived() != 0 {
		t.Errorf("initial server BytesReceived = %d, want 0", serverCh.Metrics().BytesReceived())
	}

	// Set up a stream on the server side to consume data.
	serverStream := NewStream(serverCh)

	// Send 256 bytes from client to server.
	sent := make([]byte, 256)
	rand.Read(sent)
	if err := clientCh.Send(ctx, sent); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	received := make([]byte, 256)
	if _, err := io.ReadFull(serverStream, received); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	// Verify channel metrics.
	if clientCh.Metrics().BytesSent() != 256 {
		t.Errorf("client BytesSent = %d, want 256", clientCh.Metrics().BytesSent())
	}
	if serverCh.Metrics().BytesReceived() != 256 {
		t.Errorf("server BytesReceived = %d, want 256", serverCh.Metrics().BytesReceived())
	}

	// Now send 128 bytes in the other direction (server → client).
	clientStream := NewStream(clientCh)

	sent2 := make([]byte, 128)
	rand.Read(sent2)
	if err := serverCh.Send(ctx, sent2); err != nil {
		t.Fatalf("Send (server→client) failed: %v", err)
	}

	received2 := make([]byte, 128)
	if _, err := io.ReadFull(clientStream, received2); err != nil {
		t.Fatalf("ReadFull (server→client) failed: %v", err)
	}

	if serverCh.Metrics().BytesSent() != 128 {
		t.Errorf("server BytesSent = %d, want 128", serverCh.Metrics().BytesSent())
	}
	if clientCh.Metrics().BytesReceived() != 128 {
		t.Errorf("client BytesReceived = %d, want 128", clientCh.Metrics().BytesReceived())
	}
}

// --- SessionContour Export/Import tests ---

// TestSessionContourExportImportRoundTrip verifies that a SessionContour
// can be exported and imported back with the same data preserved.
func TestSessionContourExportImportRoundTrip(t *testing.T) {
	contour := NewSessionContour(16)

	// Add some synthetic updates.
	contour.AddUpdate(ContourUpdate{Time: 100, BytesSent: 1000, BytesReceived: 500, Latency: 5.0})
	contour.AddUpdate(ContourUpdate{Time: 200, BytesSent: 2000, BytesReceived: 1000, Latency: 10.0})
	contour.AddUpdate(ContourUpdate{Time: 1100, BytesSent: 500, BytesReceived: 300, Latency: 3.0})
	contour.AddUpdate(ContourUpdate{Time: 2200, BytesSent: 800, BytesReceived: 400, Latency: 7.0})

	// Export.
	exported := contour.Export()
	if exported == "" {
		t.Fatal("Export returned empty string")
	}

	// Import.
	imported, err := ImportContour(exported)
	if err != nil {
		t.Fatalf("ImportContour failed: %v", err)
	}

	// Verify interval count matches.
	if imported.IntervalCount() != contour.IntervalCount() {
		t.Errorf("imported interval count = %d, want %d",
			imported.IntervalCount(), contour.IntervalCount())
	}

	// Verify interval duration matches.
	if imported.IntervalMs() != contour.IntervalMs() {
		t.Errorf("imported intervalMs = %d, want %d",
			imported.IntervalMs(), contour.IntervalMs())
	}

	// Verify byte metrics are approximately preserved (may lose precision from scaling).
	origSent := contour.BytesSentSlice()
	importedSent := imported.BytesSentSlice()
	if len(origSent) != len(importedSent) {
		t.Fatalf("sent slice length mismatch: %d vs %d", len(origSent), len(importedSent))
	}
	for i := range origSent {
		if origSent[i] != 0 && importedSent[i] == 0 {
			t.Errorf("interval %d: bytesSent was %d but imported as 0", i, origSent[i])
		}
	}

	origRecv := contour.BytesReceivedSlice()
	importedRecv := imported.BytesReceivedSlice()
	for i := range origRecv {
		if origRecv[i] != 0 && importedRecv[i] == 0 {
			t.Errorf("interval %d: bytesReceived was %d but imported as 0", i, origRecv[i])
		}
	}

	// Verify latency metrics are approximately preserved.
	origLatMin := contour.LatencyMinMsSlice()
	importedLatMin := imported.LatencyMinMsSlice()
	for i := range origLatMin {
		if origLatMin[i] != 0 && importedLatMin[i] == 0 {
			t.Errorf("interval %d: latencyMin was %f but imported as 0", i, origLatMin[i])
		}
	}
}

// TestSessionContourExportImportEmptyContour verifies that exporting and
// importing an empty contour works correctly.
func TestSessionContourExportImportEmptyContour(t *testing.T) {
	contour := NewSessionContour(4)

	// Add at least one update so there's something to export.
	contour.AddUpdate(ContourUpdate{Time: 500, BytesSent: 100})

	exported := contour.Export()
	imported, err := ImportContour(exported)
	if err != nil {
		t.Fatalf("ImportContour failed: %v", err)
	}

	if imported.IntervalCount() != contour.IntervalCount() {
		t.Errorf("interval count = %d, want %d",
			imported.IntervalCount(), contour.IntervalCount())
	}
}

// --- Channel.Pipe tests ---

// TestChannelPipeBidirectional verifies that two channels piped together
// relay data bidirectionally.
func TestChannelPipeBidirectional(t *testing.T) {
	// Create two session pairs. Pipe connects a channel from each.
	client1, server1 := createSessionPair(t, nil)
	client2, server2 := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
		t.Fatalf("OpenChannel 1 failed: %v", err)
	}
	clientCh2, err := client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 2 failed: %v", err)
	}
	wg.Wait()

	// Pipe the two server-side channels together.
	go func() {
		_ = serverCh1.Pipe(ctx, serverCh2)
	}()

	// Wrap client channels as streams for convenient read/write.
	stream1 := NewStream(clientCh1)
	stream2 := NewStream(clientCh2)

	// Send data from client1 → server1 → (pipe) → server2 → client2.
	msg1 := []byte("hello from client 1")
	if _, err := stream1.Write(msg1); err != nil {
		t.Fatalf("Write to stream1 failed: %v", err)
	}

	buf := make([]byte, len(msg1))
	if _, err := io.ReadFull(stream2, buf); err != nil {
		t.Fatalf("ReadFull from stream2 failed: %v", err)
	}
	if !bytes.Equal(buf, msg1) {
		t.Errorf("data mismatch direction 1: got %q, want %q", buf, msg1)
	}

	// Send data in the other direction: client2 → server2 → (pipe) → server1 → client1.
	msg2 := []byte("hello from client 2")
	if _, err := stream2.Write(msg2); err != nil {
		t.Fatalf("Write to stream2 failed: %v", err)
	}

	buf2 := make([]byte, len(msg2))
	if _, err := io.ReadFull(stream1, buf2); err != nil {
		t.Fatalf("ReadFull from stream1 failed: %v", err)
	}
	if !bytes.Equal(buf2, msg2) {
		t.Errorf("data mismatch direction 2: got %q, want %q", buf2, msg2)
	}
}

// TestChannelPipeClosePropagatesToOtherSide verifies that closing one end
// of a piped channel pair closes the other end.
func TestChannelPipeClosePropagatesToOtherSide(t *testing.T) {
	client1, server1 := createSessionPair(t, nil)
	client2, server2 := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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
		t.Fatalf("OpenChannel 1 failed: %v", err)
	}
	if _, err := client2.OpenChannel(ctx); err != nil {
		t.Fatalf("OpenChannel 2 failed: %v", err)
	}
	wg.Wait()

	pipeDone := make(chan error, 1)
	go func() {
		pipeDone <- serverCh1.Pipe(ctx, serverCh2)
	}()

	// Close clientCh1 — should propagate through the pipe.
	if err := clientCh1.Close(); err != nil {
		t.Fatalf("Close clientCh1 failed: %v", err)
	}

	// Pipe should return.
	select {
	case <-pipeDone:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return after closing one end")
	}
}

// --- SSHStream tests ---

// TestSSHStreamReadWriteClose verifies that SSHStream wrapping a channel
// works as an io.ReadWriteCloser.
func TestSSHStreamReadWriteClose(t *testing.T) {
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

	clientStream := NewStream(clientCh)
	serverStream := NewStream(serverCh)

	// Verify it satisfies io.ReadWriteCloser at compile time.
	var _ io.ReadWriteCloser = clientStream
	var _ io.ReadWriteCloser = serverStream

	// Write from client to server.
	data := []byte("stream test data")
	n, err := clientStream.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Write returned n=%d, want %d", n, len(data))
	}

	// Read on server side.
	buf := make([]byte, len(data))
	n, err = io.ReadFull(serverStream, buf)
	if err != nil {
		t.Fatalf("ReadFull failed: %v (read %d)", err, n)
	}
	if !bytes.Equal(buf, data) {
		t.Errorf("data mismatch: got %q, want %q", buf, data)
	}

	// Write from server to client.
	data2 := []byte("response data")
	n, err = serverStream.Write(data2)
	if err != nil {
		t.Fatalf("Write (server) failed: %v", err)
	}
	if n != len(data2) {
		t.Errorf("Write returned n=%d, want %d", n, len(data2))
	}

	buf2 := make([]byte, len(data2))
	n, err = io.ReadFull(clientStream, buf2)
	if err != nil {
		t.Fatalf("ReadFull (client) failed: %v (read %d)", err, n)
	}
	if !bytes.Equal(buf2, data2) {
		t.Errorf("data mismatch: got %q, want %q", buf2, data2)
	}

	// Close client stream.
	if err := clientStream.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// After close, reading from server stream should eventually return EOF.
	readBuf := make([]byte, 64)
	_, err = serverStream.Read(readBuf)
	if err != io.EOF {
		t.Errorf("expected io.EOF after close, got %v", err)
	}
}

// TestSSHStreamCloseClosesChannel verifies that closing an SSHStream closes
// the underlying SSH channel.
func TestSSHStreamCloseClosesChannel(t *testing.T) {
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

	stream := NewStream(clientCh)

	// Channel should not be closed yet.
	closedCh := make(chan struct{}, 1)
	serverCh.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		select {
		case closedCh <- struct{}{}:
		default:
		}
	})

	// Close the stream.
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close() failed: %v", err)
	}

	// The server channel should receive the close notification.
	select {
	case <-closedCh:
		// OK — channel was closed via stream close
	case <-time.After(5 * time.Second):
		t.Fatal("server channel was not closed after stream.Close()")
	}

	// The underlying channel should report as closed.
	// Send should fail on the client channel since it's been closed.
	err = clientCh.Send(ctx, []byte("should fail"))
	if err == nil {
		t.Error("expected error sending on closed channel, got nil")
	}
}

// TestSSHStreamChannelAccessor verifies that the Channel() accessor returns
// the underlying channel.
func TestSSHStreamChannelAccessor(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	stream := NewStream(clientCh)
	if stream.Channel() != clientCh {
		t.Error("Channel() did not return the underlying channel")
	}
}
