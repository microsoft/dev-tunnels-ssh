// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"
)

// TestMetricsBytesSentReceived verifies that ChannelMetrics correctly reports
// BytesSent == 1000 on sender and BytesReceived == 1000 on receiver after
// sending exactly 1000 bytes through an SSH channel.
func TestMetricsBytesSentReceived(t *testing.T) {
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

	// Set up a stream on the server side to consume data.
	serverStream := NewStream(serverCh)

	// Send exactly 1000 bytes from client to server.
	sent := make([]byte, 1000)
	rand.Read(sent)
	if err := clientCh.Send(ctx, sent); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	received := make([]byte, 1000)
	if _, err := io.ReadFull(serverStream, received); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	if clientCh.Metrics().BytesSent() != 1000 {
		t.Errorf("client BytesSent = %d, want 1000", clientCh.Metrics().BytesSent())
	}
	if serverCh.Metrics().BytesReceived() != 1000 {
		t.Errorf("server BytesReceived = %d, want 1000", serverCh.Metrics().BytesReceived())
	}
}

// TestSessionMetricsMessageCount verifies that session-level Metrics()
// correctly counts messages sent and received during connect + auth + channel
// open + data exchange. Both counters should be > 0 and plausible.
func TestSessionMetricsMessageCount(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// After connect, both sides have exchanged version + KEX + auth messages.
	clientMetrics := client.Metrics()
	serverMetrics := server.Metrics()

	if clientMetrics.MessagesSent() <= 0 {
		t.Errorf("client MessagesSent = %d, want > 0", clientMetrics.MessagesSent())
	}
	if clientMetrics.MessagesReceived() <= 0 {
		t.Errorf("client MessagesReceived = %d, want > 0", clientMetrics.MessagesReceived())
	}
	if serverMetrics.MessagesSent() <= 0 {
		t.Errorf("server MessagesSent = %d, want > 0", serverMetrics.MessagesSent())
	}
	if serverMetrics.MessagesReceived() <= 0 {
		t.Errorf("server MessagesReceived = %d, want > 0", serverMetrics.MessagesReceived())
	}

	sentBefore := clientMetrics.MessagesSent()
	recvBefore := serverMetrics.MessagesReceived()

	// Open a channel and send data to generate more messages.
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

	// Send some data.
	serverStream := NewStream(serverCh)
	data := make([]byte, 100)
	rand.Read(data)
	if err := clientCh.Send(ctx, data); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	buf := make([]byte, 100)
	if _, err := io.ReadFull(serverStream, buf); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	// Verify message counts increased.
	if clientMetrics.MessagesSent() <= sentBefore {
		t.Errorf("client MessagesSent did not increase: before=%d, after=%d",
			sentBefore, clientMetrics.MessagesSent())
	}
	if serverMetrics.MessagesReceived() <= recvBefore {
		t.Errorf("server MessagesReceived did not increase: before=%d, after=%d",
			recvBefore, serverMetrics.MessagesReceived())
	}

	// Verify wire bytes are also tracked.
	if clientMetrics.BytesSent() <= 0 {
		t.Errorf("client BytesSent = %d, want > 0", clientMetrics.BytesSent())
	}
	if serverMetrics.BytesReceived() <= 0 {
		t.Errorf("server BytesReceived = %d, want > 0", serverMetrics.BytesReceived())
	}
}

// TestSessionLatencyAfterKeepAlive verifies that with keep-alive enabled and
// the latency extension active, Metrics().LatencyCurrentMs() is populated
// with a non-negative duration after at least one keep-alive round-trip.
func TestSessionLatencyAfterKeepAlive(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	clientConfig := NewDefaultConfigWithReconnect()
	clientConfig.KeepAliveIntervalSeconds = 1

	serverConfig := NewDefaultConfigWithReconnect()

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: clientConfig,
		ServerConfig: serverConfig,
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// With encrypted sessions, authentication is required before keep-alive
	// requests are sent (canAcceptRequests checks isAuthenticated).
	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "testpass",
	})
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if !success {
		t.Fatal("Authenticate returned false")
	}

	// Wait for reconnect (and thus latency) extension to be enabled.
	if err := WaitUntilReconnectEnabled(ctx, &client.Session, &server.Session); err != nil {
		t.Fatalf("WaitUntilReconnectEnabled: %v", err)
	}

	// Set up keep-alive success callback.
	successCh := make(chan int, 5)
	client.Session.mu.Lock()
	client.Session.OnKeepAliveSucceeded = func(count int) {
		successCh <- count
	}
	client.Session.mu.Unlock()

	// Wait for at least one keep-alive round-trip to complete.
	select {
	case count := <-successCh:
		if count < 1 {
			t.Errorf("expected positive success count, got %d", count)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for keep-alive success")
	}

	// After keep-alive round-trips with latency extension, latency should
	// be populated. Allow a short delay for the protocol layer to process.
	time.Sleep(100 * time.Millisecond)

	latency := client.Metrics().LatencyCurrentMs()
	if latency < 0 {
		t.Errorf("LatencyCurrentMs = %f, want >= 0", latency)
	}

	// Min and max should also be populated if current latency is > 0.
	if latency > 0 {
		if client.Metrics().LatencyMinMs() <= 0 {
			t.Errorf("LatencyMinMs = %f, want > 0", client.Metrics().LatencyMinMs())
		}
		if client.Metrics().LatencyMaxMs() <= 0 {
			t.Errorf("LatencyMaxMs = %f, want > 0", client.Metrics().LatencyMaxMs())
		}
		if client.Metrics().LatencyAverageMs() <= 0 {
			t.Errorf("LatencyAverageMs = %f, want > 0", client.Metrics().LatencyAverageMs())
		}
	}
}

// TestSessionContourRecording verifies that a SessionContour connected to
// live session metrics records non-empty data points during data exchange.
func TestSessionContourRecording(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create and attach contour to client metrics.
	contour := NewSessionContour(16)
	contour.CollectMetrics(client.Metrics())
	defer contour.Stop()

	// Open a channel and exchange data over several intervals.
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

	// Send several bursts of data with small delays to span contour intervals.
	for i := 0; i < 5; i++ {
		data := make([]byte, 512)
		rand.Read(data)
		if err := clientCh.Send(ctx, data); err != nil {
			t.Fatalf("Send %d failed: %v", i, err)
		}
		buf := make([]byte, 512)
		if _, err := io.ReadFull(serverStream, buf); err != nil {
			t.Fatalf("ReadFull %d failed: %v", i, err)
		}
	}

	// Stop collection to flush pending updates.
	contour.Stop()

	// Verify contour has recorded data.
	if contour.IntervalCount() == 0 {
		t.Fatal("contour IntervalCount = 0, want > 0")
	}

	// Verify export produces a non-empty string.
	exported := contour.Export()
	if exported == "" {
		t.Fatal("Export returned empty string")
	}

	// At least some bytes should be recorded.
	sentSlice := contour.BytesSentSlice()
	totalSent := int64(0)
	for _, v := range sentSlice {
		totalSent += v
	}
	if totalSent <= 0 {
		t.Errorf("total bytes sent in contour = %d, want > 0", totalSent)
	}
}

// TestSessionContourExportImport verifies that exporting a contour and
// importing it into a new SessionContour preserves the data faithfully.
func TestSessionContourExportImport(t *testing.T) {
	original := NewSessionContour(16)

	// Add updates across multiple intervals.
	original.AddUpdate(ContourUpdate{Time: 100, BytesSent: 1000, BytesReceived: 500, Latency: 5.0})
	original.AddUpdate(ContourUpdate{Time: 500, BytesSent: 2000, BytesReceived: 1500, Latency: 8.0})
	original.AddUpdate(ContourUpdate{Time: 1200, BytesSent: 3000, BytesReceived: 2000, Latency: 3.0})
	original.AddUpdate(ContourUpdate{Time: 2500, BytesSent: 800, BytesReceived: 400, Latency: 12.0})
	original.AddUpdate(ContourUpdate{Time: 3700, BytesSent: 1500, BytesReceived: 900, Latency: 6.0})

	// Export.
	exported := original.Export()
	if exported == "" {
		t.Fatal("Export returned empty string")
	}

	// Import.
	imported, err := ImportContour(exported)
	if err != nil {
		t.Fatalf("ImportContour failed: %v", err)
	}

	// Verify interval count matches.
	if imported.IntervalCount() != original.IntervalCount() {
		t.Errorf("imported interval count = %d, want %d",
			imported.IntervalCount(), original.IntervalCount())
	}

	// Verify interval duration matches.
	if imported.IntervalMs() != original.IntervalMs() {
		t.Errorf("imported intervalMs = %d, want %d",
			imported.IntervalMs(), original.IntervalMs())
	}

	// Verify bytes sent are preserved (may lose minor precision from scaling).
	origSent := original.BytesSentSlice()
	importedSent := imported.BytesSentSlice()
	if len(origSent) != len(importedSent) {
		t.Fatalf("sent slice length mismatch: %d vs %d", len(origSent), len(importedSent))
	}
	for i := range origSent {
		if origSent[i] != 0 && importedSent[i] == 0 {
			t.Errorf("interval %d: bytesSent was %d but imported as 0", i, origSent[i])
		}
	}

	// Verify bytes received are preserved.
	origRecv := original.BytesReceivedSlice()
	importedRecv := imported.BytesReceivedSlice()
	for i := range origRecv {
		if origRecv[i] != 0 && importedRecv[i] == 0 {
			t.Errorf("interval %d: bytesReceived was %d but imported as 0", i, origRecv[i])
		}
	}

	// Verify latency metrics are preserved.
	origLatMin := original.LatencyMinMsSlice()
	importedLatMin := imported.LatencyMinMsSlice()
	for i := range origLatMin {
		if origLatMin[i] != 0 && importedLatMin[i] == 0 {
			t.Errorf("interval %d: latencyMin was %f but imported as 0", i, origLatMin[i])
		}
	}

	origLatMax := original.LatencyMaxMsSlice()
	importedLatMax := imported.LatencyMaxMsSlice()
	for i := range origLatMax {
		if origLatMax[i] != 0 && importedLatMax[i] == 0 {
			t.Errorf("interval %d: latencyMax was %f but imported as 0", i, origLatMax[i])
		}
	}

	origLatAvg := original.LatencyAverageMsSlice()
	importedLatAvg := imported.LatencyAverageMsSlice()
	for i := range origLatAvg {
		if origLatAvg[i] != 0 && importedLatAvg[i] == 0 {
			t.Errorf("interval %d: latencyAvg was %f but imported as 0", i, origLatAvg[i])
		}
	}
}
