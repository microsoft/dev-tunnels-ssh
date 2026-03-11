// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

const metricsTestTimeout = 5 * time.Second

// sendDataBetweenChannels sends each data buffer from channelA and waits for it
// to be received on channelB. This mirrors the C#/TS SendDataBetweenChannelsAsync helper.
func sendDataBetweenChannels(
	t *testing.T,
	ctx context.Context,
	data [][]byte,
	channelA *ssh.Channel,
	channelB *ssh.Channel,
) {
	t.Helper()

	totalExpected := 0
	for _, d := range data {
		totalExpected += len(d)
	}

	var mu sync.Mutex
	var received bytes.Buffer
	done := make(chan struct{})

	channelB.OnDataReceived = func(d []byte) {
		mu.Lock()
		received.Write(d)
		total := received.Len()
		mu.Unlock()
		channelB.AdjustWindow(uint32(len(d)))
		if total >= totalExpected {
			close(done)
		}
	}

	for _, d := range data {
		if err := channelA.Send(ctx, d); err != nil {
			t.Fatalf("send data failed: %v", err)
		}
	}

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("timed out waiting for data")
	}
}

func TestMeasureChannelBytes(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), metricsTestTimeout)
	defer cancel()

	pair.Connect(ctx)
	clientCh, serverCh := pair.OpenChannel(ctx)

	data := [][]byte{{1}, {1, 2, 3}}
	sendDataBetweenChannels(t, ctx, data, clientCh, serverCh)

	if got := clientCh.Metrics().BytesSent(); got != 4 {
		t.Errorf("client channel BytesSent = %d, want 4", got)
	}
	if got := clientCh.Metrics().BytesReceived(); got != 0 {
		t.Errorf("client channel BytesReceived = %d, want 0", got)
	}
	if got := serverCh.Metrics().BytesSent(); got != 0 {
		t.Errorf("server channel BytesSent = %d, want 0", got)
	}
	if got := serverCh.Metrics().BytesReceived(); got != 4 {
		t.Errorf("server channel BytesReceived = %d, want 4", got)
	}
}

func TestMeasureSessionBytes(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), metricsTestTimeout)
	defer cancel()

	pair.Connect(ctx)
	clientCh, serverCh := pair.OpenChannel(ctx)

	// After connect + channel open, both sessions should have non-zero bytes
	// from the version exchange and kex init messages.
	initialClientBytesSent := pair.ClientSession.Metrics().BytesSent()
	initialClientBytesReceived := pair.ClientSession.Metrics().BytesReceived()
	initialServerBytesSent := pair.ServerSession.Metrics().BytesSent()
	initialServerBytesReceived := pair.ServerSession.Metrics().BytesReceived()

	if initialClientBytesSent == 0 {
		t.Error("initial client BytesSent should not be 0")
	}
	if initialClientBytesReceived == 0 {
		t.Error("initial client BytesReceived should not be 0")
	}
	if initialServerBytesSent == 0 {
		t.Error("initial server BytesSent should not be 0")
	}
	if initialServerBytesReceived == 0 {
		t.Error("initial server BytesReceived should not be 0")
	}

	data := [][]byte{{1}, {1, 2, 3}}
	sendDataBetweenChannels(t, ctx, data, clientCh, serverCh)

	// Client sent data, so its BytesSent should increase.
	if pair.ClientSession.Metrics().BytesSent() <= initialClientBytesSent {
		t.Error("client session BytesSent should have increased after sending data")
	}
	// Client didn't receive data, so its BytesReceived should stay the same.
	if pair.ClientSession.Metrics().BytesReceived() != initialClientBytesReceived {
		t.Errorf("client session BytesReceived changed unexpectedly: was %d, now %d",
			initialClientBytesReceived, pair.ClientSession.Metrics().BytesReceived())
	}
	// Server didn't send data, so its BytesSent should stay the same.
	// Note: server may send window adjust messages, so we check it didn't send
	// before the data transfer. Actually in the C# test, the server's BytesSent
	// stays the same because it doesn't send window adjusts for small data
	// (under 50% of window).
	if pair.ServerSession.Metrics().BytesSent() != initialServerBytesSent {
		t.Errorf("server session BytesSent changed unexpectedly: was %d, now %d",
			initialServerBytesSent, pair.ServerSession.Metrics().BytesSent())
	}
	// Server received data, so its BytesReceived should increase.
	if pair.ServerSession.Metrics().BytesReceived() <= initialServerBytesReceived {
		t.Error("server session BytesReceived should have increased after receiving data")
	}
}

func TestMeasureSessionMessages(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), metricsTestTimeout)
	defer cancel()

	pair.Connect(ctx)
	clientCh, serverCh := pair.OpenChannel(ctx)

	// After connect + channel open, both sessions should have non-zero message counts
	// from the version exchange and kex init messages.
	initialClientMessagesSent := pair.ClientSession.Metrics().MessagesSent()
	initialClientMessagesReceived := pair.ClientSession.Metrics().MessagesReceived()
	initialServerMessagesSent := pair.ServerSession.Metrics().MessagesSent()
	initialServerMessagesReceived := pair.ServerSession.Metrics().MessagesReceived()

	if initialClientMessagesSent == 0 {
		t.Error("initial client MessagesSent should not be 0")
	}
	if initialClientMessagesReceived == 0 {
		t.Error("initial client MessagesReceived should not be 0")
	}
	if initialServerMessagesSent == 0 {
		t.Error("initial server MessagesSent should not be 0")
	}
	if initialServerMessagesReceived == 0 {
		t.Error("initial server MessagesReceived should not be 0")
	}

	data := [][]byte{{1}, {1, 2, 3}}
	sendDataBetweenChannels(t, ctx, data, clientCh, serverCh)

	// Client sent 2 data messages, so MessagesSent should increase.
	if pair.ClientSession.Metrics().MessagesSent() <= initialClientMessagesSent {
		t.Error("client session MessagesSent should have increased after sending data")
	}
	// Client didn't receive data messages, so MessagesReceived should stay the same.
	if pair.ClientSession.Metrics().MessagesReceived() != initialClientMessagesReceived {
		t.Errorf("client session MessagesReceived changed unexpectedly: was %d, now %d",
			initialClientMessagesReceived, pair.ClientSession.Metrics().MessagesReceived())
	}
	// Server didn't send data messages, so MessagesSent should stay the same.
	if pair.ServerSession.Metrics().MessagesSent() != initialServerMessagesSent {
		t.Errorf("server session MessagesSent changed unexpectedly: was %d, now %d",
			initialServerMessagesSent, pair.ServerSession.Metrics().MessagesSent())
	}
	// Server received 2 data messages, so MessagesReceived should increase.
	if pair.ServerSession.Metrics().MessagesReceived() <= initialServerMessagesReceived {
		t.Error("server session MessagesReceived should have increased after receiving data")
	}
}

// createReconnectSessionPair creates a connected session pair with DefaultWithReconnect config.
// Server credentials are set up with RSA and ECDSA host keys.
func createReconnectSessionPair(t *testing.T) *helpers.SessionPair {
	t.Helper()

	serverConfig := ssh.NewDefaultConfigWithReconnect()
	clientConfig := ssh.NewDefaultConfigWithReconnect()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})

	// Server needs host keys for real key exchange.
	rsaKey := helpers.GenerateTestRSAKey(t)
	rsaKP, err := ssh.NewRsaKeyPair(rsaKey, ssh.AlgoPKRsaSha512)
	if err != nil {
		t.Fatalf("failed to create RSA key pair: %v", err)
	}
	serverKey := helpers.GenerateTestECDSAKey(t)
	ecdsaKP, err := ssh.NewEcdsaKeyPair(serverKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{rsaKP, ecdsaKP},
	}

	return pair
}

// waitForLatency polls metrics until latency is non-zero or context cancels.
func waitForLatency(ctx context.Context, metrics *ssh.SessionMetrics) bool {
	for {
		if metrics.LatencyCurrentMs() != 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestMeasureSessionLatency(t *testing.T) {
	pair := createReconnectSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pair.Connect(ctx)

	// Wait for reconnect extension to be fully enabled on both sides.
	// This ensures OutgoingMessagesHaveReconnectInfo and IncomingMessagesHaveReconnectInfo
	// are set on both sessions before we start sending data.
	if err := ssh.WaitUntilReconnectEnabled(ctx, &pair.ClientSession.Session, &pair.ServerSession.Session); err != nil {
		t.Fatalf("reconnect not enabled: %v", err)
	}
	// Additional settle time for the async enable-reconnect request/response exchange.
	time.Sleep(200 * time.Millisecond)

	clientCh, serverCh := pair.OpenChannel(ctx)

	// Send data in multiple round-trips. Latency requires bidirectional traffic
	// so that timestamps are exchanged and acknowledged. Multiple rounds ensure
	// both sides have cached messages that get acknowledged by the other side.
	data := [][]byte{{1}}
	sendDataBetweenChannels(t, ctx, data, clientCh, serverCh)
	sendDataBetweenChannels(t, ctx, data, serverCh, clientCh)
	sendDataBetweenChannels(t, ctx, data, clientCh, serverCh)
	sendDataBetweenChannels(t, ctx, data, serverCh, clientCh)

	// Wait for latency to be measured on both sides.
	if !waitForLatency(ctx, pair.ClientSession.Metrics()) {
		t.Fatal("timed out waiting for client latency")
	}
	if !waitForLatency(ctx, pair.ServerSession.Metrics()) {
		t.Fatal("timed out waiting for server latency")
	}

	validateLatency := func(name string, metrics *ssh.SessionMetrics) {
		t.Helper()
		if metrics.LatencyMaxMs() == 0 {
			t.Errorf("%s LatencyMaxMs should not be 0", name)
		}
		if metrics.LatencyAverageMs() == 0 {
			t.Errorf("%s LatencyAverageMs should not be 0", name)
		}
		if metrics.LatencyMinMs() == 0 {
			t.Errorf("%s LatencyMinMs should not be 0", name)
		}
		if metrics.LatencyCurrentMs() == 0 {
			t.Errorf("%s LatencyCurrentMs should not be 0", name)
		}
		if metrics.LatencyMinMs() > metrics.LatencyAverageMs() {
			t.Errorf("%s LatencyMinMs (%f) > LatencyAverageMs (%f)",
				name, metrics.LatencyMinMs(), metrics.LatencyAverageMs())
		}
		if metrics.LatencyAverageMs() > metrics.LatencyMaxMs() {
			t.Errorf("%s LatencyAverageMs (%f) > LatencyMaxMs (%f)",
				name, metrics.LatencyAverageMs(), metrics.LatencyMaxMs())
		}
	}

	validateLatency("client", pair.ClientSession.Metrics())
	validateLatency("server", pair.ServerSession.Metrics())
}

func TestClosedSessionHasNoLatency(t *testing.T) {
	pair := createReconnectSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pair.Connect(ctx)
	pair.OpenChannel(ctx)

	pair.ClientSession.CloseWithReason(ctx, messages.DisconnectByApplication, "")
	pair.ServerSession.CloseWithReason(ctx, messages.DisconnectByApplication, "")

	// Wait for latency to be reset.
	deadline := time.After(5 * time.Second)
	for {
		clientZero := pair.ClientSession.Metrics().LatencyCurrentMs() == 0
		serverZero := pair.ServerSession.Metrics().LatencyCurrentMs() == 0
		if clientZero && serverZero {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for latency to be reset to 0")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestRecordSessionContour(t *testing.T) {
	pair := createReconnectSessionPair(t)
	defer pair.Close()

	clientContour := ssh.NewSessionContour(256)
	serverContour := ssh.NewSessionContour(256)

	clientContour.CollectMetrics(pair.ClientSession.Metrics())
	serverContour.CollectMetrics(pair.ServerSession.Metrics())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	validateContour := func(name string, contour *ssh.SessionContour) {
		t.Helper()

		intervalMs := contour.IntervalMs()
		// Normally 1s but could expand on slow machines.
		if intervalMs != 1000 && intervalMs != 2000 && intervalMs != 4000 {
			t.Errorf("%s unexpected interval: %d ms", name, intervalMs)
		}

		n := contour.IntervalCount()
		if n == 0 {
			t.Errorf("%s IntervalCount should not be 0", name)
		}

		// Check that some latency was recorded.
		var latencyMinSum, latencyMaxSum, latencyAvgSum float32
		var bytesSentSum, bytesReceivedSum int64
		for i := 0; i < n; i++ {
			latencyMinSum += contour.LatencyMinMsAt(i)
			latencyMaxSum += contour.LatencyMaxMsAt(i)
			latencyAvgSum += contour.LatencyAverageMsAt(i)
			bytesSentSum += contour.BytesSentAt(i)
			bytesReceivedSum += contour.BytesReceivedAt(i)

			if contour.LatencyMinMsAt(i) > contour.LatencyAverageMsAt(i) && contour.LatencyAverageMsAt(i) > 0 {
				t.Errorf("%s interval %d: LatencyMin (%f) > LatencyAvg (%f)",
					name, i, contour.LatencyMinMsAt(i), contour.LatencyAverageMsAt(i))
			}
			if contour.LatencyAverageMsAt(i) > contour.LatencyMaxMsAt(i) {
				t.Errorf("%s interval %d: LatencyAvg (%f) > LatencyMax (%f)",
					name, i, contour.LatencyAverageMsAt(i), contour.LatencyMaxMsAt(i))
			}
		}

		if latencyMinSum == 0 {
			t.Errorf("%s total LatencyMin should not be 0", name)
		}
		if latencyMaxSum == 0 {
			t.Errorf("%s total LatencyMax should not be 0", name)
		}
		if latencyAvgSum == 0 {
			t.Errorf("%s total LatencyAvg should not be 0", name)
		}
		if bytesSentSum == 0 {
			t.Errorf("%s total BytesSent should not be 0", name)
		}
		if bytesReceivedSum == 0 {
			t.Errorf("%s total BytesReceived should not be 0", name)
		}
	}

	data := [][]byte{{1}}
	time.Sleep(1 * time.Second)
	sendDataBetweenChannels(t, ctx, data, clientCh, serverCh)
	sendDataBetweenChannels(t, ctx, data, serverCh, clientCh)
	time.Sleep(1 * time.Second)
	sendDataBetweenChannels(t, ctx, data, clientCh, serverCh)
	sendDataBetweenChannels(t, ctx, data, serverCh, clientCh)
	time.Sleep(1 * time.Second)
	sendDataBetweenChannels(t, ctx, data, clientCh, serverCh)
	sendDataBetweenChannels(t, ctx, data, serverCh, clientCh)

	// Close sessions to stop contour collection.
	pair.ClientSession.Close()
	pair.ServerSession.Close()

	// Give time for contour goroutines to drain.
	time.Sleep(100 * time.Millisecond)

	validateContour("client", clientContour)
	validateContour("server", serverContour)
}

func TestExpandContourIntervals(t *testing.T) {
	contour := ssh.NewSessionContour(4)

	assertEqual := func(name string, got, want interface{}) {
		t.Helper()
		switch g := got.(type) {
		case int64:
			if g != want.(int64) {
				t.Errorf("%s = %d, want %d", name, g, want)
			}
		case float32:
			if g != want.(float32) {
				t.Errorf("%s = %f, want %f", name, g, want)
			}
		}
	}

	assertSliceEqual := func(prefix string, got, want interface{}) {
		t.Helper()
		switch g := got.(type) {
		case []int64:
			w := want.([]int64)
			if len(g) != len(w) {
				t.Errorf("%s length = %d, want %d (got=%v, want=%v)", prefix, len(g), len(w), g, w)
				return
			}
			for i := range g {
				if g[i] != w[i] {
					t.Errorf("%s[%d] = %d, want %d (got=%v, want=%v)", prefix, i, g[i], w[i], g, w)
					return
				}
			}
		case []float32:
			w := want.([]float32)
			if len(g) != len(w) {
				t.Errorf("%s length = %d, want %d (got=%v, want=%v)", prefix, len(g), len(w), g, w)
				return
			}
			for i := range g {
				if g[i] != w[i] {
					t.Errorf("%s[%d] = %f, want %f (got=%v, want=%v)", prefix, i, g[i], w[i], g, w)
					return
				}
			}
		}
	}

	// Initial interval should be 1 second.
	assertEqual("initial interval", contour.IntervalMs(), int64(1000))

	// Add some updates at various times.
	contour.AddUpdate(ssh.ContourUpdate{Time: 2000, BytesReceived: 2})
	contour.AddUpdate(ssh.ContourUpdate{Time: 3000, Latency: 16})
	contour.AddUpdate(ssh.ContourUpdate{Time: 3500, Latency: 32})
	contour.AddUpdate(ssh.ContourUpdate{Time: 3800, BytesSent: 1})
	contour.AddUpdate(ssh.ContourUpdate{Time: 3900, BytesReceived: 3})

	assertEqual("interval after first batch", contour.IntervalMs(), int64(1000))
	assertSliceEqual("LatencyMin[0]", contour.LatencyMinMsSlice(), []float32{0, 0, 0, 16})
	assertSliceEqual("LatencyMax[0]", contour.LatencyMaxMsSlice(), []float32{0, 0, 0, 32})
	assertSliceEqual("LatencyAvg[0]", contour.LatencyAverageMsSlice(), []float32{0, 0, 0, 24})
	assertSliceEqual("BytesSent[0]", contour.BytesSentSlice(), []int64{0, 0, 0, 1})
	assertSliceEqual("BytesReceived[0]", contour.BytesReceivedSlice(), []int64{0, 0, 2, 3})

	// Adding data at 4s triggers expansion (maxIntervals=4, need index 4).
	contour.AddUpdate(ssh.ContourUpdate{Time: 4000, BytesSent: 1})
	contour.AddUpdate(ssh.ContourUpdate{Time: 4500, Latency: 32})
	contour.AddUpdate(ssh.ContourUpdate{Time: 4600, Latency: 16})

	assertEqual("interval after expansion 1", contour.IntervalMs(), int64(2000))
	assertSliceEqual("LatencyMin[1]", contour.LatencyMinMsSlice(), []float32{0, 16, 16})
	assertSliceEqual("LatencyMax[1]", contour.LatencyMaxMsSlice(), []float32{0, 32, 32})
	assertSliceEqual("LatencyAvg[1]", contour.LatencyAverageMsSlice(), []float32{0, 24, 24})
	assertSliceEqual("BytesSent[1]", contour.BytesSentSlice(), []int64{0, 1, 1})
	assertSliceEqual("BytesReceived[1]", contour.BytesReceivedSlice(), []int64{0, 5, 0})

	// Adding data at 8s and 12s triggers another expansion.
	contour.AddUpdate(ssh.ContourUpdate{Time: 8000, BytesSent: 1})
	contour.AddUpdate(ssh.ContourUpdate{Time: 8100, Latency: 32})
	contour.AddUpdate(ssh.ContourUpdate{Time: 12000, BytesSent: 2})
	contour.AddUpdate(ssh.ContourUpdate{Time: 12500, Latency: 64})

	assertEqual("interval after expansion 2", contour.IntervalMs(), int64(4000))
	assertSliceEqual("LatencyMin[2]", contour.LatencyMinMsSlice(), []float32{16, 16, 32, 64})
	assertSliceEqual("LatencyMax[2]", contour.LatencyMaxMsSlice(), []float32{32, 32, 32, 64})
	assertSliceEqual("LatencyAvg[2]", contour.LatencyAverageMsSlice(), []float32{24, 24, 32, 64})
	assertSliceEqual("BytesSent[2]", contour.BytesSentSlice(), []int64{1, 1, 1, 2})
	assertSliceEqual("BytesReceived[2]", contour.BytesReceivedSlice(), []int64{5, 0, 0, 0})

	// Adding data at 16s triggers another expansion.
	contour.AddUpdate(ssh.ContourUpdate{Time: 16000, BytesSent: 10})

	assertEqual("interval after expansion 3", contour.IntervalMs(), int64(8000))
	assertSliceEqual("LatencyMin[3]", contour.LatencyMinMsSlice(), []float32{16, 32, 0})
	assertSliceEqual("LatencyMax[3]", contour.LatencyMaxMsSlice(), []float32{32, 64, 0})
	assertSliceEqual("LatencyAvg[3]", contour.LatencyAverageMsSlice(), []float32{24, 48, 0})
	assertSliceEqual("BytesSent[3]", contour.BytesSentSlice(), []int64{2, 3, 10})
	assertSliceEqual("BytesReceived[3]", contour.BytesReceivedSlice(), []int64{5, 0, 0})
}

func TestExportImportContour(t *testing.T) {
	contour := ssh.NewSessionContour(4)

	contour.AddUpdate(ssh.ContourUpdate{Time: 0, BytesReceived: 2000})
	contour.AddUpdate(ssh.ContourUpdate{Time: 2000, Latency: 16})
	contour.AddUpdate(ssh.ContourUpdate{Time: 3000, Latency: 32})
	contour.AddUpdate(ssh.ContourUpdate{Time: 3600, BytesSent: 1000})
	contour.AddUpdate(ssh.ContourUpdate{Time: 3800, BytesReceived: 3000})
	contour.AddUpdate(ssh.ContourUpdate{Time: 4000, BytesSent: 1})
	contour.AddUpdate(ssh.ContourUpdate{Time: 5000, Latency: 32})
	contour.AddUpdate(ssh.ContourUpdate{Time: 5200, Latency: 16})

	// After adding data at 4s, interval should have expanded from 1s to 2s.
	if got := contour.IntervalMs(); got != 2000 {
		t.Fatalf("interval = %d, want 2000", got)
	}

	result := contour.Export()
	resultBytes, err := base64.StdEncoding.DecodeString(result)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	// Verify the expected byte layout.
	expected := []byte{
		1,   // version
		5,   // metric count
		1,   // timeScale
		0,   // \
		0,   //  \
		0,   //   } value scales
		2,   //  /
		4,   // /
		1,   // \
		2,   //  \
		3,   //   } metric IDs
		11,  //  /
		12,  // /
		0,   // \
		0,   //  \
		0,   //   } interval 0
		0,   //  /
		125, // /
		16,  // \
		32,  //  \
		24,  //   } interval 1
		250, //  /
		188, // /
		16,  // \
		32,  //  \
		24,  //   } interval 2
		0,   //  /
		0,   // /
	}

	if len(resultBytes) != len(expected) {
		t.Fatalf("export length = %d, want %d", len(resultBytes), len(expected))
	}
	for i, b := range expected {
		if resultBytes[i] != b {
			t.Errorf("export byte[%d] = %d, want %d", i, resultBytes[i], b)
		}
	}

	// Import and verify round-trip.
	imported, err := ssh.ImportContour(result)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if imported.IntervalCount() != 3 {
		t.Errorf("imported IntervalCount = %d, want 3", imported.IntervalCount())
	}
	if imported.IntervalMs() != 2000 {
		t.Errorf("imported interval = %d, want 2000", imported.IntervalMs())
	}

	// Re-export and verify it matches.
	result2 := imported.Export()
	if result != result2 {
		t.Errorf("round-trip export mismatch:\n  first:  %s\n  second: %s", result, result2)
	}
}
