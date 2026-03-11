// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTraceFuncFiresDuringConnect verifies that setting Trace on a session produces
// trace events during the connection lifecycle (connecting, version exchange,
// key exchange, encryption).
func TestTraceFuncFiresDuringConnect(t *testing.T) {
	var mu sync.Mutex
	var events []traceEvent

	collector := func(level TraceLevel, eventID int, message string) {
		mu.Lock()
		events = append(events, traceEvent{level: level, eventID: eventID, message: message})
		mu.Unlock()
	}

	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cs, ss := createSessionPair(t, &SessionPairOptions{
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{serverKey}},
		ClientTrace:       collector,
		ServerTrace:       collector,
	})

	if !cs.IsConnected() || !ss.IsConnected() {
		t.Fatal("sessions not connected")
	}

	mu.Lock()
	defer mu.Unlock()

	// Verify we got at least a SessionConnecting event.
	found := false
	for _, e := range events {
		if e.eventID == TraceEventSessionConnecting {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TraceEventSessionConnecting event")
	}

	// Verify we got a ProtocolVersion event.
	found = false
	for _, e := range events {
		if e.eventID == TraceEventProtocolVersion {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TraceEventProtocolVersion event")
	}

	// Verify we got a SessionEncrypted event.
	found = false
	for _, e := range events {
		if e.eventID == TraceEventSessionEncrypted {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TraceEventSessionEncrypted event")
	}
}

// TestTraceFuncFiresDuringConnectNoSecurity verifies tracing works with no-security config.
func TestTraceFuncFiresDuringConnectNoSecurity(t *testing.T) {
	var mu sync.Mutex
	var events []traceEvent

	collector := func(level TraceLevel, eventID int, message string) {
		mu.Lock()
		events = append(events, traceEvent{level: level, eventID: eventID, message: message})
		mu.Unlock()
	}

	cs, ss := createSessionPair(t, &SessionPairOptions{
		ClientTrace: collector,
		ServerTrace: collector,
	})

	if !cs.IsConnected() || !ss.IsConnected() {
		t.Fatal("sessions not connected")
	}

	mu.Lock()
	defer mu.Unlock()

	found := false
	for _, e := range events {
		if e.eventID == TraceEventSessionConnecting {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TraceEventSessionConnecting event")
	}
}

// TestTraceFuncNilSafe verifies that a nil Trace callback doesn't panic.
func TestTraceFuncNilSafe(t *testing.T) {
	// Create sessions without setting Trace — should not panic.
	cs, ss := createSessionPair(t, nil)
	if !cs.IsConnected() || !ss.IsConnected() {
		t.Fatal("sessions not connected")
	}
}

// TestTraceChannelOpenClose verifies that channel open/close events are traced.
func TestTraceChannelOpenClose(t *testing.T) {
	var mu sync.Mutex
	var events []traceEvent

	collector := func(level TraceLevel, eventID int, message string) {
		mu.Lock()
		events = append(events, traceEvent{level: level, eventID: eventID, message: message})
		mu.Unlock()
	}

	cs, ss := createSessionPair(t, &SessionPairOptions{
		ClientTrace: collector,
		ServerTrace: collector,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Open a channel from client.
	ch, err := cs.Session.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("failed to open channel: %v", err)
	}

	// Accept on server.
	sCh, err := ss.Session.AcceptChannel(ctx)
	if err != nil {
		t.Fatalf("failed to accept channel: %v", err)
	}

	// Close channel.
	_ = ch.Close()
	// Wait for remote close to propagate.
	time.Sleep(50 * time.Millisecond)
	_ = sCh

	mu.Lock()
	defer mu.Unlock()

	// Verify channel opened events.
	openCount := 0
	for _, e := range events {
		if e.eventID == TraceEventChannelOpened {
			openCount++
		}
	}
	if openCount < 2 {
		t.Errorf("expected at least 2 TraceEventChannelOpened events (client+server), got %d", openCount)
	}

	// Verify channel closed event.
	closeCount := 0
	for _, e := range events {
		if e.eventID == TraceEventChannelClosed {
			closeCount++
		}
	}
	if closeCount < 1 {
		t.Errorf("expected at least 1 TraceEventChannelClosed event, got %d", closeCount)
	}
}

// TestTraceAuthEvents verifies that authentication events are traced.
func TestTraceAuthEvents(t *testing.T) {
	var mu sync.Mutex
	var events []traceEvent

	collector := func(level TraceLevel, eventID int, message string) {
		mu.Lock()
		events = append(events, traceEvent{level: level, eventID: eventID, message: message})
		mu.Unlock()
	}

	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cs, ss := createSessionPair(t, &SessionPairOptions{
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{serverKey}},
		ClientTrace:       collector,
		ServerTrace:       collector,
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = &struct{}{}
		},
	})

	if !cs.IsConnected() || !ss.IsConnected() {
		t.Fatal("sessions not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, authErr := cs.Authenticate(ctx, &ClientCredentials{Username: "testuser"})
	if authErr != nil {
		t.Fatalf("Authenticate error: %v", authErr)
	}
	if !ok {
		t.Fatal("expected authentication to succeed")
	}

	// Give the server side time to process the auth.
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Verify SessionAuthenticating event.
	found := false
	for _, e := range events {
		if e.eventID == TraceEventSessionAuthenticating {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TraceEventSessionAuthenticating event")
	}

	// Verify SessionAuthenticated event.
	found = false
	for _, e := range events {
		if e.eventID == TraceEventSessionAuthenticated {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TraceEventSessionAuthenticated event")
	}
}

// TestTraceSessionClose verifies that session close is traced.
func TestTraceSessionClose(t *testing.T) {
	var mu sync.Mutex
	var events []traceEvent

	collector := func(level TraceLevel, eventID int, message string) {
		mu.Lock()
		events = append(events, traceEvent{level: level, eventID: eventID, message: message})
		mu.Unlock()
	}

	cs, _ := createSessionPair(t, &SessionPairOptions{
		ClientTrace: collector,
	})

	_ = cs.Session.Close()
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	found := false
	for _, e := range events {
		if e.eventID == TraceEventSessionClosing {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected TraceEventSessionClosing event")
	}
}

// TestTraceMessageSendReceive verifies that message send/receive events are traced.
func TestTraceMessageSendReceive(t *testing.T) {
	var mu sync.Mutex
	var events []traceEvent

	collector := func(level TraceLevel, eventID int, message string) {
		mu.Lock()
		events = append(events, traceEvent{level: level, eventID: eventID, message: message})
		mu.Unlock()
	}

	cs, ss := createSessionPair(t, &SessionPairOptions{
		ClientTrace: collector,
		ServerTrace: collector,
	})

	if !cs.IsConnected() || !ss.IsConnected() {
		t.Fatal("sessions not connected")
	}

	mu.Lock()
	defer mu.Unlock()

	// There should be message send/receive events from the initial handshake.
	sendCount := 0
	recvCount := 0
	for _, e := range events {
		if e.eventID == TraceEventSendingMessage {
			sendCount++
		}
		if e.eventID == TraceEventReceivingMessage {
			recvCount++
		}
	}
	if sendCount == 0 {
		t.Error("expected at least one TraceEventSendingMessage event")
	}
	if recvCount == 0 {
		t.Error("expected at least one TraceEventReceivingMessage event")
	}
}

// TestTraceChannelDataNotTracedByDefault verifies that channel data is NOT traced
// when TraceChannelData is false (default).
func TestTraceChannelDataNotTracedByDefault(t *testing.T) {
	var mu sync.Mutex
	var events []traceEvent

	collector := func(level TraceLevel, eventID int, message string) {
		mu.Lock()
		events = append(events, traceEvent{level: level, eventID: eventID, message: message})
		mu.Unlock()
	}

	cs, ss := createSessionPair(t, &SessionPairOptions{
		ClientTrace: collector,
		ServerTrace: collector,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := cs.Session.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("failed to open channel: %v", err)
	}

	sCh, err := ss.Session.AcceptChannel(ctx)
	if err != nil {
		t.Fatalf("failed to accept channel: %v", err)
	}

	// Send data.
	data := []byte("hello trace test")
	if err := ch.Send(ctx, data); err != nil {
		t.Fatalf("failed to send: %v", err)
	}

	// Read on server side.
	stream := NewStream(sCh)
	buf := make([]byte, len(data))
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if string(buf[:n]) != string(data) {
		t.Fatalf("data mismatch: got %q, want %q", buf[:n], data)
	}

	mu.Lock()
	defer mu.Unlock()

	// Channel data events should NOT be present.
	for _, e := range events {
		if e.eventID == TraceEventSendingChannelData || e.eventID == TraceEventReceivingChannelData {
			t.Errorf("unexpected channel data trace event: %v", e)
		}
	}
}

// TestTraceChannelDataTracedWhenEnabled verifies that channel data IS traced
// when TraceChannelData is true.
func TestTraceChannelDataTracedWhenEnabled(t *testing.T) {
	var mu sync.Mutex
	var events []traceEvent

	collector := func(level TraceLevel, eventID int, message string) {
		mu.Lock()
		events = append(events, traceEvent{level: level, eventID: eventID, message: message})
		mu.Unlock()
	}

	clientConfig := NewNoSecurityConfig()
	clientConfig.TraceChannelData = true
	serverConfig := NewNoSecurityConfig()
	serverConfig.TraceChannelData = true

	cs, ss := createSessionPair(t, &SessionPairOptions{
		ClientConfig: clientConfig,
		ServerConfig: serverConfig,
		ClientTrace:  collector,
		ServerTrace:  collector,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := cs.Session.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("failed to open channel: %v", err)
	}

	sCh, err := ss.Session.AcceptChannel(ctx)
	if err != nil {
		t.Fatalf("failed to accept channel: %v", err)
	}

	// Send data.
	data := []byte("hello channel data trace")
	if err := ch.Send(ctx, data); err != nil {
		t.Fatalf("failed to send: %v", err)
	}

	// Read on server side.
	stream := NewStream(sCh)
	buf := make([]byte, len(data))
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if string(buf[:n]) != string(data) {
		t.Fatalf("data mismatch: got %q, want %q", buf[:n], data)
	}

	mu.Lock()
	defer mu.Unlock()

	// Channel data events SHOULD be present.
	foundSend := false
	foundRecv := false
	for _, e := range events {
		if e.eventID == TraceEventSendingChannelData {
			foundSend = true
		}
		if e.eventID == TraceEventReceivingChannelData {
			foundRecv = true
		}
	}
	if !foundSend {
		t.Error("expected TraceEventSendingChannelData event when TraceChannelData=true")
	}
	if !foundRecv {
		t.Error("expected TraceEventReceivingChannelData event when TraceChannelData=true")
	}
}

// TestTraceAlgorithmNegotiation verifies that algorithm negotiation is traced.
func TestTraceAlgorithmNegotiation(t *testing.T) {
	var mu sync.Mutex
	var events []traceEvent

	collector := func(level TraceLevel, eventID int, message string) {
		mu.Lock()
		events = append(events, traceEvent{level: level, eventID: eventID, message: message})
		mu.Unlock()
	}

	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	cs, ss := createSessionPair(t, &SessionPairOptions{
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{serverKey}},
		ClientTrace:       collector,
		ServerTrace:       collector,
	})

	if !cs.IsConnected() || !ss.IsConnected() {
		t.Fatal("sessions not connected")
	}

	mu.Lock()
	defer mu.Unlock()

	found := false
	for _, e := range events {
		if e.eventID == TraceEventAlgorithmNegotiation {
			found = true
			if !strings.Contains(e.message, "kex=") {
				t.Errorf("expected algorithm negotiation message to contain 'kex=', got: %s", e.message)
			}
			break
		}
	}
	if !found {
		t.Error("expected TraceEventAlgorithmNegotiation event")
	}
}

// TestSetTraceHandler verifies thread-safe setter works.
func TestSetTraceHandler(t *testing.T) {
	cs, _ := createSessionPair(t, nil)

	called := false
	cs.Session.SetTraceHandler(func(level TraceLevel, eventID int, message string) {
		called = true
	})

	// Verify the handler was set by calling trace directly.
	cs.Session.trace(TraceLevelInfo, TraceEventSessionConnecting, "test")
	if !called {
		t.Error("expected trace handler to be called after SetTraceHandler")
	}
}

// TestTraceLevelString verifies TraceLevel String() method.
func TestTraceLevelString(t *testing.T) {
	tests := []struct {
		level TraceLevel
		want  string
	}{
		{TraceLevelError, "error"},
		{TraceLevelWarning, "warning"},
		{TraceLevelInfo, "info"},
		{TraceLevelVerbose, "verbose"},
		{TraceLevel(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.level.String()
		if got != tt.want {
			t.Errorf("TraceLevel(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

// TestTraceEventIDsAreDistinct verifies that all event ID constants are unique.
func TestTraceEventIDsAreDistinct(t *testing.T) {
	ids := []int{
		TraceEventUnknownError, TraceEventStreamReadError, TraceEventStreamWriteError,
		TraceEventStreamCloseError, TraceEventSendMessageFailed, TraceEventReceiveMessageFailed,
		TraceEventHandleMessageFailed, TraceEventServerAuthenticationFailed,
		TraceEventClientAuthenticationFailed, TraceEventAuthenticationError,
		TraceEventChannelWindowAdjustFailed, TraceEventSessionReconnectInitFailed,
		TraceEventServerSessionReconnectFailed, TraceEventClientSessionReconnectFailed,
		TraceEventSessionRequestFailed, TraceEventChannelRequestFailed,
		TraceEventChannelCloseFailed, TraceEventKeepAliveFailed,
		TraceEventKeepAliveResponseNotReceived,
		TraceEventProtocolVersion, TraceEventSendingMessage, TraceEventReceivingMessage,
		TraceEventSendingChannelData, TraceEventReceivingChannelData,
		TraceEventSessionEncrypted, TraceEventSessionAuthenticating,
		TraceEventSessionAuthenticated, TraceEventSessionClosing,
		TraceEventSessionConnecting, TraceEventChannelOpened, TraceEventChannelOpenFailed,
		TraceEventChannelClosed, TraceEventSessionDisconnected,
		TraceEventClientSessionReconnecting, TraceEventServerSessionReconnecting,
		TraceEventAlgorithmNegotiation,
	}

	seen := make(map[int]bool)
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate event ID: %d", id)
		}
		seen[id] = true
	}
}

// traceEvent is a captured trace event for testing.
type traceEvent struct {
	level   TraceLevel
	eventID int
	message string
}

func (e traceEvent) String() string {
	return fmt.Sprintf("{%s %d %q}", e.level, e.eventID, e.message)
}
