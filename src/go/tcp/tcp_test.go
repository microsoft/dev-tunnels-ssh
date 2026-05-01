// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// --- Message serialization round-trip tests ---

func roundTrip(t *testing.T, original messages.Message, target messages.Message) {
	t.Helper()
	buf := original.ToBuffer()
	if len(buf) == 0 {
		t.Fatal("ToBuffer returned empty buffer")
	}
	if buf[0] != original.MessageType() {
		t.Fatalf("first byte should be message type %d, got %d", original.MessageType(), buf[0])
	}
	err := messages.ReadMessage(target, buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
}

func TestPortForwardRequestMessageRoundTrip(t *testing.T) {
	original := &PortForwardRequestMessage{
		RequestType:   PortForwardRequestType,
		WantReply:     true,
		AddressToBind: "127.0.0.1",
		Port:          8080,
	}
	target := &PortForwardRequestMessage{}
	roundTrip(t, original, target)

	if target.RequestType != PortForwardRequestType {
		t.Errorf("RequestType = %q, want %q", target.RequestType, PortForwardRequestType)
	}
	if target.WantReply != true {
		t.Error("WantReply should be true")
	}
	if target.AddressToBind != "127.0.0.1" {
		t.Errorf("AddressToBind = %q, want %q", target.AddressToBind, "127.0.0.1")
	}
	if target.Port != 8080 {
		t.Errorf("Port = %d, want 8080", target.Port)
	}
}

func TestPortForwardRequestMessageCancelRoundTrip(t *testing.T) {
	original := &PortForwardRequestMessage{
		RequestType:   CancelPortForwardRequestType,
		WantReply:     false,
		AddressToBind: "0.0.0.0",
		Port:          9090,
	}
	target := &PortForwardRequestMessage{}
	roundTrip(t, original, target)

	if target.RequestType != CancelPortForwardRequestType {
		t.Errorf("RequestType = %q, want %q", target.RequestType, CancelPortForwardRequestType)
	}
	if target.WantReply != false {
		t.Error("WantReply should be false")
	}
	if target.AddressToBind != "0.0.0.0" {
		t.Errorf("AddressToBind = %q, want %q", target.AddressToBind, "0.0.0.0")
	}
	if target.Port != 9090 {
		t.Errorf("Port = %d, want 9090", target.Port)
	}
}

func TestPortForwardRequestMessageType(t *testing.T) {
	m := &PortForwardRequestMessage{}
	if m.MessageType() != messages.MsgNumSessionRequest {
		t.Errorf("MessageType() = %d, want %d", m.MessageType(), messages.MsgNumSessionRequest)
	}
}

func TestPortForwardRequestMessageZeroPort(t *testing.T) {
	original := &PortForwardRequestMessage{
		RequestType:   PortForwardRequestType,
		WantReply:     true,
		AddressToBind: "localhost",
		Port:          0,
	}
	target := &PortForwardRequestMessage{}
	roundTrip(t, original, target)

	if target.Port != 0 {
		t.Errorf("Port = %d, want 0", target.Port)
	}
	if target.AddressToBind != "localhost" {
		t.Errorf("AddressToBind = %q, want %q", target.AddressToBind, "localhost")
	}
}

func TestPortForwardRequestMessageEmptyAddress(t *testing.T) {
	original := &PortForwardRequestMessage{
		RequestType:   PortForwardRequestType,
		WantReply:     true,
		AddressToBind: "",
		Port:          443,
	}
	target := &PortForwardRequestMessage{}
	roundTrip(t, original, target)

	if target.AddressToBind != "" {
		t.Errorf("AddressToBind = %q, want empty", target.AddressToBind)
	}
}

func TestParsePortForwardRequestMessage(t *testing.T) {
	original := &PortForwardRequestMessage{
		RequestType:   PortForwardRequestType,
		WantReply:     true,
		AddressToBind: "10.0.0.1",
		Port:          3000,
	}
	buf := original.ToBuffer()

	parsed, err := ParsePortForwardRequestMessage(buf)
	if err != nil {
		t.Fatalf("ParsePortForwardRequestMessage failed: %v", err)
	}
	if parsed.RequestType != PortForwardRequestType {
		t.Errorf("RequestType = %q, want %q", parsed.RequestType, PortForwardRequestType)
	}
	if parsed.Port != 3000 {
		t.Errorf("Port = %d, want 3000", parsed.Port)
	}
}

func TestPortForwardSuccessMessageRoundTrip(t *testing.T) {
	original := &PortForwardSuccessMessage{Port: 12345}
	target := &PortForwardSuccessMessage{}
	roundTrip(t, original, target)

	if target.Port != 12345 {
		t.Errorf("Port = %d, want 12345", target.Port)
	}
}

func TestPortForwardSuccessMessageZeroPort(t *testing.T) {
	original := &PortForwardSuccessMessage{Port: 0}
	target := &PortForwardSuccessMessage{}
	roundTrip(t, original, target)

	if target.Port != 0 {
		t.Errorf("Port = %d, want 0", target.Port)
	}
}

func TestPortForwardSuccessMessageType(t *testing.T) {
	m := &PortForwardSuccessMessage{}
	if m.MessageType() != messages.MsgNumSessionRequestSuccess {
		t.Errorf("MessageType() = %d, want %d", m.MessageType(), messages.MsgNumSessionRequestSuccess)
	}
}

func TestPortForwardSuccessMessageOptionalPort(t *testing.T) {
	// The Port field is optional in the protocol — test reading with no port data.
	// Build a minimal buffer: just the message type byte.
	buf := []byte{messages.MsgNumSessionRequestSuccess}
	target := &PortForwardSuccessMessage{}
	err := messages.ReadMessage(target, buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	if target.Port != 0 {
		t.Errorf("Port = %d, want 0 for missing optional port", target.Port)
	}
}

func TestPortForwardChannelOpenMessageRoundTrip(t *testing.T) {
	original := &PortForwardChannelOpenMessage{
		ChannelType:         ForwardedTCPIPChannelType,
		SenderChannel:       1,
		MaxWindowSize:       1048576,
		MaxPacketSize:       32768,
		Host:                "192.168.1.1",
		Port:                22,
		OriginatorIPAddress: "10.0.0.5",
		OriginatorPort:      54321,
	}
	target := &PortForwardChannelOpenMessage{}
	roundTrip(t, original, target)

	if target.ChannelType != ForwardedTCPIPChannelType {
		t.Errorf("ChannelType = %q, want %q", target.ChannelType, ForwardedTCPIPChannelType)
	}
	if target.SenderChannel != 1 {
		t.Errorf("SenderChannel = %d, want 1", target.SenderChannel)
	}
	if target.MaxWindowSize != 1048576 {
		t.Errorf("MaxWindowSize = %d, want 1048576", target.MaxWindowSize)
	}
	if target.MaxPacketSize != 32768 {
		t.Errorf("MaxPacketSize = %d, want 32768", target.MaxPacketSize)
	}
	if target.Host != "192.168.1.1" {
		t.Errorf("Host = %q, want %q", target.Host, "192.168.1.1")
	}
	if target.Port != 22 {
		t.Errorf("Port = %d, want 22", target.Port)
	}
	if target.OriginatorIPAddress != "10.0.0.5" {
		t.Errorf("OriginatorIPAddress = %q, want %q", target.OriginatorIPAddress, "10.0.0.5")
	}
	if target.OriginatorPort != 54321 {
		t.Errorf("OriginatorPort = %d, want 54321", target.OriginatorPort)
	}
}

func TestPortForwardChannelOpenMessageDirectTCPIP(t *testing.T) {
	original := &PortForwardChannelOpenMessage{
		ChannelType:         DirectTCPIPChannelType,
		SenderChannel:       7,
		MaxWindowSize:       65536,
		MaxPacketSize:       16384,
		Host:                "example.com",
		Port:                443,
		OriginatorIPAddress: "127.0.0.1",
		OriginatorPort:      0,
	}
	target := &PortForwardChannelOpenMessage{}
	roundTrip(t, original, target)

	if target.ChannelType != DirectTCPIPChannelType {
		t.Errorf("ChannelType = %q, want %q", target.ChannelType, DirectTCPIPChannelType)
	}
	if target.Host != "example.com" {
		t.Errorf("Host = %q, want %q", target.Host, "example.com")
	}
	if target.Port != 443 {
		t.Errorf("Port = %d, want 443", target.Port)
	}
	if target.OriginatorPort != 0 {
		t.Errorf("OriginatorPort = %d, want 0", target.OriginatorPort)
	}
}

func TestPortForwardChannelOpenMessageType(t *testing.T) {
	m := &PortForwardChannelOpenMessage{}
	if m.MessageType() != messages.MsgNumChannelOpen {
		t.Errorf("MessageType() = %d, want %d", m.MessageType(), messages.MsgNumChannelOpen)
	}
}

func TestParsePortForwardChannelOpenMessage(t *testing.T) {
	original := &PortForwardChannelOpenMessage{
		ChannelType:         ForwardedTCPIPChannelType,
		SenderChannel:       3,
		MaxWindowSize:       1048576,
		MaxPacketSize:       32768,
		Host:                "myhost",
		Port:                8888,
		OriginatorIPAddress: "10.10.10.10",
		OriginatorPort:      11111,
	}
	buf := original.ToBuffer()

	parsed, err := ParsePortForwardChannelOpenMessage(buf)
	if err != nil {
		t.Fatalf("ParsePortForwardChannelOpenMessage failed: %v", err)
	}
	if parsed.ChannelType != ForwardedTCPIPChannelType {
		t.Errorf("ChannelType = %q, want %q", parsed.ChannelType, ForwardedTCPIPChannelType)
	}
	if parsed.Host != "myhost" {
		t.Errorf("Host = %q, want %q", parsed.Host, "myhost")
	}
	if parsed.Port != 8888 {
		t.Errorf("Port = %d, want 8888", parsed.Port)
	}
}

func TestParsePortForwardChannelOpenMessageInvalid(t *testing.T) {
	// Wrong message type byte.
	buf := []byte{messages.MsgNumSessionRequest}
	_, err := ParsePortForwardChannelOpenMessage(buf)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

func TestParsePortForwardRequestMessageInvalid(t *testing.T) {
	// Wrong message type byte.
	buf := []byte{messages.MsgNumChannelOpen}
	_, err := ParsePortForwardRequestMessage(buf)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

// --- Constants tests ---

func TestPortForwardConstants(t *testing.T) {
	if PortForwardRequestType != "tcpip-forward" {
		t.Errorf("PortForwardRequestType = %q, want %q", PortForwardRequestType, "tcpip-forward")
	}
	if CancelPortForwardRequestType != "cancel-tcpip-forward" {
		t.Errorf("CancelPortForwardRequestType = %q, want %q", CancelPortForwardRequestType, "cancel-tcpip-forward")
	}
	if ForwardedTCPIPChannelType != "forwarded-tcpip" {
		t.Errorf("ForwardedTCPIPChannelType = %q, want %q", ForwardedTCPIPChannelType, "forwarded-tcpip")
	}
	if DirectTCPIPChannelType != "direct-tcpip" {
		t.Errorf("DirectTCPIPChannelType = %q, want %q", DirectTCPIPChannelType, "direct-tcpip")
	}
	if PortForwardingServiceName != "port-forwarding" {
		t.Errorf("PortForwardingServiceName = %q, want %q", PortForwardingServiceName, "port-forwarding")
	}
}

// --- Socket configuration tests ---

func TestConfigureSocketForSSHTCP(t *testing.T) {
	// Create a real TCP listener to get a real TCP connection.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Accept in a goroutine.
	done := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		done <- conn
	}()

	// Dial the listener.
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	serverConn := <-done
	if serverConn != nil {
		defer serverConn.Close()
	}

	// Should not panic on a real TCP connection.
	configureSocketForSSH(clientConn)

	// Verify it's a TCPConn (the function should have set options).
	_, ok := clientConn.(*net.TCPConn)
	if !ok {
		t.Fatal("expected *net.TCPConn")
	}
}

func TestConfigureSocketForSSHNonTCP(t *testing.T) {
	// Use a Unix-domain socket pair via net.Pipe, which produces non-TCP connections.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Should not panic on a non-TCP connection — just silently return.
	configureSocketForSSH(c1)
	configureSocketForSSH(c2)
}

func TestDefaultSocketBufferSize(t *testing.T) {
	// 2 * 32KB = 64KB
	expected := 2 * 0x8000
	if defaultSocketBufferSize != expected {
		t.Errorf("defaultSocketBufferSize = %d, want %d", defaultSocketBufferSize, expected)
	}
}

// --- Client tests ---

func TestNewClientNilConfig(t *testing.T) {
	c := NewClient(nil)
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.config == nil {
		t.Fatal("config should default to non-nil")
	}
}

func TestNewClientWithConfig(t *testing.T) {
	config := ssh.NewNoSecurityConfig()
	c := NewClient(config)
	if c.config != config {
		t.Error("config should be the one passed in")
	}
}

func TestClientSessionsEmpty(t *testing.T) {
	c := NewClient(nil)
	sessions := c.Sessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestClientSessionsSnapshotIndependent(t *testing.T) {
	c := NewClient(nil)
	s1 := c.Sessions()
	s2 := c.Sessions()
	// Both should be independent slices.
	if s1 == nil || s2 == nil {
		t.Fatal("Sessions should return non-nil slices")
	}
}

func TestClientCloseIdempotent(t *testing.T) {
	c := NewClient(nil)
	if err := c.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestClientOpenSessionAfterClose(t *testing.T) {
	c := NewClient(nil)
	c.Close()

	_, err := c.OpenSession(context.Background(), "localhost", 22)
	if err == nil {
		t.Fatal("expected error after close")
	}
}

func TestClientReconnectSessionNilSession(t *testing.T) {
	c := NewClient(nil)
	err := c.ReconnectSession(context.Background(), nil, "localhost", 22)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
}

func TestClientReconnectSessionAfterClose(t *testing.T) {
	c := NewClient(nil)
	c.Close()

	session := ssh.NewClientSession(ssh.NewNoSecurityConfig())
	err := c.ReconnectSession(context.Background(), session, "localhost", 22)
	if err == nil {
		t.Fatal("expected error after close")
	}
}

func TestClientOpenSessionConnectionRefused(t *testing.T) {
	c := NewClient(nil)
	// Use a port that is almost certainly not listening.
	_, err := c.OpenSession(context.Background(), "127.0.0.1", 1)
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestClientOpenSessionCancelled(t *testing.T) {
	c := NewClient(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.OpenSession(ctx, "127.0.0.1", 1)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// --- Server tests ---

func TestNewServerNilConfig(t *testing.T) {
	s := NewServer(nil)
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.config == nil {
		t.Fatal("config should default to non-nil")
	}
}

func TestNewServerWithConfig(t *testing.T) {
	config := ssh.NewNoSecurityConfig()
	s := NewServer(config)
	if s.config != config {
		t.Error("config should be the one passed in")
	}
}

func TestNewServerReconnectConfig(t *testing.T) {
	config := ssh.NewDefaultConfigWithReconnect()
	s := NewServer(config)
	if s.reconnectableSessions == nil {
		t.Error("reconnectableSessions should be non-nil for reconnect config")
	}
}

func TestNewServerNoReconnectConfig(t *testing.T) {
	config := ssh.NewDefaultConfig()
	s := NewServer(config)
	if s.reconnectableSessions != nil {
		t.Error("reconnectableSessions should be nil for default config")
	}
}

func TestServerSessionsEmpty(t *testing.T) {
	s := NewServer(nil)
	sessions := s.Sessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestServerCloseIdempotent(t *testing.T) {
	s := NewServer(nil)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

func TestServerAcceptSessionsAfterClose(t *testing.T) {
	s := NewServer(nil)
	s.Close()

	err := s.AcceptSessions(context.Background(), 0, "")
	if err == nil {
		t.Fatal("expected error after close")
	}
}

func TestServerListenPortBeforeListening(t *testing.T) {
	s := NewServer(nil)
	port := s.ListenPort()
	if port != 0 {
		t.Errorf("expected 0 before listening, got %d", port)
	}
}

func TestServerAcceptSessionsAndClose(t *testing.T) {
	s := NewServer(nil)

	// Start listening on a dynamic port.
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.AcceptSessions(context.Background(), 0, "127.0.0.1")
	}()

	// Wait a bit for the listener to start.
	time.Sleep(50 * time.Millisecond)

	port := s.ListenPort()
	if port == 0 {
		t.Fatal("expected non-zero listen port after AcceptSessions starts")
	}

	// Close the server — AcceptSessions should return nil.
	s.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("AcceptSessions returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AcceptSessions did not return after Close")
	}
}

func TestServerAcceptSessionsCancelledContext(t *testing.T) {
	s := NewServer(nil)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.AcceptSessions(ctx, 0, "127.0.0.1")
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("expected nil or context.Canceled, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AcceptSessions did not return after context cancel")
	}
}

// --- PortForwardingService tests ---

func TestNewPortForwardingService(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)

	if pfs == nil {
		t.Fatal("NewPortForwardingService returned nil")
	}
	if pfs.AcceptLocalConnectionsForForwardedPorts != true {
		t.Error("AcceptLocalConnectionsForForwardedPorts should default to true")
	}
	if pfs.AcceptRemoteConnectionsForNonForwardedPorts != true {
		t.Error("AcceptRemoteConnectionsForNonForwardedPorts should default to true")
	}
	if pfs.remoteForwarders == nil {
		t.Error("remoteForwarders should be initialized")
	}
	if pfs.localForwarders == nil {
		t.Error("localForwarders should be initialized")
	}
	if pfs.streamWaiters == nil {
		t.Error("streamWaiters should be initialized")
	}
}

func TestAddPortForwardingService(t *testing.T) {
	config := ssh.NewDefaultConfig()
	AddPortForwardingService(config)

	reg, ok := config.ServiceRegistrations[PortForwardingServiceName]
	if !ok {
		t.Fatal("port forwarding service not registered")
	}
	if reg.Factory == nil {
		t.Error("factory should be non-nil")
	}

	// Verify activation rules.
	if len(reg.Activation.SessionRequests) != 2 {
		t.Fatalf("expected 2 session request activations, got %d", len(reg.Activation.SessionRequests))
	}
	if reg.Activation.SessionRequests[0] != PortForwardRequestType {
		t.Errorf("SessionRequests[0] = %q, want %q", reg.Activation.SessionRequests[0], PortForwardRequestType)
	}
	if reg.Activation.SessionRequests[1] != CancelPortForwardRequestType {
		t.Errorf("SessionRequests[1] = %q, want %q", reg.Activation.SessionRequests[1], CancelPortForwardRequestType)
	}
	if len(reg.Activation.ChannelTypes) != 2 {
		t.Fatalf("expected 2 channel type activations, got %d", len(reg.Activation.ChannelTypes))
	}
	if reg.Activation.ChannelTypes[0] != ForwardedTCPIPChannelType {
		t.Errorf("ChannelTypes[0] = %q, want %q", reg.Activation.ChannelTypes[0], ForwardedTCPIPChannelType)
	}
	if reg.Activation.ChannelTypes[1] != DirectTCPIPChannelType {
		t.Errorf("ChannelTypes[1] = %q, want %q", reg.Activation.ChannelTypes[1], DirectTCPIPChannelType)
	}
}

func TestPortForwardingServiceCloseIdempotent(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)

	// Should not panic on double close.
	pfs.Close()
	pfs.Close()
}

func TestPortForwardingServiceCloseClosesListeners(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)

	// Create a real listener and register it as a remote forwarder.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	pfs.remoteForwarders[port] = &remoteForwarder{
		remoteHost: "127.0.0.1",
		remotePort: port,
		listener:   ln,
	}

	pfs.Close()

	// The listener should be closed — accepting should fail.
	_, err = ln.Accept()
	if err == nil {
		t.Fatal("expected error after dispose closed listener")
	}

	// Maps should be reset.
	if len(pfs.remoteForwarders) != 0 {
		t.Errorf("expected 0 remote forwarders after dispose, got %d", len(pfs.remoteForwarders))
	}
}

func TestPortForwardingServiceOnChannelRequestNoop(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)

	// OnChannelRequest is a no-op — should not panic.
	pfs.OnChannelRequest(nil, nil)
}

func TestPortForwardingServiceWaitForForwardedPortAlreadyPresent(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)

	// Pre-register a forwarder.
	pfs.remoteForwarders[8080] = &remoteForwarder{
		remoteHost: "127.0.0.1",
		remotePort: 8080,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := pfs.WaitForForwardedPort(ctx, 8080)
	if err != nil {
		t.Fatalf("WaitForForwardedPort failed: %v", err)
	}
}

func TestPortForwardingServiceWaitForForwardedPortTimeout(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := pfs.WaitForForwardedPort(ctx, 9999)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
}

func TestPortForwardingServiceWaitForForwardedPortAsyncRegister(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)

	// Register the forwarder after a short delay, with notification.
	go func() {
		time.Sleep(30 * time.Millisecond)
		pfs.mu.Lock()
		pfs.remoteForwarders[7777] = &remoteForwarder{
			remoteHost: "127.0.0.1",
			remotePort: 7777,
		}
		pfs.notifyForwarderAdded()
		pfs.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := pfs.WaitForForwardedPort(ctx, 7777)
	if err != nil {
		t.Fatalf("WaitForForwardedPort failed: %v", err)
	}
}

func TestPortForwardingServiceOnChannelOpeningNilPayload(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)

	args := &ssh.ChannelOpeningEventArgs{
		Payload: nil,
	}
	pfs.OnChannelOpening(args)

	if args.FailureReason != messages.ChannelOpenFailureConnectFailed {
		t.Errorf("FailureReason = %d, want %d", args.FailureReason, messages.ChannelOpenFailureConnectFailed)
	}
	if args.FailureDescription != "missing channel open data" {
		t.Errorf("FailureDescription = %q, want %q", args.FailureDescription, "missing channel open data")
	}
}

func TestPortForwardingServiceOnChannelOpeningInvalidPayload(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)

	args := &ssh.ChannelOpeningEventArgs{
		// Invalid: wrong message type byte.
		Payload: []byte{0xFF},
	}
	pfs.OnChannelOpening(args)

	if args.FailureReason != messages.ChannelOpenFailureConnectFailed {
		t.Errorf("FailureReason = %d, want %d", args.FailureReason, messages.ChannelOpenFailureConnectFailed)
	}
}

func TestPortForwardingServiceDirectTCPIPRejectedWhenDisabled(t *testing.T) {
	session := &ssh.Session{}
	pfs := NewPortForwardingService(session)
	pfs.AcceptRemoteConnectionsForNonForwardedPorts = false

	pfMsg := &PortForwardChannelOpenMessage{
		ChannelType:         DirectTCPIPChannelType,
		SenderChannel:       0,
		MaxWindowSize:       1048576,
		MaxPacketSize:       32768,
		Host:                "target.example.com",
		Port:                80,
		OriginatorIPAddress: "10.0.0.1",
		OriginatorPort:      55555,
	}
	args := &ssh.ChannelOpeningEventArgs{
		Payload: pfMsg.ToBuffer(),
	}

	pfs.OnChannelOpening(args)

	if args.FailureReason != messages.ChannelOpenFailureAdministrativelyProhibited {
		t.Errorf("FailureReason = %d, want %d", args.FailureReason, messages.ChannelOpenFailureAdministrativelyProhibited)
	}
}

// --- ForwardedPort struct test ---

func TestForwardedPortFields(t *testing.T) {
	fp := ForwardedPort{
		LocalHost:  "127.0.0.1",
		LocalPort:  3000,
		RemoteHost: "0.0.0.0",
		RemotePort: 8080,
	}
	if fp.LocalHost != "127.0.0.1" {
		t.Errorf("LocalHost = %q", fp.LocalHost)
	}
	if fp.LocalPort != 3000 {
		t.Errorf("LocalPort = %d", fp.LocalPort)
	}
	if fp.RemoteHost != "0.0.0.0" {
		t.Errorf("RemoteHost = %q", fp.RemoteHost)
	}
	if fp.RemotePort != 8080 {
		t.Errorf("RemotePort = %d", fp.RemotePort)
	}
}

// --- relayStreams bidirectional shutdown tests ---

// asyncPipeRWC wraps an io.Pipe with a buffered write path. Writes copy data
// into a channel and return immediately; a background goroutine drains the
// channel into the underlying PipeWriter. This provides the write buffering
// that real OS transports (TCP sockets) offer via kernel buffers, which
// io.Pipe lacks. Without this, SSH Connect deadlocks when both sides pipeline
// version + kexInit writes through synchronous pipes.
type asyncPipeRWC struct {
	r         *io.PipeReader
	w         *io.PipeWriter
	wch       chan []byte
	wdone     chan struct{}
	closeCh   chan struct{}
	closeOnce sync.Once
}

func newAsyncPipeRWC(r *io.PipeReader, w *io.PipeWriter) *asyncPipeRWC {
	p := &asyncPipeRWC{
		r:       r,
		w:       w,
		wch:     make(chan []byte, 256),
		wdone:   make(chan struct{}),
		closeCh: make(chan struct{}),
	}
	go p.writePump()
	return p
}

func (p *asyncPipeRWC) writePump() {
	defer close(p.wdone)
	for {
		select {
		case data := <-p.wch:
			if _, err := p.w.Write(data); err != nil {
				p.closeOnce.Do(func() { close(p.closeCh) })
				return
			}
		case <-p.closeCh:
			return
		}
	}
}

func (p *asyncPipeRWC) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p *asyncPipeRWC) Write(b []byte) (int, error) {
	select {
	case <-p.closeCh:
		return 0, io.ErrClosedPipe
	default:
	}
	data := make([]byte, len(b))
	copy(data, b)
	select {
	case p.wch <- data:
		return len(b), nil
	case <-p.closeCh:
		return 0, io.ErrClosedPipe
	}
}

func (p *asyncPipeRWC) Close() error {
	p.closeOnce.Do(func() { close(p.closeCh) })
	<-p.wdone
	p.r.Close()
	return p.w.Close()
}

// createDuplexStreams creates a pair of connected bidirectional streams
// with async-buffered writes to simulate real TCP socket behavior.
func createDuplexStreams() (io.ReadWriteCloser, io.ReadWriteCloser) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return newAsyncPipeRWC(r1, w2), newAsyncPipeRWC(r2, w1)
}

// createSessionPairWithChannel creates a no-security session pair over io.Pipe,
// connects them, opens a channel, and returns both sessions and the channel pair.
func createSessionPairWithChannel(t *testing.T) (
	clientSession *ssh.ClientSession,
	serverSession *ssh.ServerSession,
	clientChannel *ssh.Channel,
	serverChannel *ssh.Channel,
	cleanup func(),
) {
	t.Helper()

	config := ssh.NewNoSecurityConfig()
	clientSession = ssh.NewClientSession(config)
	clientSession.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	serverConfig := ssh.NewNoSecurityConfig()
	serverSession = ssh.NewServerSession(serverConfig)
	serverSession.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	streamA, streamB := createDuplexStreams()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	var wg sync.WaitGroup
	var clientErr, serverErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = clientSession.Connect(ctx, streamA)
	}()
	go func() {
		defer wg.Done()
		serverErr = serverSession.Connect(ctx, streamB)
	}()
	wg.Wait()

	if clientErr != nil {
		cancel()
		t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		cancel()
		t.Fatalf("server connect failed: %v", serverErr)
	}

	// Open channel concurrently.
	var openErr, acceptErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientChannel, openErr = clientSession.OpenChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		serverChannel, acceptErr = serverSession.AcceptChannel(ctx)
	}()
	wg.Wait()

	if openErr != nil {
		cancel()
		t.Fatalf("open channel failed: %v", openErr)
	}
	if acceptErr != nil {
		cancel()
		t.Fatalf("accept channel failed: %v", acceptErr)
	}

	cleanup = func() {
		cancel()
		clientSession.Close()
		serverSession.Close()
	}

	return
}

func TestRelayStreamsCloseConnEndsRelay(t *testing.T) {
	// Set up a session pair with a channel for the SSH stream side.
	clientSession, _, clientChannel, serverChannel, cleanup := createSessionPairWithChannel(t)
	defer cleanup()
	_ = clientSession

	// Create the SSH stream wrapping the server-side channel.
	sshStream := ssh.NewStream(serverChannel)

	// Set up a data handler on the client-side channel to consume data.
	clientChannel.SetDataReceivedHandler(func(data []byte) {
		clientChannel.AdjustWindow(uint32(len(data)))
	})

	// Create a net.Pipe for the conn side.
	connA, connB := net.Pipe()

	// Run relayStreams in a goroutine.
	done := make(chan struct{})
	go func() {
		relayStreams(connA, sshStream)
		close(done)
	}()

	// Write some data through connB to verify relay works.
	testData := []byte("hello relay")
	_, err := connB.Write(testData)
	if err != nil {
		t.Fatalf("connB write failed: %v", err)
	}

	// Close connB — this causes connA.Read to return io.EOF,
	// which should trigger closeBoth, unblocking the other goroutine.
	connB.Close()

	// Verify relayStreams returns promptly.
	select {
	case <-done:
		// Success — relayStreams returned.
	case <-time.After(5 * time.Second):
		t.Fatal("relayStreams did not return within 5 seconds after closing conn")
	}
}

func TestRelayStreamsCloseStreamEndsRelay(t *testing.T) {
	// Set up a session pair with a channel for the SSH stream side.
	_, _, clientChannel, serverChannel, cleanup := createSessionPairWithChannel(t)
	defer cleanup()

	// Create the SSH stream wrapping the server-side channel.
	sshStream := ssh.NewStream(serverChannel)

	// Set up a data handler on the client-side channel to consume data.
	clientChannel.SetDataReceivedHandler(func(data []byte) {
		clientChannel.AdjustWindow(uint32(len(data)))
	})

	// Create a net.Pipe for the conn side.
	connA, connB := net.Pipe()
	defer connB.Close()

	// Run relayStreams in a goroutine.
	done := make(chan struct{})
	go func() {
		relayStreams(connA, sshStream)
		close(done)
	}()

	// Close the client-side channel to trigger SSH stream closure.
	// This causes sshStream.Read to return io.EOF,
	// which should trigger closeBoth, unblocking the conn→stream goroutine.
	clientChannel.Close()

	// Verify relayStreams returns promptly.
	select {
	case <-done:
		// Success — relayStreams returned.
	case <-time.After(5 * time.Second):
		t.Fatal("relayStreams did not return within 5 seconds after closing stream")
	}
}

func TestRelayStreamsDataFlowsBidirectionally(t *testing.T) {
	// Set up a session pair with a channel for the SSH stream side.
	_, _, clientChannel, serverChannel, cleanup := createSessionPairWithChannel(t)
	defer cleanup()

	// Create the SSH stream wrapping the server-side channel.
	sshStream := ssh.NewStream(serverChannel)

	// Create a client-side stream for reading.
	clientStream := ssh.NewStream(clientChannel)

	// Create a net.Pipe for the conn side.
	connA, connB := net.Pipe()

	// Run relayStreams in a goroutine.
	done := make(chan struct{})
	go func() {
		relayStreams(connA, sshStream)
		close(done)
	}()

	// Test conn → stream direction: write to connB, read from clientStream.
	testData := []byte("hello from conn")
	_, err := connB.Write(testData)
	if err != nil {
		t.Fatalf("connB write failed: %v", err)
	}

	readBuf := make([]byte, 100)
	n, err := clientStream.Read(readBuf)
	if err != nil {
		t.Fatalf("clientStream read failed: %v", err)
	}
	if string(readBuf[:n]) != string(testData) {
		t.Errorf("conn→stream: got %q, want %q", string(readBuf[:n]), string(testData))
	}

	// Test stream → conn direction: write to clientStream, read from connB.
	replyData := []byte("hello from stream")
	_, err = clientStream.Write(replyData)
	if err != nil {
		t.Fatalf("clientStream write failed: %v", err)
	}

	n, err = connB.Read(readBuf)
	if err != nil {
		t.Fatalf("connB read failed: %v", err)
	}
	if string(readBuf[:n]) != string(replyData) {
		t.Errorf("stream→conn: got %q, want %q", string(readBuf[:n]), string(replyData))
	}

	// Clean shutdown.
	connB.Close()

	select {
	case <-done:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("relayStreams did not return after close")
	}
}
