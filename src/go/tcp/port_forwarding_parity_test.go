// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// --- Port forwarding parity tests (matching C#/TS PortForwardingTests) ---

// TestAutoPortSelection verifies that ForwardFromRemotePort with port 0 returns
// a ForwardedPort with a dynamically allocated port > 0.
func TestAutoPortSelection(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	_, echoPort := startEchoServer(t)

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Request remote forwarding with port 0 (auto-select).
	fwd, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}

	if fwd.RemotePort <= 0 {
		t.Fatalf("expected auto-selected port > 0, got %d", fwd.RemotePort)
	}

	// Verify the port is tracked in the collection.
	if !clientPFS.RemoteForwardedPorts.Contains(fwd.RemotePort) {
		t.Fatal("RemoteForwardedPorts should contain the auto-selected port")
	}

	// Verify the port is usable — connect and send data.
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fwd.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to auto-selected port: %v", err)
	}

	testData := []byte("auto port test")
	_, err = conn.Write(testData)
	if err != nil {
		conn.Close()
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		conn.Close()
		t.Fatalf("read failed: %v", err)
	}

	// Close TCP conn before session cleanup to allow relay goroutines to unwind.
	conn.Close()

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", string(buf), string(testData))
	}
}

// TestUnauthorizedForward verifies that ForwardFromRemotePort fails when the
// server does not have PortForwardingService registered (unauthorized).
func TestUnauthorizedForward(t *testing.T) {
	// Create a session pair where only the client has port forwarding.
	clientConfig := ssh.NewNoSecurityConfig()
	AddPortForwardingService(clientConfig)
	clientSession := ssh.NewClientSession(clientConfig)
	clientSession.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	// Server has NO port forwarding service — tcpip-forward will be rejected.
	serverConfig := ssh.NewNoSecurityConfig()
	serverSession := ssh.NewServerSession(serverConfig)
	serverSession.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	streamA, streamB := createDuplexStreams()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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
		t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server connect failed: %v", serverErr)
	}
	defer func() {
		clientSession.Close()
		serverSession.Close()
	}()

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}

	// Attempt to forward a remote port — should fail because server
	// has no handler for tcpip-forward.
	_, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", 9999)
	if err == nil {
		t.Fatal("expected error for unauthorized forward, got nil")
	}
}

// TestForwardAndCancel verifies that closing a RemotePortForwarder sends
// cancel-tcpip-forward and removes the port from RemoteForwardedPorts.
func TestForwardAndCancel(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	_, echoPort := startEchoServer(t)

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Forward a remote port.
	fwd, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}

	remotePort := fwd.RemotePort
	if remotePort == 0 {
		t.Fatal("expected non-zero remote port")
	}

	// Verify port is tracked on both sides.
	if !clientPFS.RemoteForwardedPorts.Contains(remotePort) {
		t.Fatal("client RemoteForwardedPorts should contain the port")
	}
	if !serverPFS.RemoteForwardedPorts.Contains(remotePort) {
		t.Fatal("server RemoteForwardedPorts should contain the port")
	}

	// Close the forwarder — sends cancel-tcpip-forward.
	if err := fwd.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify port removed from client collection.
	if clientPFS.RemoteForwardedPorts.Contains(remotePort) {
		t.Fatal("client RemoteForwardedPorts should not contain the port after Close")
	}

	// Give the server time to process cancel-tcpip-forward.
	time.Sleep(100 * time.Millisecond)

	// Verify server also removed the forwarder.
	if serverPFS.RemoteForwardedPorts.Contains(remotePort) {
		t.Fatal("server RemoteForwardedPorts should not contain the port after cancel")
	}
}

// TestForwardConnectionAcceptedEvent verifies that OnForwardedPortConnecting fires
// with correct port info when a connection is accepted through a forwarded port.
func TestForwardConnectionAcceptedEvent(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	_, echoPort := startEchoServer(t)

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	// Set up OnForwardedPortConnecting to capture event args on the client side
	// (forwarded-tcpip channels arrive at the client).
	var mu sync.Mutex
	var capturedArgs *ForwardedPortConnectingEventArgs
	argsCh := make(chan struct{}, 1)
	clientPFS.OnForwardedPortConnecting = func(args *ForwardedPortConnectingEventArgs) {
		mu.Lock()
		capturedArgs = &ForwardedPortConnectingEventArgs{
			Port:       args.Port,
			IsIncoming: args.IsIncoming,
			Stream:     args.Stream,
			Reject:     args.Reject,
		}
		mu.Unlock()
		argsCh <- struct{}{}
		// Do not reject — allow the connection.
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Forward from remote port.
	fwd, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Connect through the forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fwd.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}

	// Wait for the callback.
	select {
	case <-argsCh:
	case <-time.After(5 * time.Second):
		conn.Close()
		t.Fatal("OnForwardedPortConnecting was not called within timeout")
	}

	// Close TCP conn before session cleanup to allow relay goroutines to unwind.
	conn.Close()

	mu.Lock()
	defer mu.Unlock()

	if capturedArgs == nil {
		t.Fatal("OnForwardedPortConnecting args not captured")
	}
	// The callback's Port is the remote forwarded port (from the forwarded-tcpip message).
	if capturedArgs.Port != fwd.RemotePort {
		t.Errorf("Port = %d, want %d", capturedArgs.Port, fwd.RemotePort)
	}
	if capturedArgs.Stream == nil {
		t.Error("Stream should be non-nil")
	}
	if capturedArgs.Reject {
		t.Error("Reject should be false")
	}
}

// TestForwardConnectionRejectedEvent verifies that setting Reject=true in
// OnForwardedPortConnecting causes the connection to be refused.
func TestForwardConnectionRejectedEvent(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	_, echoPort := startEchoServer(t)

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	// Client rejects all incoming forwarded-tcpip connections.
	var callbackFired int32
	clientPFS.OnForwardedPortConnecting = func(args *ForwardedPortConnectingEventArgs) {
		atomic.StoreInt32(&callbackFired, 1)
		args.Reject = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Forward from remote port.
	fwd, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}
	defer fwd.Close()

	time.Sleep(50 * time.Millisecond)

	// Connect through the forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fwd.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer conn.Close()

	// Send data.
	conn.Write([]byte("test data"))

	// Read should fail or timeout because the client rejected the connection.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 10)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected error/timeout on read after rejection")
	}

	// Verify the callback was called.
	if atomic.LoadInt32(&callbackFired) != 1 {
		t.Fatal("OnForwardedPortConnecting was not called")
	}
}

// TestMultipleConnectionsOnForward verifies that multiple TCP connections to a
// forwarded port each get their own SSH channel and data flows independently.
func TestMultipleConnectionsOnForward(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const numConns = 3

	// Open 3 independent forwarded connections sequentially using ConnectToForwardedPort
	// to guarantee 1:1 mapping between TCP conns and SSH streams.
	for i := 0; i < numConns; i++ {
		// Request remote streaming on a dynamic port.
		fp, err := clientPFS.StreamFromRemotePort(ctx, "127.0.0.1", 0)
		if err != nil {
			t.Fatalf("connection %d: StreamFromRemotePort failed: %v", i, err)
		}

		time.Sleep(50 * time.Millisecond)

		// Start waiting for the forwarded stream.
		streamCh := make(chan io.ReadWriteCloser, 1)
		errCh := make(chan error, 1)
		go func() {
			s, err := clientPFS.ConnectToForwardedPort(ctx, fp.RemotePort)
			streamCh <- s
			errCh <- err
		}()

		// Connect via TCP to trigger the forwarded channel.
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.RemotePort))
		if err != nil {
			t.Fatalf("connection %d: failed to connect: %v", i, err)
		}

		// Wait for the stream (10s to avoid flakiness under -race).
		var stream io.ReadWriteCloser
		select {
		case stream = <-streamCh:
		case <-time.After(10 * time.Second):
			conn.Close()
			t.Fatalf("connection %d: ConnectToForwardedPort timed out", i)
		}
		if err := <-errCh; err != nil {
			conn.Close()
			t.Fatalf("connection %d: ConnectToForwardedPort error: %v", i, err)
		}

		// Send data from TCP side, read from SSH stream side.
		testData := []byte(fmt.Sprintf("connection-%d-data", i))
		_, err = conn.Write(testData)
		if err != nil {
			conn.Close()
			stream.Close()
			t.Fatalf("connection %d: write failed: %v", i, err)
		}

		buf := make([]byte, len(testData))
		_, err = io.ReadFull(stream, buf)
		if err != nil {
			conn.Close()
			stream.Close()
			t.Fatalf("connection %d: stream read failed: %v", i, err)
		}

		if string(buf) != string(testData) {
			t.Errorf("connection %d: data mismatch: got %q, want %q", i, string(buf), string(testData))
		}

		conn.Close()
		stream.Close()
	}
}

// TestForwardFromRemotePortEndSession verifies that disposing the session during
// active remote port forwarding causes the TCP stream and channel to close.
// Matches C# PortForwardingTests.ForwardFromRemotePortEndSession.
func TestForwardFromRemotePortEndSession(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	_, echoPort := startEchoServer(t)

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fwd, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Connect through the forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fwd.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer conn.Close()

	// Verify it works by writing data.
	_, err = conn.Write([]byte("test"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Close the server session (simulate "end session").
	serverSession.Close()

	// The TCP stream should close — read should return error or 0 bytes.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		// Read returned data without error — the stream may not have closed yet.
		// Try one more read.
		_, readErr = conn.Read(buf)
	}
	// readErr should be non-nil (EOF or connection reset) indicating stream closed.
	if readErr == nil {
		t.Error("expected TCP stream to close after session disposal")
	}
}

// TestForwardToRemotePortEndSession verifies that disposing the session during
// active local-to-remote port forwarding causes the TCP stream and channel to close.
// Matches C# PortForwardingTests.ForwardToRemotePortEndSession.
func TestForwardToRemotePortEndSession(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	_, echoPort := startEchoServer(t)

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardToRemotePort failed: %v", err)
	}

	// Connect to the local forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.LocalPort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer conn.Close()

	// Verify it works.
	_, err = conn.Write([]byte("test"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Close the server session.
	serverSession.Close()

	// The TCP stream should close.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	if readErr == nil {
		_, readErr = conn.Read(buf)
	}
	if readErr == nil {
		t.Error("expected TCP stream to close after session disposal")
	}
}

// TestForwardFromRemotePortError verifies that closing the forwarded port
// during active remote port forwarding causes the TCP stream to close cleanly.
// In C#, this test closes the SSH channel with SIGABRT. In Go, the channel is
// managed by the PFS service, so we close the forwarder to trigger cleanup.
// Matches C# PortForwardingTests.ForwardFromRemotePortError.
func TestForwardFromRemotePortError(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	_, echoPort := startEchoServer(t)

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fwd, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Connect through the forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fwd.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer conn.Close()

	// Verify data flows before the error.
	testData := []byte("pre-error-test")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, len(testData))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	// Close the forwarder — this cancels the forwarding and closes the channel.
	if err := fwd.Close(); err != nil {
		t.Fatalf("Close forwarder failed: %v", err)
	}

	// The TCP connection should fail on subsequent operations.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, readErr := conn.Read(make([]byte, 1))
	if readErr == nil {
		t.Error("expected TCP stream to close after forwarder error")
	}

	// Session should still be connected.
	if !clientSession.IsConnected() {
		t.Error("client session should still be connected after forwarder error")
	}
}

// TestForwardToRemotePortError verifies that closing the forwarded port
// during active local-to-remote port forwarding causes the TCP stream to close cleanly.
// Matches C# PortForwardingTests.ForwardToRemotePortError.
func TestForwardToRemotePortError(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	_, echoPort := startEchoServer(t)

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardToRemotePort failed: %v", err)
	}

	// Connect to the local forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.LocalPort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer conn.Close()

	// Verify data flows before the error.
	testData := []byte("pre-error-test")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	buf := make([]byte, len(testData))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	// Close the forwarder — this cancels the forwarding and closes the channel.
	if err := fp.Close(); err != nil {
		t.Fatalf("Close forwarder failed: %v", err)
	}

	// The TCP connection should fail on subsequent operations.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, readErr := conn.Read(make([]byte, 1))
	if readErr == nil {
		t.Error("expected TCP stream to close after forwarder error")
	}

	// Session should still be connected.
	if !clientSession.IsConnected() {
		t.Error("client session should still be connected after forwarder error")
	}
}

// Note: C# has ForwardAndConnectTwoPorts — a deadlock regression test where two
// concurrent ForwardFromRemotePort requests interleave with a channel-open. The
// deadlock pattern depends on C#'s async request/response pipeline where requests
// and channel-opens can interleave in specific ways. Go's goroutine-based message
// handling avoids this specific pattern. Concurrent forward operations are tested
// by TestPortForwardRacing below.

// TestPortForwardRacing verifies that concurrent ForwardFromRemotePort + Close()
// operations don't deadlock or panic.
func TestPortForwardRacing(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	_, echoPort := startEchoServer(t)

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const numOps = 10
	var wg sync.WaitGroup
	wg.Add(numOps)

	for i := 0; i < numOps; i++ {
		go func(idx int) {
			defer wg.Done()

			fwd, err := clientPFS.ForwardFromRemotePort(
				ctx, "127.0.0.1", 0, "127.0.0.1", echoPort,
			)
			if err != nil {
				// Some may fail due to racing — that's OK as long as no panic/deadlock.
				return
			}

			// Small delay to vary timing.
			time.Sleep(time.Duration(idx) * time.Millisecond)

			// Close the forwarder.
			fwd.Close()
		}(i)
	}

	// Wait with a timeout to detect deadlocks.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All operations completed without deadlock.
	case <-time.After(20 * time.Second):
		t.Fatal("timed out — possible deadlock in concurrent ForwardFromRemotePort + Close")
	}
}
