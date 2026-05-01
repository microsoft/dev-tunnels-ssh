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

// createPortForwardingSessionPair creates a connected client/server session pair with
// port forwarding registered on both sides. Returns the sessions and a cleanup function.
func createPortForwardingSessionPair(t *testing.T) (
	clientSession *ssh.ClientSession,
	serverSession *ssh.ServerSession,
	cleanup func(),
) {
	t.Helper()

	clientConfig := ssh.NewNoSecurityConfig()
	AddPortForwardingService(clientConfig)
	clientSession = ssh.NewClientSession(clientConfig)
	clientSession.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	serverConfig := ssh.NewNoSecurityConfig()
	AddPortForwardingService(serverConfig)
	serverSession = ssh.NewServerSession(serverConfig)
	serverSession.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	streamA, streamB := createDuplexStreams()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

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

	cleanup = func() {
		cancel()
		clientSession.Close()
		serverSession.Close()
	}

	return
}

// startEchoServer starts a TCP echo server that echoes back all received data.
// Returns the listener and the port it's listening on.
func startEchoServer(t *testing.T) (net.Listener, int) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return ln, port
}

// TestForwardToRemotePort verifies local-to-remote port forwarding:
// client listens locally, opens direct-tcpip channel, data arrives at remote TCP target.
func TestForwardToRemotePort(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	// Start an echo server as the remote target.
	_, echoPort := startEchoServer(t)

	// Get port forwarding service on client side.
	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}

	// Also activate on server so it handles direct-tcpip channels.
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Forward: local dynamic port → remote echo server.
	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardToRemotePort failed: %v", err)
	}
	if fp.LocalPort == 0 {
		t.Fatal("expected non-zero local port")
	}

	// Connect to the local forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.LocalPort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer conn.Close()

	// Send data and verify echo.
	testData := []byte("hello port forwarding")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo data mismatch: got %q, want %q", string(buf), string(testData))
	}
}

// TestForwardFromRemotePort verifies remote-to-local port forwarding:
// server listens on a port, incoming TCP connections are forwarded back through SSH
// to a local TCP target.
func TestForwardFromRemotePort(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	// Start an echo server as the local destination.
	_, echoPort := startEchoServer(t)

	// Get port forwarding services on both sides.
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

	// Request remote side (server) to listen on a dynamic port, forwarding
	// connections back to our local echo server.
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}
	if fp.RemotePort == 0 {
		t.Fatal("expected non-zero remote port")
	}

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	// Connect to the server's forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to remote forwarded port: %v", err)
	}
	defer conn.Close()

	// Send data and verify echo.
	testData := []byte("hello remote forwarding")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo data mismatch: got %q, want %q", string(buf), string(testData))
	}
}

// TestStreamToRemotePort verifies opening a direct-tcpip channel as io.ReadWriteCloser.
func TestStreamToRemotePort(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	// Start an echo server as the target.
	_, echoPort := startEchoServer(t)

	// Activate port forwarding on both sides.
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

	// Open a stream to the remote echo server.
	stream, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("StreamToRemotePort failed: %v", err)
	}
	defer stream.Close()

	// Write data and verify echo through the stream.
	testData := []byte("hello stream forwarding")
	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("stream write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		t.Fatalf("stream read failed: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo data mismatch: got %q, want %q", string(buf), string(testData))
	}
}

// TestStreamFromRemotePort verifies remote streaming with OnStreamOpened callback.
func TestStreamFromRemotePort(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	// Get port forwarding services on both sides.
	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	// Set up OnStreamOpened to capture the stream.
	streamCh := make(chan *ssh.Stream, 1)
	portCh := make(chan int, 1)
	clientPFS.OnStreamOpened = func(stream *ssh.Stream, port int) {
		streamCh <- stream
		portCh <- port
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Request remote streaming on a dynamic port.
	fp, err := clientPFS.StreamFromRemotePort(ctx, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("StreamFromRemotePort failed: %v", err)
	}
	if fp.RemotePort == 0 {
		t.Fatal("expected non-zero remote port")
	}

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	// Connect to the remote forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to remote port: %v", err)
	}
	defer conn.Close()

	// Wait for OnStreamOpened.
	var stream *ssh.Stream
	select {
	case stream = <-streamCh:
	case <-time.After(5 * time.Second):
		t.Fatal("OnStreamOpened not called within timeout")
	}

	select {
	case port := <-portCh:
		if port != fp.RemotePort {
			t.Errorf("OnStreamOpened port = %d, want %d", port, fp.RemotePort)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("port not received")
	}

	// Write data from TCP side, read through SSH stream.
	testData := []byte("hello stream from remote")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("TCP write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		t.Fatalf("stream read failed: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("data mismatch: got %q, want %q", string(buf), string(testData))
	}

	// Write data from SSH stream, read through TCP side.
	replyData := []byte("reply from ssh")
	_, err = stream.Write(replyData)
	if err != nil {
		t.Fatalf("stream write failed: %v", err)
	}

	replyBuf := make([]byte, len(replyData))
	_, err = io.ReadFull(conn, replyBuf)
	if err != nil {
		t.Fatalf("TCP read failed: %v", err)
	}

	if string(replyBuf) != string(replyData) {
		t.Errorf("reply mismatch: got %q, want %q", string(replyBuf), string(replyData))
	}
}

// TestConnectToForwardedPort verifies waiting for a forwarded channel and returning as stream.
func TestConnectToForwardedPort(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	// Get port forwarding services on both sides.
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

	// Request remote streaming on a dynamic port.
	fp, err := clientPFS.StreamFromRemotePort(ctx, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("StreamFromRemotePort failed: %v", err)
	}
	if fp.RemotePort == 0 {
		t.Fatal("expected non-zero remote port")
	}

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	// Start waiting for the forwarded port in a goroutine.
	streamCh := make(chan io.ReadWriteCloser, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := clientPFS.ConnectToForwardedPort(ctx, fp.RemotePort)
		streamCh <- s
		errCh <- err
	}()

	// Connect to the remote forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to remote port: %v", err)
	}
	defer conn.Close()

	// Wait for ConnectToForwardedPort to return.
	var stream io.ReadWriteCloser
	select {
	case stream = <-streamCh:
	case <-time.After(5 * time.Second):
		t.Fatal("ConnectToForwardedPort did not return within timeout")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("ConnectToForwardedPort error: %v", err)
	}
	defer stream.Close()

	// Verify bidirectional data flow.
	testData := []byte("hello connect forwarded")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("TCP write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		t.Fatalf("stream read failed: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("data mismatch: got %q, want %q", string(buf), string(testData))
	}
}

// TestMultipleConnectionsOnForwardedPort verifies that multiple TCP connections
// to a forwarded port each get their own SSH channel.
func TestMultipleConnectionsOnForwardedPort(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	// Get port forwarding services on both sides.
	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	// Track streams received via OnStreamOpened.
	var mu sync.Mutex
	var streams []*ssh.Stream
	streamsCh := make(chan struct{}, 3)
	clientPFS.OnStreamOpened = func(stream *ssh.Stream, port int) {
		mu.Lock()
		streams = append(streams, stream)
		mu.Unlock()
		streamsCh <- struct{}{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Request remote streaming on a dynamic port.
	fp, err := clientPFS.StreamFromRemotePort(ctx, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("StreamFromRemotePort failed: %v", err)
	}

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	// Open 3 TCP connections.
	conns := make([]net.Conn, 3)
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.RemotePort))
		if err != nil {
			t.Fatalf("connection %d: failed to connect: %v", i, err)
		}
		conns[i] = conn
		defer conn.Close()
	}

	// Wait for all 3 streams.
	for i := 0; i < 3; i++ {
		select {
		case <-streamsCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("only received %d of 3 streams", i)
		}
	}

	mu.Lock()
	if len(streams) != 3 {
		t.Fatalf("expected 3 streams, got %d", len(streams))
	}
	mu.Unlock()

	// Verify each connection can send/receive independently.
	for i := 0; i < 3; i++ {
		testData := []byte(fmt.Sprintf("connection-%d", i))

		_, err := conns[i].Write(testData)
		if err != nil {
			t.Fatalf("connection %d: write failed: %v", i, err)
		}

		mu.Lock()
		stream := streams[i]
		mu.Unlock()

		buf := make([]byte, len(testData))
		_, err = io.ReadFull(stream, buf)
		if err != nil {
			t.Fatalf("connection %d: stream read failed: %v", i, err)
		}

		if string(buf) != string(testData) {
			t.Errorf("connection %d: data mismatch: got %q, want %q", i, string(buf), string(testData))
		}
	}
}

// TestForwardToRemotePortCollection verifies that LocalForwardedPorts is updated
// when forwarding a local port to remote.
func TestForwardToRemotePortCollection(t *testing.T) {
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

	// Verify collection starts empty.
	if clientPFS.LocalForwardedPorts.Count() != 0 {
		t.Fatalf("expected 0 local forwarded ports, got %d", clientPFS.LocalForwardedPorts.Count())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Forward: local dynamic port → remote echo server.
	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardToRemotePort failed: %v", err)
	}

	// Verify the port is tracked in the collection.
	if clientPFS.LocalForwardedPorts.Count() != 1 {
		t.Fatalf("expected 1 local forwarded port, got %d", clientPFS.LocalForwardedPorts.Count())
	}
	if !clientPFS.LocalForwardedPorts.Contains(fp.LocalPort) {
		t.Fatal("LocalForwardedPorts should contain the forwarded port")
	}

	// Verify the stored ForwardedPort has correct fields.
	storedFP := clientPFS.LocalForwardedPorts.Get(fp.LocalPort)
	if storedFP == nil {
		t.Fatal("expected non-nil ForwardedPort from Get")
	}
	if storedFP.LocalPort != fp.LocalPort {
		t.Errorf("stored LocalPort = %d, want %d", storedFP.LocalPort, fp.LocalPort)
	}
	if storedFP.RemotePort != echoPort {
		t.Errorf("stored RemotePort = %d, want %d", storedFP.RemotePort, echoPort)
	}
}

// TestForwardFromRemotePortCollection verifies that RemoteForwardedPorts is updated
// on the client side when forwarding a remote port.
func TestForwardFromRemotePortCollection(t *testing.T) {
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

	// Verify collection starts empty.
	if clientPFS.RemoteForwardedPorts.Count() != 0 {
		t.Fatalf("expected 0 remote forwarded ports, got %d", clientPFS.RemoteForwardedPorts.Count())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Request remote forwarding.
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}
	if fp.RemotePort == 0 {
		t.Fatal("expected non-zero remote port")
	}

	// Verify the port is tracked in the client's collection.
	if clientPFS.RemoteForwardedPorts.Count() != 1 {
		t.Fatalf("expected 1 remote forwarded port, got %d", clientPFS.RemoteForwardedPorts.Count())
	}
	if !clientPFS.RemoteForwardedPorts.Contains(fp.RemotePort) {
		t.Fatal("RemoteForwardedPorts should contain the forwarded port")
	}

	// Also verify the server's collection was updated.
	if serverPFS.RemoteForwardedPorts.Count() != 1 {
		t.Fatalf("expected 1 remote forwarded port on server, got %d", serverPFS.RemoteForwardedPorts.Count())
	}
}

// TestOnPortAddedCallback verifies that OnPortAdded fires when forwarding starts.
func TestOnPortAddedCallback(t *testing.T) {
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

	// Set up OnPortAdded callback on local collection.
	var addedPort *ForwardedPort
	addedCh := make(chan struct{}, 1)
	clientPFS.LocalForwardedPorts.OnPortAdded = func(port *ForwardedPort) {
		addedPort = port
		addedCh <- struct{}{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Forward a port.
	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardToRemotePort failed: %v", err)
	}

	// Verify callback was called.
	select {
	case <-addedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("OnPortAdded was not called")
	}

	if addedPort == nil {
		t.Fatal("OnPortAdded received nil port")
	}
	if addedPort.LocalPort != fp.LocalPort {
		t.Errorf("OnPortAdded LocalPort = %d, want %d", addedPort.LocalPort, fp.LocalPort)
	}
	if addedPort.RemotePort != echoPort {
		t.Errorf("OnPortAdded RemotePort = %d, want %d", addedPort.RemotePort, echoPort)
	}
}

// TestOnPortRemovedCallback verifies that OnPortRemoved fires on dispose.
func TestOnPortRemovedCallback(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	_ = cleanup // We manage cleanup ourselves for this test.

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

	// Forward a port.
	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardToRemotePort failed: %v", err)
	}

	// Set up OnPortRemoved callback.
	var removedPort *ForwardedPort
	removedCh := make(chan struct{}, 1)
	clientPFS.LocalForwardedPorts.OnPortRemoved = func(port *ForwardedPort) {
		removedPort = port
		removedCh <- struct{}{}
	}

	// Close triggers cleanup and OnPortRemoved.
	clientPFS.Close()

	select {
	case <-removedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("OnPortRemoved was not called")
	}

	if removedPort == nil {
		t.Fatal("OnPortRemoved received nil port")
	}
	if removedPort.LocalPort != fp.LocalPort {
		t.Errorf("OnPortRemoved LocalPort = %d, want %d", removedPort.LocalPort, fp.LocalPort)
	}

	// Verify collection is now empty.
	if clientPFS.LocalForwardedPorts.Count() != 0 {
		t.Fatalf("expected 0 local forwarded ports after dispose, got %d", clientPFS.LocalForwardedPorts.Count())
	}

	// Cleanup sessions.
	cleanup()
}

// TestLocalPortForwarderClose verifies that closing a LocalPortForwarder stops
// the TCP listener and removes the port from the collection.
func TestLocalPortForwarderClose(t *testing.T) {
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

	// Forward a local port.
	fwd, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardToRemotePort failed: %v", err)
	}

	localPort := fwd.LocalPort
	if localPort == 0 {
		t.Fatal("expected non-zero local port")
	}

	// Verify port is in the collection.
	if !clientPFS.LocalForwardedPorts.Contains(localPort) {
		t.Fatal("LocalForwardedPorts should contain the forwarded port")
	}

	// Verify TCP listener is accepting connections.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		t.Fatalf("expected to connect to forwarded port: %v", err)
	}
	conn.Close()

	// Close the forwarder.
	if err := fwd.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify port removed from collection.
	if clientPFS.LocalForwardedPorts.Contains(localPort) {
		t.Fatal("LocalForwardedPorts should not contain the port after Close")
	}

	// Verify TCP listener is stopped — connect should fail.
	time.Sleep(50 * time.Millisecond)
	_, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected connection to fail after forwarder Close")
	}

	// Verify Close is idempotent.
	if err := fwd.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

// TestRemotePortForwarderClose verifies that closing a RemotePortForwarder sends
// a cancel-tcpip-forward request and removes the port from the collection.
func TestRemotePortForwarderClose(t *testing.T) {
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

	// Request remote forwarding.
	fwd, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}

	remotePort := fwd.RemotePort
	if remotePort == 0 {
		t.Fatal("expected non-zero remote port")
	}

	// Give the server a moment to start listening.
	time.Sleep(50 * time.Millisecond)

	// Verify port is in the client's collection.
	if !clientPFS.RemoteForwardedPorts.Contains(remotePort) {
		t.Fatal("RemoteForwardedPorts should contain the forwarded port")
	}

	// Verify server is listening on the forwarded port.
	if !serverPFS.RemoteForwardedPorts.Contains(remotePort) {
		t.Fatal("server RemoteForwardedPorts should contain the forwarded port")
	}

	// Close the forwarder — sends cancel-tcpip-forward.
	if err := fwd.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify port removed from client collection.
	if clientPFS.RemoteForwardedPorts.Contains(remotePort) {
		t.Fatal("client RemoteForwardedPorts should not contain the port after Close")
	}

	// Give the server a moment to process the cancel-tcpip-forward.
	time.Sleep(100 * time.Millisecond)

	// Verify server also removed the forwarder (cancel-tcpip-forward was processed).
	if serverPFS.RemoteForwardedPorts.Contains(remotePort) {
		t.Fatal("server RemoteForwardedPorts should not contain the port after cancel")
	}

	// Verify Close is idempotent.
	if err := fwd.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

// TestForwardToRemotePortDuplicate verifies that forwarding the same local port
// twice returns an error.
func TestForwardToRemotePortDuplicate(t *testing.T) {
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

	// Forward from a dynamic port first to get an allocated port.
	fwd, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("first ForwardToRemotePort failed: %v", err)
	}
	defer fwd.Close()

	localPort := fwd.LocalPort

	// Attempt to forward the same local port again — should fail.
	_, err = clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", localPort, "127.0.0.1", echoPort)
	if err == nil {
		t.Fatal("expected error when forwarding duplicate local port")
	}
}

// TestForwardFromRemotePortDuplicate verifies that forwarding the same remote port
// twice returns an error.
func TestForwardFromRemotePortDuplicate(t *testing.T) {
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

	// Forward from a dynamic port first to get an allocated port.
	fwd, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("first ForwardFromRemotePort failed: %v", err)
	}
	defer fwd.Close()

	remotePort := fwd.RemotePort

	// Attempt to forward the same remote port again — should fail.
	_, err = clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", remotePort, "127.0.0.1", echoPort)
	if err == nil {
		t.Fatal("expected error when forwarding duplicate remote port")
	}
}

// TestLocalPortForwarderImplementsCloser verifies compile-time io.Closer compliance.
func TestLocalPortForwarderImplementsCloser(t *testing.T) {
	var _ io.Closer = (*LocalPortForwarder)(nil)
}

// TestRemotePortForwarderImplementsCloser verifies compile-time io.Closer compliance.
func TestRemotePortForwarderImplementsCloser(t *testing.T) {
	var _ io.Closer = (*RemotePortForwarder)(nil)
}

// TestOnForwardedPortConnectingRejectDirectTcpip verifies that setting Reject=true
// in the OnForwardedPortConnecting callback refuses a direct-tcpip connection.
func TestOnForwardedPortConnectingRejectDirectTcpip(t *testing.T) {
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

	// Server rejects all forwarded port connections.
	var callbackPort int32
	var callbackIsIncoming int32
	serverPFS.OnForwardedPortConnecting = func(args *ForwardedPortConnectingEventArgs) {
		atomic.StoreInt32(&callbackPort, int32(args.Port))
		if args.IsIncoming {
			atomic.StoreInt32(&callbackIsIncoming, 1)
		}
		args.Reject = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open a stream to the remote echo server via direct-tcpip.
	stream, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("StreamToRemotePort failed: %v", err)
	}
	defer stream.Close()

	// Write data — may or may not succeed depending on timing.
	stream.Write([]byte("test data"))

	// Read should fail because server rejected the connection and closed the stream.
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 10)
		_, err := stream.Read(buf)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected error on read after rejection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read did not fail within timeout after rejection")
	}

	// Verify callback was called with correct args.
	if port := atomic.LoadInt32(&callbackPort); port != int32(echoPort) {
		t.Errorf("callback Port = %d, want %d", port, echoPort)
	}
	if atomic.LoadInt32(&callbackIsIncoming) != 1 {
		t.Error("callback IsIncoming should be true")
	}
}

// TestOnForwardedPortConnectingRejectForwardedTcpip verifies that setting Reject=true
// in the OnForwardedPortConnecting callback refuses a forwarded-tcpip connection.
func TestOnForwardedPortConnectingRejectForwardedTcpip(t *testing.T) {
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

	// Client rejects incoming forwarded connections.
	var callbackFired int32
	clientPFS.OnForwardedPortConnecting = func(args *ForwardedPortConnectingEventArgs) {
		atomic.StoreInt32(&callbackFired, 1)
		args.Reject = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Request server to listen and forward to client's local echo server.
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Connect to the server's forwarded port.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer conn.Close()

	// Write data.
	conn.Write([]byte("test data"))

	// Read should fail or timeout because client rejected the forwarded connection.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 10)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected error/timeout on read after rejection")
	}

	// Verify callback was called.
	if atomic.LoadInt32(&callbackFired) != 1 {
		t.Fatal("OnForwardedPortConnecting was not called")
	}
}

// TestForwardConnectionsToLocalPortsFalseDirectTcpip verifies that when
// ForwardConnectionsToLocalPorts is false, direct-tcpip channels are accepted
// but not auto-connected to local TCP targets.
func TestForwardConnectionsToLocalPortsFalseDirectTcpip(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	// Start an echo server and track connections.
	var connCount int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	echoPort := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&connCount, 1)
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}

	// Disable auto-connection on server.
	serverPFS.ForwardConnectionsToLocalPorts = false

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open a stream to the echo server via direct-tcpip.
	// The channel should be accepted (no error).
	stream, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("StreamToRemotePort failed: %v", err)
	}
	defer stream.Close()

	// Give the server time to process.
	time.Sleep(200 * time.Millisecond)

	// Verify no TCP connection was made to the echo server.
	if count := atomic.LoadInt32(&connCount); count != 0 {
		t.Fatalf("expected 0 connections to echo server, got %d", count)
	}
}

// TestForwardConnectionsToLocalPortsFalseForwardedTcpip verifies that when
// ForwardConnectionsToLocalPorts is false on the client, forwarded-tcpip channels
// are accepted but not auto-connected to local TCP targets.
func TestForwardConnectionsToLocalPortsFalseForwardedTcpip(t *testing.T) {
	clientSession, serverSession, cleanup := createPortForwardingSessionPair(t)
	defer cleanup()

	// Start an echo server and track connections.
	var connCount int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	echoPort := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&connCount, 1)
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })

	clientPFS := GetPortForwardingService(&clientSession.Session)
	if clientPFS == nil {
		t.Fatal("failed to get client port forwarding service")
	}
	serverPFS := GetPortForwardingService(&serverSession.Session)
	if serverPFS == nil {
		t.Fatal("failed to get server port forwarding service")
	}
	_ = serverPFS

	// Disable auto-connection on client (for incoming forwarded-tcpip channels).
	clientPFS.ForwardConnectionsToLocalPorts = false

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Request server to listen and forward to client's echo server.
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Connect to the server's forwarded port — this triggers a forwarded-tcpip channel.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.RemotePort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer conn.Close()

	// Give time for the channel to be processed.
	time.Sleep(200 * time.Millisecond)

	// Verify no TCP connection was made to the echo server (because
	// ForwardConnectionsToLocalPorts=false prevents auto-connection).
	if count := atomic.LoadInt32(&connCount); count != 0 {
		t.Fatalf("expected 0 connections to echo server, got %d", count)
	}
}

// TestOnForwardedPortConnectingEventArgsPopulated verifies that the callback
// receives correctly populated event args including a non-nil Stream.
func TestOnForwardedPortConnectingEventArgsPopulated(t *testing.T) {
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

	// Capture event args without rejecting.
	var mu sync.Mutex
	var capturedArgs *ForwardedPortConnectingEventArgs
	argsCh := make(chan struct{}, 1)
	serverPFS.OnForwardedPortConnecting = func(args *ForwardedPortConnectingEventArgs) {
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

	// Open a stream to the remote echo server — triggers direct-tcpip.
	stream, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("StreamToRemotePort failed: %v", err)
	}
	defer stream.Close()

	// Wait for callback.
	select {
	case <-argsCh:
	case <-time.After(5 * time.Second):
		t.Fatal("OnForwardedPortConnecting was not called")
	}

	mu.Lock()
	defer mu.Unlock()

	if capturedArgs.Port != echoPort {
		t.Errorf("Port = %d, want %d", capturedArgs.Port, echoPort)
	}
	if !capturedArgs.IsIncoming {
		t.Error("IsIncoming should be true")
	}
	if capturedArgs.Stream == nil {
		t.Error("Stream should be non-nil")
	}
	if capturedArgs.Reject {
		t.Error("Reject should be false (not set)")
	}

	// Verify the echo still works (connection was not rejected).
	testData := []byte("hello with event")
	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", string(buf), string(testData))
	}
}

// --- Factory interface tests ---

// testListenerFactory is a custom TCPListenerFactory that records calls.
type testListenerFactory struct {
	calls      []testListenerCall
	mu         sync.Mutex
	underlying TCPListenerFactory
}

type testListenerCall struct {
	RemotePort         int
	LocalIPAddress     string
	LocalPort          int
	CanChangeLocalPort bool
}

func newTestListenerFactory() *testListenerFactory {
	return &testListenerFactory{
		underlying: &defaultTCPListenerFactory{},
	}
}

func (f *testListenerFactory) CreateTCPListener(
	remotePort int,
	localIPAddress string,
	localPort int,
	canChangeLocalPort bool,
) (net.Listener, error) {
	f.mu.Lock()
	f.calls = append(f.calls, testListenerCall{
		RemotePort:         remotePort,
		LocalIPAddress:     localIPAddress,
		LocalPort:          localPort,
		CanChangeLocalPort: canChangeLocalPort,
	})
	f.mu.Unlock()
	return f.underlying.CreateTCPListener(remotePort, localIPAddress, localPort, canChangeLocalPort)
}

func (f *testListenerFactory) getCalls() []testListenerCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]testListenerCall, len(f.calls))
	copy(result, f.calls)
	return result
}

// testMessageFactory is a custom PortForwardMessageFactory that records calls.
type testMessageFactory struct {
	requestCalls     []int
	successCalls     []int
	channelOpenCalls []int
	mu               sync.Mutex
	underlying       PortForwardMessageFactory
}

func newTestMessageFactory() *testMessageFactory {
	return &testMessageFactory{
		underlying: &defaultPortForwardMessageFactory{},
	}
}

func (f *testMessageFactory) CreateRequestMessage(port int) *PortForwardRequestMessage {
	f.mu.Lock()
	f.requestCalls = append(f.requestCalls, port)
	f.mu.Unlock()
	return f.underlying.CreateRequestMessage(port)
}

func (f *testMessageFactory) CreateSuccessMessage(port int) *PortForwardSuccessMessage {
	f.mu.Lock()
	f.successCalls = append(f.successCalls, port)
	f.mu.Unlock()
	return f.underlying.CreateSuccessMessage(port)
}

func (f *testMessageFactory) CreateChannelOpenMessage(port int) *PortForwardChannelOpenMessage {
	f.mu.Lock()
	f.channelOpenCalls = append(f.channelOpenCalls, port)
	f.mu.Unlock()
	return f.underlying.CreateChannelOpenMessage(port)
}

// TestCustomListenerFactoryCalledDuringForwardToRemotePort verifies that a custom
// TCPListenerFactory is called during ForwardToRemotePort.
func TestCustomListenerFactoryCalledDuringForwardToRemotePort(t *testing.T) {
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

	// Install custom listener factory on client side.
	factory := newTestListenerFactory()
	clientPFS.ListenerFactory = factory

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Forward a local port to the echo server.
	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardToRemotePort failed: %v", err)
	}
	defer fp.Close()

	// Verify the factory was called.
	calls := factory.getCalls()
	if len(calls) == 0 {
		t.Fatal("expected at least one factory call")
	}

	// First call should have canChangeLocalPort=true and the correct remote port.
	if calls[0].RemotePort != echoPort {
		t.Errorf("RemotePort = %d, want %d", calls[0].RemotePort, echoPort)
	}
	if calls[0].LocalIPAddress != "127.0.0.1" {
		t.Errorf("LocalIPAddress = %q, want %q", calls[0].LocalIPAddress, "127.0.0.1")
	}
	if !calls[0].CanChangeLocalPort {
		t.Error("expected CanChangeLocalPort=true for primary listener")
	}

	// Verify data still flows through.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", fp.LocalPort))
	if err != nil {
		t.Fatalf("failed to connect to forwarded port: %v", err)
	}
	defer conn.Close()

	testData := []byte("factory test")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", string(buf), string(testData))
	}
}

// TestCustomListenerFactoryDualModeIPv6 verifies that when listening on 127.0.0.1,
// a second listener is created for ::1 (IPv6 loopback) via the factory.
func TestCustomListenerFactoryDualModeIPv6(t *testing.T) {
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

	// Install custom listener factory on client side.
	factory := newTestListenerFactory()
	clientPFS.ListenerFactory = factory

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardToRemotePort failed: %v", err)
	}
	defer fp.Close()

	calls := factory.getCalls()
	// Should have at least 2 calls: one for IPv4, one for IPv6.
	// (IPv6 may fail if not supported, but the call should still be made.)
	if len(calls) < 2 {
		t.Skipf("dual-mode listening not available (only %d calls), IPv6 may not be supported", len(calls))
	}

	// Second call should be for IPv6 loopback with canChangeLocalPort=false.
	if calls[1].LocalIPAddress != "::1" {
		t.Errorf("second call LocalIPAddress = %q, want %q", calls[1].LocalIPAddress, "::1")
	}
	if calls[1].CanChangeLocalPort {
		t.Error("expected CanChangeLocalPort=false for IPv6 dual-mode listener")
	}
	// The local port should match the dynamically allocated port from the first call.
	if calls[1].LocalPort != fp.LocalPort {
		t.Errorf("second call LocalPort = %d, want %d", calls[1].LocalPort, fp.LocalPort)
	}
}

// TestCustomMessageFactoryCalledDuringForwardFromRemotePort verifies that a custom
// PortForwardMessageFactory is called during ForwardFromRemotePort.
func TestCustomMessageFactoryCalledDuringForwardFromRemotePort(t *testing.T) {
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

	// Install custom message factory on both sides.
	clientFactory := newTestMessageFactory()
	serverFactory := newTestMessageFactory()
	clientPFS.MessageFactory = clientFactory
	serverPFS.MessageFactory = serverFactory

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Forward from remote — this sends a tcpip-forward request.
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}
	defer fp.Close()

	// Client should have called CreateRequestMessage.
	clientFactory.mu.Lock()
	clientReqCalls := len(clientFactory.requestCalls)
	clientFactory.mu.Unlock()

	if clientReqCalls == 0 {
		t.Error("expected CreateRequestMessage to be called on client factory")
	}

	// Server should have called CreateSuccessMessage (for the response).
	// Give a moment for the server to process.
	time.Sleep(50 * time.Millisecond)

	serverFactory.mu.Lock()
	serverSuccCalls := len(serverFactory.successCalls)
	serverFactory.mu.Unlock()

	if serverSuccCalls == 0 {
		t.Error("expected CreateSuccessMessage to be called on server factory")
	}
}

// TestCustomMessageFactoryCalledDuringStreamToRemotePort verifies that a custom
// PortForwardMessageFactory's CreateChannelOpenMessage is called when opening
// a direct-tcpip channel.
func TestCustomMessageFactoryCalledDuringStreamToRemotePort(t *testing.T) {
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

	// Install custom message factory on client side.
	factory := newTestMessageFactory()
	clientPFS.MessageFactory = factory

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("StreamToRemotePort failed: %v", err)
	}
	defer stream.Close()

	// Verify CreateChannelOpenMessage was called with the correct port.
	factory.mu.Lock()
	channelOpenCalls := make([]int, len(factory.channelOpenCalls))
	copy(channelOpenCalls, factory.channelOpenCalls)
	factory.mu.Unlock()

	if len(channelOpenCalls) == 0 {
		t.Fatal("expected CreateChannelOpenMessage to be called")
	}
	if channelOpenCalls[0] != echoPort {
		t.Errorf("CreateChannelOpenMessage port = %d, want %d", channelOpenCalls[0], echoPort)
	}

	// Verify data still flows.
	testData := []byte("message factory test")
	_, err = stream.Write(testData)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	buf := make([]byte, len(testData))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", string(buf), string(testData))
	}
}

// TestDefaultFactoriesMatchExistingBehavior verifies that the default factories
// produce the same results as the hardcoded behavior before factories were added.
func TestDefaultFactoriesMatchExistingBehavior(t *testing.T) {
	// Test default listener factory.
	factory := &defaultTCPListenerFactory{}
	ln, err := factory.CreateTCPListener(8080, "127.0.0.1", 0, true)
	if err != nil {
		t.Fatalf("CreateTCPListener failed: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	if addr.Port == 0 {
		t.Error("expected non-zero port from dynamic allocation")
	}
	if addr.IP.String() != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %s", addr.IP.String())
	}

	// Test default message factory.
	msgFactory := &defaultPortForwardMessageFactory{}

	reqMsg := msgFactory.CreateRequestMessage(8080)
	if reqMsg == nil {
		t.Fatal("CreateRequestMessage returned nil")
	}

	succMsg := msgFactory.CreateSuccessMessage(8080)
	if succMsg == nil {
		t.Fatal("CreateSuccessMessage returned nil")
	}

	openMsg := msgFactory.CreateChannelOpenMessage(8080)
	if openMsg == nil {
		t.Fatal("CreateChannelOpenMessage returned nil")
	}
}

// TestListenerFactoryOnServerSideHandleForwardRequest verifies that the server-side
// listener factory is used in handleForwardRequest (tcpip-forward processing).
func TestListenerFactoryOnServerSideHandleForwardRequest(t *testing.T) {
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

	// Install custom listener factory on server side.
	serverFactory := newTestListenerFactory()
	serverPFS.ListenerFactory = serverFactory

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// ForwardFromRemotePort triggers a tcpip-forward request to the server.
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	if err != nil {
		t.Fatalf("ForwardFromRemotePort failed: %v", err)
	}
	defer fp.Close()

	// The server should have used the listener factory to create its listener.
	calls := serverFactory.getCalls()
	if len(calls) == 0 {
		t.Fatal("expected server listener factory to be called during tcpip-forward")
	}
	if !calls[0].CanChangeLocalPort {
		t.Error("expected CanChangeLocalPort=true for server listener")
	}
}
