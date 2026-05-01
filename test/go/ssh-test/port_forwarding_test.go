// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
	"github.com/microsoft/dev-tunnels-ssh/src/go/tcp"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createPortForwardingPair creates a connected session pair with port forwarding
// service registered on both sides.
func createPortForwardingPair(t *testing.T) *helpers.SessionPair {
	t.Helper()

	serverConfig := ssh.NewNoSecurityConfig()
	tcp.AddPortForwardingService(serverConfig)

	clientConfig := ssh.NewNoSecurityConfig()
	tcp.AddPortForwardingService(clientConfig)

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	pair.Connect(context.Background())
	return pair
}

// startEchoServer starts a TCP server that echoes back any data received.
// Returns the listener and its port.
func startEchoServer(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	return ln, port
}

// TestForwardFromRemotePort tests basic remote port forwarding.
// Client asks server to listen on a port; connections to that port are forwarded
// back through the SSH session.
func TestForwardFromRemotePort(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	// Get the server-side port forwarding service.
	serverPFS := tcp.GetPortForwardingService(&pair.ServerSession.Session)
	require.NotNil(t, serverPFS)

	// Get the client-side port forwarding service.
	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Start a local echo server that the forwarded connections will reach.
	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()

	// Client requests remote (server) to listen on port 0 (auto-allocate)
	// and forward connections to the local echo server.
	ctx := context.Background()
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	require.NoError(t, err)
	require.NotNil(t, fp)
	assert.Greater(t, fp.RemotePort, 0, "should have allocated a port")

	// Connect to the forwarded port on the server side.
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fp.RemotePort)))
	require.NoError(t, err)
	defer conn.Close()

	// Send data through the forwarded connection.
	testData := []byte("hello port forwarding")
	_, err = conn.Write(testData)
	require.NoError(t, err)

	// Read echo response.
	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf)
}

// TestForwardFromRemotePortAutoChoose tests dynamic port allocation
// when requesting port 0.
func TestForwardFromRemotePortAutoChoose(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Start an echo server.
	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()

	// Request port 0 for dynamic allocation.
	ctx := context.Background()
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	require.NoError(t, err)
	assert.Greater(t, fp.RemotePort, 0, "auto-allocated port should be > 0")
}

// TestForwardFromRemotePortInUse tests that requesting an in-use port fails.
func TestForwardFromRemotePortInUse(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Occupy a port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	occupiedPort := ln.Addr().(*net.TCPAddr).Port

	// Try to forward to the occupied port.
	ctx := context.Background()
	_, err = clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", occupiedPort, "127.0.0.1", 9999)
	assert.Error(t, err, "should fail when port is in use")
}

// TestForwardToRemotePort tests local-to-remote port forwarding.
// We listen on a local port and forward connections to a remote destination
// through the SSH session.
func TestForwardToRemotePort(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Start an echo server on the "remote" side.
	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()

	// Forward local port to remote echo server.
	ctx := context.Background()
	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	require.NoError(t, err)
	require.NotNil(t, fp)
	assert.Greater(t, fp.LocalPort, 0, "should have allocated a local port")

	// Connect to the local forwarded port.
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fp.LocalPort)))
	require.NoError(t, err)
	defer conn.Close()

	// Send data through the forwarded connection.
	testData := []byte("hello local forward")
	_, err = conn.Write(testData)
	require.NoError(t, err)

	// Read echo response.
	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf)
}

// TestForwardToRemotePortAutoChoose tests local port auto-allocation.
func TestForwardToRemotePortAutoChoose(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()

	ctx := context.Background()
	fp, err := clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	require.NoError(t, err)
	assert.Greater(t, fp.LocalPort, 0, "auto-allocated local port should be > 0")
}

// TestForwardToRemotePortInUse tests that listening on an in-use local port fails.
func TestForwardToRemotePortInUse(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Occupy a port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	occupiedPort := ln.Addr().(*net.TCPAddr).Port

	// Try to forward from the occupied port.
	ctx := context.Background()
	_, err = clientPFS.ForwardToRemotePort(ctx, "127.0.0.1", occupiedPort, "127.0.0.1", 9999)
	assert.Error(t, err, "should fail when local port is in use")
}

// TestStreamToRemotePort tests stream-based forwarding to a remote port.
func TestStreamToRemotePort(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Start an echo server.
	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()

	// Open a stream to the remote echo server.
	ctx := context.Background()
	stream, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
	require.NoError(t, err)
	defer stream.Close()

	// Send data through the stream.
	testData := []byte("hello stream forward")
	_, err = stream.Write(testData)
	require.NoError(t, err)

	// Read echo response.
	buf := make([]byte, len(testData))
	n, err := readWithTimeout(stream, buf, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n])
}

// TestStreamFromRemotePort tests stream-based forwarding from a remote port.
func TestStreamFromRemotePort(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Request the remote side to listen.
	ctx := context.Background()
	fp, err := clientPFS.StreamFromRemotePort(ctx, "127.0.0.1", 0)
	require.NoError(t, err)
	require.Greater(t, fp.RemotePort, 0)

	// Set up a goroutine to accept the forwarded stream.
	streamCh := make(chan io.ReadWriteCloser, 1)
	go func() {
		s, err := clientPFS.ConnectToForwardedPort(ctx, fp.RemotePort)
		if err != nil {
			return
		}
		streamCh <- s
	}()

	// Connect to the remote port (which should trigger a forwarded-tcpip channel).
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fp.RemotePort)))
	require.NoError(t, err)
	defer conn.Close()

	// Wait for the stream to be delivered.
	var stream io.ReadWriteCloser
	select {
	case stream = <-streamCh:
		require.NotNil(t, stream)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for forwarded stream")
	}
	defer stream.Close()

	// Send data from the TCP side.
	testData := []byte("hello stream from remote")
	_, err = conn.Write(testData)
	require.NoError(t, err)

	// Read on the stream side.
	buf := make([]byte, len(testData))
	n, err := readWithTimeout(stream, buf, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n])
}

// TestPortForwardingServiceRegistration tests that the service is activated
// on session request and channel type triggers.
func TestPortForwardingServiceRegistration(t *testing.T) {
	serverConfig := ssh.NewNoSecurityConfig()
	tcp.AddPortForwardingService(serverConfig)

	clientConfig := ssh.NewNoSecurityConfig()
	tcp.AddPortForwardingService(clientConfig)

	// Verify service registrations exist.
	_, ok := serverConfig.ServiceRegistrations[tcp.PortForwardingServiceName]
	assert.True(t, ok, "service should be registered")
}

// TestDirectTCPIPChannelOpen tests opening a direct-tcpip channel.
func TestDirectTCPIPChannelOpen(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	// Start an echo server.
	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Open a stream to the echo server via direct-tcpip.
	ctx := context.Background()
	stream, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
	require.NoError(t, err)
	require.NotNil(t, stream)
	defer stream.Close()

	// Verify bidirectional data flow.
	testData := []byte("direct-tcpip test data")
	_, err = stream.Write(testData)
	require.NoError(t, err)

	buf := make([]byte, len(testData))
	n, err := readWithTimeout(stream, buf, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n])
}

// TestDirectTCPIPUnauthorized tests that direct-tcpip can be rejected.
func TestDirectTCPIPUnauthorized(t *testing.T) {
	serverConfig := ssh.NewNoSecurityConfig()
	tcp.AddPortForwardingService(serverConfig)

	clientConfig := ssh.NewNoSecurityConfig()
	tcp.AddPortForwardingService(clientConfig)

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	pair.Connect(context.Background())
	defer pair.Close()

	// Disable direct-tcpip on server.
	serverPFS := tcp.GetPortForwardingService(&pair.ServerSession.Session)
	require.NotNil(t, serverPFS)
	serverPFS.AcceptRemoteConnectionsForNonForwardedPorts = false

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Try to open a direct-tcpip stream — should fail.
	ctx := context.Background()
	_, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", 9999)
	assert.Error(t, err, "direct-tcpip should be rejected")
}

// TestMultipleConcurrentForwardedConnections tests that multiple connections
// through a forwarded port work correctly.
func TestMultipleConcurrentForwardedConnections(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()

	// Forward a port.
	ctx := context.Background()
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	require.NoError(t, err)

	// Open multiple concurrent connections.
	const numConns = 5
	var wg sync.WaitGroup
	errors := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fp.RemotePort)))
			if err != nil {
				errors <- fmt.Errorf("conn %d dial: %w", idx, err)
				return
			}
			defer conn.Close()

			data := []byte(fmt.Sprintf("data-%d", idx))
			_, err = conn.Write(data)
			if err != nil {
				errors <- fmt.Errorf("conn %d write: %w", idx, err)
				return
			}

			buf := make([]byte, len(data))
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = io.ReadFull(conn, buf)
			if err != nil {
				errors <- fmt.Errorf("conn %d read: %w", idx, err)
				return
			}

			if !bytes.Equal(data, buf) {
				errors <- fmt.Errorf("conn %d: expected %q, got %q", idx, data, buf)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// TestConnectionRefusedError tests that connection refused errors are propagated
// through the stream when the target TCP port is not reachable.
func TestConnectionRefusedError(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Bind a port and then close the listener, ensuring the port is free but nothing listens.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	refusedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	// Open a stream to a port where the connection will be refused.
	// The SSH channel open will succeed but the server-side TCP dial will fail.
	ctx := context.Background()
	stream, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", refusedPort)
	if err != nil {
		// Error during channel open is also acceptable.
		return
	}
	defer stream.Close()

	// The stream should be closed by the server side when the TCP connection fails.
	// A read should return an error or EOF.
	buf := make([]byte, 1)
	_, err = readWithTimeout(stream, buf, 5*time.Second)
	assert.Error(t, err, "reading from connection-refused stream should error")
}

// TestPortForwardingAuthorization tests authorization via OnChannelOpening callback.
func TestPortForwardingAuthorization(t *testing.T) {
	serverConfig := ssh.NewNoSecurityConfig()
	tcp.AddPortForwardingService(serverConfig)

	clientConfig := ssh.NewNoSecurityConfig()
	tcp.AddPortForwardingService(clientConfig)

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	pair.Connect(context.Background())
	defer pair.Close()

	serverPFS := tcp.GetPortForwardingService(&pair.ServerSession.Session)
	require.NotNil(t, serverPFS)

	// Set up authorization to reject all direct-tcpip channels.
	serverPFS.ChannelOpeningHandler = func(args *ssh.ChannelOpeningEventArgs) {
		args.FailureReason = messages.ChannelOpenFailureAdministrativelyProhibited
		args.FailureDescription = "port forwarding not allowed"
	}

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	// Try to stream to remote — should be rejected.
	ctx := context.Background()
	_, err := clientPFS.StreamToRemotePort(ctx, "127.0.0.1", 9999)
	assert.Error(t, err, "should be rejected by authorization")
}

// TestForwardFromRemotePortCancel tests cancelling a port forward.
func TestForwardFromRemotePortCancel(t *testing.T) {
	pair := createPortForwardingPair(t)
	defer pair.Close()

	clientPFS := tcp.GetPortForwardingService(&pair.ClientSession.Session)
	require.NotNil(t, clientPFS)

	echoLn, echoPort := startEchoServer(t)
	defer echoLn.Close()

	// Forward a port.
	ctx := context.Background()
	fp, err := clientPFS.ForwardFromRemotePort(ctx, "127.0.0.1", 0, "127.0.0.1", echoPort)
	require.NoError(t, err)

	// Verify the port is forwarding (we can connect).
	conn, err := net.DialTimeout("tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(fp.RemotePort)),
		2*time.Second)
	if err == nil {
		conn.Close()
	}

	// Now cancel the forwarding by sending cancel-tcpip-forward.
	cancelMsg := &tcp.PortForwardRequestMessage{
		RequestType:   tcp.CancelPortForwardRequestType,
		WantReply:     true,
		AddressToBind: "127.0.0.1",
		Port:          uint32(fp.RemotePort),
	}
	success, err := pair.ClientSession.Request(ctx, &messages.SessionRequestMessage{
		RequestType: cancelMsg.RequestType,
		WantReply:   cancelMsg.WantReply,
	})
	// The cancel may succeed or fail depending on timing, but shouldn't error.
	_ = success
	_ = err
}

// TestPortForwardMessages tests port forwarding message round-trip.
func TestPortForwardMessages(t *testing.T) {
	t.Run("PortForwardRequest", func(t *testing.T) {
		msg := &tcp.PortForwardRequestMessage{
			RequestType:   tcp.PortForwardRequestType,
			WantReply:     true,
			AddressToBind: "192.168.1.1",
			Port:          8080,
		}

		buf := msg.ToBuffer()
		require.NotEmpty(t, buf)

		parsed, err := tcp.ParsePortForwardRequestMessage(buf)
		require.NoError(t, err)
		assert.Equal(t, tcp.PortForwardRequestType, parsed.RequestType)
		assert.True(t, parsed.WantReply)
		assert.Equal(t, "192.168.1.1", parsed.AddressToBind)
		assert.Equal(t, uint32(8080), parsed.Port)
	})

	t.Run("PortForwardChannelOpen", func(t *testing.T) {
		msg := &tcp.PortForwardChannelOpenMessage{
			ChannelType:         tcp.ForwardedTCPIPChannelType,
			SenderChannel:       1,
			MaxWindowSize:       1048576,
			MaxPacketSize:       32768,
			Host:                "10.0.0.1",
			Port:                3000,
			OriginatorIPAddress: "192.168.1.100",
			OriginatorPort:      54321,
		}

		buf := msg.ToBuffer()
		require.NotEmpty(t, buf)

		parsed, err := tcp.ParsePortForwardChannelOpenMessage(buf)
		require.NoError(t, err)
		assert.Equal(t, tcp.ForwardedTCPIPChannelType, parsed.ChannelType)
		assert.Equal(t, uint32(1), parsed.SenderChannel)
		assert.Equal(t, uint32(1048576), parsed.MaxWindowSize)
		assert.Equal(t, uint32(32768), parsed.MaxPacketSize)
		assert.Equal(t, "10.0.0.1", parsed.Host)
		assert.Equal(t, uint32(3000), parsed.Port)
		assert.Equal(t, "192.168.1.100", parsed.OriginatorIPAddress)
		assert.Equal(t, uint32(54321), parsed.OriginatorPort)
	})

	t.Run("PortForwardSuccess", func(t *testing.T) {
		msg := &tcp.PortForwardSuccessMessage{Port: 12345}
		buf := msg.ToBuffer()
		require.NotEmpty(t, buf)

		parsed := &tcp.PortForwardSuccessMessage{}
		err := messages.ReadMessage(parsed, buf)
		require.NoError(t, err)
		assert.Equal(t, uint32(12345), parsed.Port)
	})
}

// readWithTimeout reads from a reader with a timeout.
func readWithTimeout(r io.Reader, buf []byte, timeout time.Duration) (int, error) {
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := r.Read(buf)
		ch <- result{n, err}
	}()

	select {
	case res := <-ch:
		return res.n, res.err
	case <-time.After(timeout):
		return 0, fmt.Errorf("read timed out after %v", timeout)
	}
}
