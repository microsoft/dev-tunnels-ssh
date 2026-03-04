// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

// --- DuplexStream tests ---

func TestDuplexStreamBidirectional(t *testing.T) {
	s1, s2 := helpers.CreateDuplexStreams()
	defer s1.Close()
	defer s2.Close()

	testData := []byte("hello from stream1")

	// Write from s1, read from s2.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(testData))
		n, err := io.ReadFull(s2, buf)
		if err != nil {
			t.Errorf("s2 read error: %v", err)
			return
		}
		if n != len(testData) {
			t.Errorf("s2 read %d bytes, want %d", n, len(testData))
			return
		}
		if !bytes.Equal(buf, testData) {
			t.Errorf("s2 read %q, want %q", buf, testData)
		}
	}()

	_, err := s1.Write(testData)
	if err != nil {
		t.Fatalf("s1 write error: %v", err)
	}
	wg.Wait()

	// Write from s2, read from s1.
	testData2 := []byte("hello from stream2")
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(testData2))
		n, err := io.ReadFull(s1, buf)
		if err != nil {
			t.Errorf("s1 read error: %v", err)
			return
		}
		if n != len(testData2) {
			t.Errorf("s1 read %d bytes, want %d", n, len(testData2))
			return
		}
		if !bytes.Equal(buf, testData2) {
			t.Errorf("s1 read %q, want %q", buf, testData2)
		}
	}()

	_, err = s2.Write(testData2)
	if err != nil {
		t.Fatalf("s2 write error: %v", err)
	}
	wg.Wait()
}

func TestDuplexStreamLargeData(t *testing.T) {
	s1, s2 := helpers.CreateDuplexStreams()
	defer s1.Close()
	defer s2.Close()

	// Send 64KB of data.
	data := helpers.GenerateDeterministicBytes(42, 64*1024)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(data))
		_, err := io.ReadFull(s2, buf)
		if err != nil {
			t.Errorf("read error: %v", err)
			return
		}
		if !bytes.Equal(buf, data) {
			t.Error("received data does not match sent data")
		}
	}()

	_, err := s1.Write(data)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}
	wg.Wait()
}

func TestDuplexStreamCloseUnblocksRead(t *testing.T) {
	s1, s2 := helpers.CreateDuplexStreams()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 10)
		_, err := s1.Read(buf)
		done <- err
	}()

	// Close s2, which should cause s1's read to return EOF or error.
	s2.Close()

	err := <-done
	if err == nil {
		t.Error("expected error from read after close, got nil")
	}
}

func TestDuplexStreamClosedState(t *testing.T) {
	s1, s2 := helpers.CreateDuplexStreams()

	if s1.IsClosed() {
		t.Error("stream1 should not be closed initially")
	}
	if s2.IsClosed() {
		t.Error("stream2 should not be closed initially")
	}

	s1.Close()
	if !s1.IsClosed() {
		t.Error("stream1 should be closed after Close()")
	}

	s2.Close()
	if !s2.IsClosed() {
		t.Error("stream2 should be closed after Close()")
	}
}

// --- MockNetworkStream tests ---

func TestMockNetworkStreamPassthrough(t *testing.T) {
	s1, s2 := helpers.CreateDuplexStreams()
	m1 := helpers.NewMockNetworkStream(s1)
	m2 := helpers.NewMockNetworkStream(s2)
	defer m1.Close()
	defer m2.Close()

	testData := []byte("test data through mock")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(testData))
		_, err := io.ReadFull(m2, buf)
		if err != nil {
			t.Errorf("read error: %v", err)
			return
		}
		if !bytes.Equal(buf, testData) {
			t.Errorf("got %q, want %q", buf, testData)
		}
	}()

	_, err := m1.Write(testData)
	if err != nil {
		t.Fatalf("write error: %v", err)
	}
	wg.Wait()
}

func TestMockNetworkStreamDisconnect(t *testing.T) {
	s1, s2 := helpers.CreateDuplexStreams()
	m1 := helpers.NewMockNetworkStream(s1)
	m2 := helpers.NewMockNetworkStream(s2)
	defer m2.Close()

	disconnectErr := errors.New("simulated network failure")

	// Disconnect m1.
	m1.MockDisconnect(disconnectErr)

	if !m1.IsDisconnected() {
		t.Error("m1 should be disconnected after MockDisconnect")
	}

	// Reads from m1 should fail.
	buf := make([]byte, 10)
	_, err := m1.Read(buf)
	if err == nil {
		t.Error("expected error from read after disconnect, got nil")
	}
	if !errors.Is(err, disconnectErr) && err.Error() != disconnectErr.Error() {
		t.Errorf("expected disconnect error, got: %v", err)
	}

	// Writes to m1 should fail.
	_, err = m1.Write([]byte("test"))
	if err == nil {
		t.Error("expected error from write after disconnect, got nil")
	}
}

func TestMockNetworkStreamDisconnectWithDrop(t *testing.T) {
	s1, s2 := helpers.CreateDuplexStreams()
	m1 := helpers.NewMockNetworkStream(s1)
	_ = helpers.NewMockNetworkStream(s2)

	disconnectErr := errors.New("drop disconnect")

	// Disconnect with 10 bytes to drop.
	m1.MockDisconnectWithDrop(disconnectErr, 10)

	// First write of 5 bytes should succeed (within drop limit).
	n, err := m1.Write([]byte("12345"))
	if err != nil {
		t.Fatalf("expected first write to succeed, got error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes written, got %d", n)
	}

	// Second write of 10 bytes should partially succeed (5 more within drop limit).
	n, err = m1.Write([]byte("1234567890"))
	if err == nil {
		t.Error("expected error from write exceeding drop limit, got nil")
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written before error, got %d", n)
	}
}

func TestMockNetworkStreamClose(t *testing.T) {
	s1, s2 := helpers.CreateDuplexStreams()
	m1 := helpers.NewMockNetworkStream(s1)
	m2 := helpers.NewMockNetworkStream(s2)

	if m1.IsClosed() {
		t.Error("m1 should not be closed initially")
	}

	m1.Close()
	if !m1.IsClosed() {
		t.Error("m1 should be closed after Close()")
	}

	m2.Close()
	if !m2.IsClosed() {
		t.Error("m2 should be closed after Close()")
	}
}

// --- MockRandom tests ---

func TestMockRandomDeterministic(t *testing.T) {
	r1 := helpers.NewMockRandom(42)
	r2 := helpers.NewMockRandom(42)

	buf1 := make([]byte, 100)
	buf2 := make([]byte, 100)

	r1.Read(buf1)
	r2.Read(buf2)

	if !bytes.Equal(buf1, buf2) {
		t.Error("two MockRandom instances with same seed should produce identical output")
	}
}

func TestMockRandomDifferentSeeds(t *testing.T) {
	buf1 := helpers.GenerateDeterministicBytes(1, 100)
	buf2 := helpers.GenerateDeterministicBytes(2, 100)

	if bytes.Equal(buf1, buf2) {
		t.Error("different seeds should produce different output")
	}
}

func TestMockRandomReset(t *testing.T) {
	r := helpers.NewMockRandom(99)
	buf1 := make([]byte, 50)
	r.Read(buf1)

	r.Reset()
	buf2 := make([]byte, 50)
	r.Read(buf2)

	if !bytes.Equal(buf1, buf2) {
		t.Error("Reset should restore the original state")
	}
}

// --- TestKeys tests ---

func TestGenerateTestRSAKey(t *testing.T) {
	key := helpers.GenerateTestRSAKey(t)
	if key == nil {
		t.Fatal("generated RSA key should not be nil")
	}
	if key.N.BitLen() < 2048 {
		t.Errorf("RSA key bit length %d, want >= 2048", key.N.BitLen())
	}
}

func TestGenerateTestECDSAKey(t *testing.T) {
	key := helpers.GenerateTestECDSAKey(t)
	if key == nil {
		t.Fatal("generated ECDSA key should not be nil")
	}
	if key.Curve != helpers.DefaultECDSACurve() {
		t.Error("default ECDSA key should use P-384 curve")
	}
}

func TestGenerateTestKeys(t *testing.T) {
	keys := helpers.GenerateTestKeys(t)
	if keys.RSA2048 == nil {
		t.Error("RSA2048 key should not be nil")
	}
	if keys.ECDSAP256 == nil {
		t.Error("ECDSAP256 key should not be nil")
	}
	if keys.ECDSAP384 == nil {
		t.Error("ECDSAP384 key should not be nil")
	}
	if keys.ECDSAP521 == nil {
		t.Error("ECDSAP521 key should not be nil")
	}
}

// --- SessionPair tests ---

func TestNewSessionPair(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	if pair.ClientSession == nil {
		t.Error("ClientSession should not be nil")
	}
	if pair.ServerSession == nil {
		t.Error("ServerSession should not be nil")
	}
	if pair.ClientKey == nil {
		t.Error("ClientKey should not be nil")
	}
	if pair.ServerKey == nil {
		t.Error("ServerKey should not be nil")
	}

	// Verify no-security config is used by default.
	clientConfig := pair.ClientSession.Config
	if len(clientConfig.KeyExchangeAlgorithms) != 1 || clientConfig.KeyExchangeAlgorithms[0] != ssh.AlgoKexNone {
		t.Error("default client config should use no-security KEX")
	}
	serverConfig := pair.ServerSession.Config
	if len(serverConfig.KeyExchangeAlgorithms) != 1 || serverConfig.KeyExchangeAlgorithms[0] != ssh.AlgoKexNone {
		t.Error("default server config should use no-security KEX")
	}
}

func TestNewSessionPairWithConfig(t *testing.T) {
	config := &helpers.SessionPairConfig{
		ServerConfig: ssh.NewDefaultConfig(),
		ClientConfig: ssh.NewDefaultConfig(),
	}
	pair := helpers.NewSessionPairWithConfig(t, config)
	defer pair.Close()

	// Verify custom config is applied.
	if len(pair.ClientSession.Config.KeyExchangeAlgorithms) <= 1 {
		t.Error("client should have multiple KEX algorithms with default config")
	}
	if len(pair.ServerSession.Config.KeyExchangeAlgorithms) <= 1 {
		t.Error("server should have multiple KEX algorithms with default config")
	}
}

func TestSessionPairCreateStreams(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	pair.CreateStreams()

	if pair.ClientStream == nil {
		t.Error("ClientStream should not be nil after CreateStreams")
	}
	if pair.ServerStream == nil {
		t.Error("ServerStream should not be nil after CreateStreams")
	}

	// Verify streams are connected by writing data through them.
	testData := []byte("session pair stream test")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(testData))
		_, err := io.ReadFull(pair.ServerStream, buf)
		if err != nil {
			t.Errorf("server stream read error: %v", err)
			return
		}
		if !bytes.Equal(buf, testData) {
			t.Errorf("server stream got %q, want %q", buf, testData)
		}
	}()

	_, err := pair.ClientStream.Write(testData)
	if err != nil {
		t.Fatalf("client stream write error: %v", err)
	}
	wg.Wait()
}

func TestSessionPairDisconnect(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	pair.CreateStreams()

	disconnectErr := errors.New("test disconnect")
	pair.Disconnect(disconnectErr)

	if !pair.ClientStream.IsDisconnected() {
		t.Error("client stream should be disconnected")
	}
	if !pair.ServerStream.IsDisconnected() {
		t.Error("server stream should be disconnected")
	}
}

func TestSessionPairConnectAndOpenChannel(t *testing.T) {
	// This test verifies the session pair infrastructure is properly set up.
	// Full session connect and channel operations will work once
	// US-009 (channels) is implemented.
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx := context.Background()
	pair.Connect(ctx)

	// Verify both sessions are connected.
	if !pair.ClientSession.IsConnected() {
		t.Error("client should be connected after Connect")
	}
	if !pair.ServerSession.IsConnected() {
		t.Error("server should be connected after Connect")
	}

	// Verify version exchange worked.
	if pair.ClientSession.RemoteVersion == nil {
		t.Fatal("client should have remote version after connect")
	}
	if pair.ServerSession.RemoteVersion == nil {
		t.Fatal("server should have remote version after connect")
	}
	if !pair.ClientSession.RemoteVersion.IsDevTunnelsSSH() {
		t.Error("client's remote version should be dev tunnels ssh")
	}
	if !pair.ServerSession.RemoteVersion.IsDevTunnelsSSH() {
		t.Error("server's remote version should be dev tunnels ssh")
	}
}

// --- Session lifecycle tests ---

const testTimeout = 5 * time.Second

// testDisconnectReason is the disconnect reason used in session close tests.
const testDisconnectReason = messages.DisconnectByApplication

func TestCloseSessionStream(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	ctx := context.Background()
	pair.Connect(ctx)

	// Set up close event tracking with semaphores (channels).
	var serverClosedEvent, clientClosedEvent *ssh.SessionClosedEventArgs
	serverClosed := make(chan struct{})
	clientClosed := make(chan struct{})

	pair.ServerSession.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		serverClosedEvent = args
		close(serverClosed)
	}
	pair.ClientSession.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		clientClosedEvent = args
		close(clientClosed)
	}

	// Close both streams to simulate network failure.
	pair.ServerStream.Close()
	pair.ClientStream.Close()

	// Wait for both sessions to detect the closure.
	select {
	case <-serverClosed:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for server close event")
	}
	select {
	case <-clientClosed:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for client close event")
	}

	// Verify both sides report ConnectionLost.
	if serverClosedEvent == nil {
		t.Fatal("server close event should not be nil")
	}
	if serverClosedEvent.Reason != messages.DisconnectConnectionLost {
		t.Errorf("server close reason = %d, want ConnectionLost (%d)",
			serverClosedEvent.Reason, messages.DisconnectConnectionLost)
	}
	if serverClosedEvent.Err == nil {
		t.Error("server close event should have an error")
	}

	if clientClosedEvent == nil {
		t.Fatal("client close event should not be nil")
	}
	if clientClosedEvent.Reason != messages.DisconnectConnectionLost {
		t.Errorf("client close reason = %d, want ConnectionLost (%d)",
			clientClosedEvent.Reason, messages.DisconnectConnectionLost)
	}
	if clientClosedEvent.Err == nil {
		t.Error("client close event should have an error")
	}

	// Verify both sessions are closed.
	if !pair.ServerSession.IsClosed() {
		t.Error("server should be closed")
	}
	if !pair.ClientSession.IsClosed() {
		t.Error("client should be closed")
	}
	if pair.ServerSession.IsConnected() {
		t.Error("server should not be connected")
	}
	if pair.ClientSession.IsConnected() {
		t.Error("client should not be connected")
	}
}

func TestCloseServerSession(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	ctx := context.Background()
	pair.Connect(ctx)

	// Set up close event tracking.
	var serverClosedEvent, clientClosedEvent *ssh.SessionClosedEventArgs
	serverClosed := make(chan struct{})
	clientClosed := make(chan struct{})

	pair.ServerSession.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		serverClosedEvent = args
		close(serverClosed)
	}
	pair.ClientSession.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		clientClosedEvent = args
		close(clientClosed)
	}

	// Close the server session (sends disconnect message to client).
	pair.ServerSession.CloseWithReason(ctx, testDisconnectReason, "test close")

	// Wait for both sessions to close.
	select {
	case <-serverClosed:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for server close event")
	}
	select {
	case <-clientClosed:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for client close event")
	}

	// Verify server reports the reason it chose.
	if serverClosedEvent == nil {
		t.Fatal("server close event should not be nil")
	}
	if serverClosedEvent.Reason != testDisconnectReason {
		t.Errorf("server close reason = %d, want %d",
			serverClosedEvent.Reason, testDisconnectReason)
	}

	// Verify client received the disconnect reason from the server.
	if clientClosedEvent == nil {
		t.Fatal("client close event should not be nil")
	}
	if clientClosedEvent.Reason != testDisconnectReason {
		t.Errorf("client close reason = %d, want %d",
			clientClosedEvent.Reason, testDisconnectReason)
	}
	if clientClosedEvent.Err == nil {
		t.Error("client close event should have an error")
	}
}

func TestCloseClientSession(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	ctx := context.Background()
	pair.Connect(ctx)

	// Set up close event tracking.
	var serverClosedEvent, clientClosedEvent *ssh.SessionClosedEventArgs
	serverClosed := make(chan struct{})
	clientClosed := make(chan struct{})

	pair.ServerSession.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		serverClosedEvent = args
		close(serverClosed)
	}
	pair.ClientSession.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		clientClosedEvent = args
		close(clientClosed)
	}

	// Close the client session (sends disconnect message to server).
	pair.ClientSession.CloseWithReason(ctx, testDisconnectReason, "test close")

	// Wait for both sessions to close.
	select {
	case <-clientClosed:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for client close event")
	}
	select {
	case <-serverClosed:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for server close event")
	}

	// Verify client reports the reason it chose.
	if clientClosedEvent == nil {
		t.Fatal("client close event should not be nil")
	}
	if clientClosedEvent.Reason != testDisconnectReason {
		t.Errorf("client close reason = %d, want %d",
			clientClosedEvent.Reason, testDisconnectReason)
	}

	// Verify server received the disconnect reason from the client.
	if serverClosedEvent == nil {
		t.Fatal("server close event should not be nil")
	}
	if serverClosedEvent.Reason != testDisconnectReason {
		t.Errorf("server close reason = %d, want %d",
			serverClosedEvent.Reason, testDisconnectReason)
	}
	if serverClosedEvent.Err == nil {
		t.Error("server close event should have an error")
	}
}
