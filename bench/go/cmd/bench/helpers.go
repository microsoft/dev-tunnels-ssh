// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// defaultSocketBufferSize is 2 * DefaultMaxPacketSize (32KB) = 64KB,
// matching the C# and TypeScript implementations.
const defaultSocketBufferSize = 2 * 0x8000

// configureSocket sets TCP_NODELAY and 64KB send/receive buffers on a TCP connection.
func configureSocket(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tcpConn.SetNoDelay(true)
	tcpConn.SetReadBuffer(defaultSocketBufferSize)
	tcpConn.SetWriteBuffer(defaultSocketBufferSize)
}

// newTCPPipe creates a pair of connected TCP loopback connections,
// matching the transport used by C# and TypeScript benchmarks.
func newTCPPipe() (io.ReadWriteCloser, io.ReadWriteCloser, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listen: %w", err)
	}

	var serverConn net.Conn
	var acceptErr error
	accepted := make(chan struct{})
	go func() {
		serverConn, acceptErr = ln.Accept()
		if serverConn != nil {
			configureSocket(serverConn)
		}
		close(accepted)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		return nil, nil, nil, fmt.Errorf("dial: %w", err)
	}
	configureSocket(clientConn)

	<-accepted
	if acceptErr != nil {
		clientConn.Close()
		ln.Close()
		return nil, nil, nil, fmt.Errorf("accept: %w", acceptErr)
	}

	cleanup := func() { ln.Close() }
	return clientConn, serverConn, cleanup, nil
}

// latencyStream wraps a stream and adds a delay to each write, matching
// the C# SlowStream and TS SlowStream behavior: writes return immediately
// (data is queued), and the actual write to the underlying stream happens
// after the delay in a single background drainer goroutine. This models
// real TCP behavior where Write() returns as soon as data enters the kernel
// send buffer and the network adds latency to delivery. A single drainer
// guarantees FIFO write ordering.
type latencyStream struct {
	stream    io.ReadWriteCloser
	delay     time.Duration
	queue     chan latencyItem
	closeCh   chan struct{}
	closeOnce sync.Once
	done      chan struct{}
}

type latencyItem struct {
	data      []byte
	deliverAt time.Time
}

func newLatencyStream(stream io.ReadWriteCloser, delay time.Duration) *latencyStream {
	s := &latencyStream{
		stream:  stream,
		delay:   delay,
		queue:   make(chan latencyItem, 256),
		closeCh: make(chan struct{}),
		done:    make(chan struct{}),
	}
	go s.drainer()
	return s
}

func (s *latencyStream) drainer() {
	defer close(s.done)
	for {
		select {
		case item := <-s.queue:
			if wait := time.Until(item.deliverAt); wait > 0 {
				time.Sleep(wait)
			}
			s.stream.Write(item.data)
		case <-s.closeCh:
			return
		}
	}
}

func (s *latencyStream) Read(b []byte) (int, error) {
	return s.stream.Read(b)
}

func (s *latencyStream) Write(b []byte) (int, error) {
	data := make([]byte, len(b))
	copy(data, b)
	select {
	case s.queue <- latencyItem{data: data, deliverAt: time.Now().Add(s.delay)}:
		return len(b), nil
	case <-s.closeCh:
		return 0, io.ErrClosedPipe
	}
}

func (s *latencyStream) Close() error {
	s.closeOnce.Do(func() { close(s.closeCh) })
	<-s.done
	return s.stream.Close()
}

// createSessionPair creates a connected client+server session pair via TCP loopback.
func createSessionPair(encrypted bool) (*ssh.ClientSession, *ssh.ServerSession, error) {
	clientStream, serverStream, cleanup, err := newTCPPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create TCP pipe: %w", err)
	}
	client, server, err := createSessionPairWithStreams(clientStream, serverStream, encrypted)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	// The TCP listener is no longer needed once the connection is established.
	cleanup()
	return client, server, nil
}

// createSessionPairWithStreams creates a connected session pair using provided streams.
func createSessionPairWithStreams(clientStream, serverStream io.ReadWriteCloser, encrypted bool) (*ssh.ClientSession, *ssh.ServerSession, error) {
	var clientConfig, serverConfig *ssh.SessionConfig
	if encrypted {
		clientConfig = ssh.NewDefaultConfig()
		serverConfig = ssh.NewDefaultConfig()
	} else {
		clientConfig = ssh.NewNoSecurityConfig()
		serverConfig = ssh.NewNoSecurityConfig()
	}
	clientConfig.KeyRotationThreshold = 0
	serverConfig.KeyRotationThreshold = 0

	client := ssh.NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := ssh.NewServerSession(serverConfig)
	server.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	if encrypted {
		hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
		if err != nil {
			return nil, nil, fmt.Errorf("generate host key: %w", err)
		}
		server.Credentials = &ssh.ServerCredentials{
			PublicKeys: []ssh.KeyPair{hostKey},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var clientErr, serverErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = client.Connect(ctx, clientStream)
	}()
	go func() {
		defer wg.Done()
		serverErr = server.Connect(ctx, serverStream)
	}()
	wg.Wait()

	if clientErr != nil {
		return nil, nil, fmt.Errorf("client connect: %w", clientErr)
	}
	if serverErr != nil {
		return nil, nil, fmt.Errorf("server connect: %w", serverErr)
	}

	return client, server, nil
}

// openChannel opens a channel between client and server sessions.
func openChannel(client *ssh.Session, server *ssh.Session) (*ssh.Channel, *ssh.Channel, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var clientCh, serverCh *ssh.Channel
	var openErr, acceptErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, openErr = client.OpenChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		serverCh, acceptErr = server.AcceptChannel(ctx)
	}()
	wg.Wait()

	if openErr != nil {
		return nil, nil, fmt.Errorf("open channel: %w", openErr)
	}
	if acceptErr != nil {
		return nil, nil, fmt.Errorf("accept channel: %w", acceptErr)
	}

	return clientCh, serverCh, nil
}
