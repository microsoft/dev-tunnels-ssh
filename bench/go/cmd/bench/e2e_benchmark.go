// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/tcp"
)

// --- Multi-channel throughput benchmark ---

func multiChannelScenarios() []benchmarkScenario {
	return []benchmarkScenario{
		{
			name:     "multichannel-10",
			category: "session-multichannel",
			tags:     map[string]string{"channels": "10"},
			run:      runMultiChannelBenchmark,
			verify:   verifyMultiChannel,
		},
	}
}

func runMultiChannelBenchmark(runs int) []metric {
	const numChannels = 10

	client, server, err := createSessionPair(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating session pair: %v\n", err)
		return nil
	}
	defer client.Close()
	defer server.Close()

	type channelPair struct {
		clientCh *ssh.Channel
		serverCh *ssh.Channel
	}

	pairs := make([]channelPair, numChannels)
	for i := 0; i < numChannels; i++ {
		clientCh, serverCh, err := openChannel(&client.Session, &server.Session)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening channel %d: %v\n", i, err)
			return nil
		}
		serverCh.SetDataReceivedHandler(func(data []byte) {
			serverCh.AdjustWindow(uint32(len(data)))
		})
		pairs[i] = channelPair{clientCh: clientCh, serverCh: serverCh}
	}

	const chunkSize = 32 * 1024
	data := make([]byte, chunkSize)
	rand.Read(data)

	ctx := context.Background()
	const benchDuration = 2 * time.Second

	byteRates := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		var totalMessages int64
		start := time.Now()

		for time.Since(start) < benchDuration {
			var wg sync.WaitGroup
			for c := 0; c < numChannels; c++ {
				wg.Add(1)
				ch := pairs[c].clientCh
				go func() {
					defer wg.Done()
					ch.Send(ctx, data)
				}()
			}
			wg.Wait()
			totalMessages += int64(numChannels)
		}

		elapsed := time.Since(start)
		seconds := elapsed.Seconds()
		if seconds > 0 {
			totalBytes := float64(totalMessages) * chunkSize
			byteRates = append(byteRates, totalBytes/seconds/(1024*1024))
		}

		fmt.Print(".")
	}

	for i := 0; i < numChannels; i++ {
		pairs[i].clientCh.Close()
	}

	return []metric{
		{Name: "Aggregate throughput", Unit: "MB/s", Values: byteRates, HigherIsBetter: true},
	}
}

// --- E2E benchmarks ---

func e2eScenarios() []benchmarkScenario {
	type pfConfig struct {
		name          string
		listenAddress string
		hostAddress   string
		addressTag    string
	}
	pfConfigs := []pfConfig{
		{"portforward-ipv4", "127.0.0.1", "127.0.0.1", "ipv4"},
		{"portforward-ipv4-localhost", "127.0.0.1", "localhost", "ipv4"},
		{"portforward-ipv6", "::1", "::1", "ipv6"},
		{"portforward-ipv6-localhost", "::1", "localhost", "ipv6"},
	}

	scenarios := make([]benchmarkScenario, 0, len(pfConfigs)+1)
	for _, cfg := range pfConfigs {
		cfg := cfg // capture loop variable
		scenarios = append(scenarios, benchmarkScenario{
			name:     cfg.name,
			category: "e2e-portforward",
			tags:     map[string]string{"address": cfg.addressTag, "host": cfg.hostAddress},
			run: func(runs int) []metric {
				return runPortForwardBenchmark(runs, cfg.listenAddress, cfg.hostAddress)
			},
			verify: func() error {
				return verifyPortForward(cfg.listenAddress, cfg.hostAddress)
			},
		})
	}
	scenarios = append(scenarios, benchmarkScenario{
		name:     "reconnect",
		category: "e2e-reconnect",
		tags:     map[string]string{},
		run:      runReconnectBenchmark,
		verify:   verifyReconnect,
	})
	return scenarios
}

// startEchoServer starts a TCP echo server on the given address and returns the listener and port.
func startEchoServer(listenAddress string) (net.Listener, int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(listenAddress, "0"))
	if err != nil {
		return nil, 0, err
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
	return ln, port, nil
}

// createPortForwardSessionPair creates a connected client/server session pair
// with the PortForwardingService enabled on both sides.
func createPortForwardSessionPair() (*ssh.ClientSession, *ssh.ServerSession, error) {
	clientStream, serverStream, tcpCleanup, err := newTCPPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create TCP pipe: %w", err)
	}
	defer tcpCleanup()

	clientConfig := ssh.NewDefaultConfig()
	clientConfig.KeyRotationThreshold = 0
	tcp.AddPortForwardingService(clientConfig)

	serverConfig := ssh.NewDefaultConfig()
	serverConfig.KeyRotationThreshold = 0
	tcp.AddPortForwardingService(serverConfig)

	hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		return nil, nil, fmt.Errorf("generate host key: %w", err)
	}

	client := ssh.NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := ssh.NewServerSession(serverConfig)
	server.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}
	server.OnRequest = func(args *ssh.RequestEventArgs) {
		args.IsAuthorized = true
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

	// Authenticate the client session (required before session requests work with encryption).
	ok, err := client.Authenticate(ctx, &ssh.ClientCredentials{Username: "benchmark"})
	if err != nil {
		return nil, nil, fmt.Errorf("client authenticate: %w", err)
	}
	if !ok {
		return nil, nil, fmt.Errorf("client authentication rejected")
	}

	return client, server, nil
}

// runPortForwardBenchmark measures real TCP port-forward connect time using
// the PortForwardingService, matching the C#/TS benchmark pattern.
func runPortForwardBenchmark(runs int, listenAddress, hostAddress string) []metric {
	// Start an echo server as the forwarding target.
	echoLn, echoPort, err := startEchoServer(listenAddress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting echo server: %v\n", err)
		return nil
	}
	defer echoLn.Close()

	timesMs := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		// Create a fresh session pair per run to avoid state accumulation.
		client, server, err := createPortForwardSessionPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating session pair: %v\n", err)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		// Get port forwarding service on the client side.
		// ForwardFromRemotePort on the client sends a tcpip-forward request to the server,
		// which the server PFS handles automatically.
		clientPFS := tcp.GetPortForwardingService(&client.Session)
		if clientPFS == nil {
			cancel()
			client.Close()
			server.Close()
			fmt.Fprintf(os.Stderr, "Error getting port forwarding service\n")
			continue
		}

		// Request remote (server) to listen on a dynamic port and forward back to our echo server.
		forwarder, err := clientPFS.ForwardFromRemotePort(ctx, listenAddress, 0, hostAddress, echoPort)
		if err != nil || forwarder == nil {
			cancel()
			client.Close()
			server.Close()
			fmt.Fprintf(os.Stderr, "Error forwarding port: %v\n", err)
			continue
		}

		// Give the server a moment to start listening.
		time.Sleep(50 * time.Millisecond)

		// Time the TCP connect to the server's forwarded port.
		start := time.Now()

		conn, err := net.DialTimeout("tcp", net.JoinHostPort(listenAddress, fmt.Sprintf("%d", forwarder.RemotePort)), 5*time.Second)
		if err != nil {
			cancel()
			client.Close()
			server.Close()
			fmt.Fprintf(os.Stderr, "Error connecting to forwarded port: %v\n", err)
			continue
		}
		conn.Close()

		elapsed := time.Since(start)
		timesMs = append(timesMs, float64(elapsed.Nanoseconds())/1e6)
		fmt.Print(".")

		cancel()
		client.Close()
		server.Close()
	}

	return []metric{
		{Name: "Connect time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}

// runReconnectBenchmark measures reconnection time.
func runReconnectBenchmark(runs int) []metric {
	timesMs := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		clientStream, serverStream, tcpCleanup1, err := newTCPPipe()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating TCP pipe: %v\n", err)
			continue
		}

		clientConfig := ssh.NewDefaultConfigWithReconnect()
		clientConfig.KeyRotationThreshold = 0
		serverConfig := ssh.NewDefaultConfigWithReconnect()
		serverConfig.KeyRotationThreshold = 0

		hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating host key: %v\n", err)
			continue
		}

		client := ssh.NewClientSession(clientConfig)
		client.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		}

		server := ssh.NewServerSession(serverConfig)
		server.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		}
		server.Credentials = &ssh.ServerCredentials{
			PublicKeys: []ssh.KeyPair{hostKey},
		}

		reconnectableSessions := ssh.NewReconnectableSessions()
		server.ReconnectableSessions = reconnectableSessions

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

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

		if clientErr != nil || serverErr != nil {
			cancel()
			tcpCleanup1()
			fmt.Fprintf(os.Stderr, "Initial connect error: client=%v server=%v\n", clientErr, serverErr)
			continue
		}

		reconnectableSessions.Add(server)

		// Wait for reconnect to be enabled on both sides.
		if err := ssh.WaitUntilReconnectEnabled(ctx, &client.Session, &server.Session); err != nil {
			cancel()
			tcpCleanup1()
			fmt.Fprintf(os.Stderr, "WaitUntilReconnectEnabled error: %v\n", err)
			continue
		}

		// Disconnect by closing the underlying streams.
		clientStream.Close()
		serverStream.Close()

		// Wait briefly for disconnect to be processed.
		time.Sleep(50 * time.Millisecond)

		// Create new streams for reconnection.
		newClientStream, newServerStream, tcpCleanup2, err := newTCPPipe()
		if err != nil {
			cancel()
			tcpCleanup1()
			fmt.Fprintf(os.Stderr, "Error creating reconnect TCP pipe: %v\n", err)
			continue
		}

		// Set up new server session to accept the reconnection.
		newServerConfig := ssh.NewDefaultConfigWithReconnect()
		newServerConfig.KeyRotationThreshold = 0
		newServer := ssh.NewServerSession(newServerConfig)
		newServer.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		}
		newServer.Credentials = &ssh.ServerCredentials{
			PublicKeys: []ssh.KeyPair{hostKey},
		}
		newServer.ReconnectableSessions = reconnectableSessions

		// Time the reconnection.
		start := time.Now()

		wg.Add(1)
		go func() {
			defer wg.Done()
			serverErr = newServer.Connect(ctx, newServerStream)
		}()

		clientErr = client.Reconnect(ctx, newClientStream)
		wg.Wait()

		elapsed := time.Since(start)
		cancel()

		if clientErr != nil {
			fmt.Fprintf(os.Stderr, "Reconnect error: %v\n", clientErr)
			client.Close()
			newServer.Close()
			tcpCleanup1()
			tcpCleanup2()
			continue
		}

		timesMs = append(timesMs, float64(elapsed.Nanoseconds())/1e6)
		fmt.Print(".")

		client.Close()
		newServer.Close()
		tcpCleanup1()
		tcpCleanup2()
	}

	return []metric{
		{Name: "Reconnect time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}

// --- Verification functions ---

func verifyMultiChannel() error {
	client, server, err := createSessionPair(false)
	if err != nil {
		return fmt.Errorf("create session pair: %w", err)
	}
	defer client.Close()
	defer server.Close()

	clientCh, serverCh, err := openChannel(&client.Session, &server.Session)
	if err != nil {
		return fmt.Errorf("open channel: %w", err)
	}

	testData := []byte("multichannel verify")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var received []byte
	done := make(chan struct{})
	serverCh.SetDataReceivedHandler(func(data []byte) {
		received = append(received, data...)
		serverCh.AdjustWindow(uint32(len(data)))
		if len(received) >= len(testData) {
			close(done)
		}
	})

	if err := clientCh.Send(ctx, testData); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	select {
	case <-done:
	case <-ctx.Done():
		return fmt.Errorf("timeout waiting for data")
	}

	if !bytes.Equal(received, testData) {
		return fmt.Errorf("received data does not match sent data")
	}
	return nil
}

func verifyPortForward(listenAddress, hostAddress string) error {
	echoLn, echoPort, err := startEchoServer(listenAddress)
	if err != nil {
		return fmt.Errorf("start echo server: %w", err)
	}
	defer echoLn.Close()

	client, server, err := createPortForwardSessionPair()
	if err != nil {
		return fmt.Errorf("create session pair: %w", err)
	}
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientPFS := tcp.GetPortForwardingService(&client.Session)
	if clientPFS == nil {
		return fmt.Errorf("no port forwarding service")
	}

	forwarder, err := clientPFS.ForwardFromRemotePort(ctx, listenAddress, 0, hostAddress, echoPort)
	if err != nil || forwarder == nil {
		return fmt.Errorf("forward port: %w", err)
	}

	time.Sleep(50 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(listenAddress, fmt.Sprintf("%d", forwarder.RemotePort)), 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to forwarded port: %w", err)
	}
	defer conn.Close()

	testData := []byte("port forward verify")
	if _, err := conn.Write(testData); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read echo: %w", err)
	}

	if !bytes.Equal(buf, testData) {
		return fmt.Errorf("echo data does not match sent data")
	}
	return nil
}

func verifyReconnect() error {
	clientStream, serverStream, tcpCleanup1, err := newTCPPipe()
	if err != nil {
		return fmt.Errorf("create TCP pipe: %w", err)
	}

	clientConfig := ssh.NewDefaultConfigWithReconnect()
	serverConfig := ssh.NewDefaultConfigWithReconnect()

	hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		tcpCleanup1()
		return fmt.Errorf("generate host key: %w", err)
	}

	client := ssh.NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := ssh.NewServerSession(serverConfig)
	server.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	server.Credentials = &ssh.ServerCredentials{PublicKeys: []ssh.KeyPair{hostKey}}

	reconnectableSessions := ssh.NewReconnectableSessions()
	server.ReconnectableSessions = reconnectableSessions

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var clientErr, serverErr error
	wg.Add(2)
	go func() { defer wg.Done(); clientErr = client.Connect(ctx, clientStream) }()
	go func() { defer wg.Done(); serverErr = server.Connect(ctx, serverStream) }()
	wg.Wait()

	if clientErr != nil || serverErr != nil {
		tcpCleanup1()
		return fmt.Errorf("initial connect: client=%v server=%v", clientErr, serverErr)
	}

	reconnectableSessions.Add(server)

	if err := ssh.WaitUntilReconnectEnabled(ctx, &client.Session, &server.Session); err != nil {
		tcpCleanup1()
		return fmt.Errorf("wait for reconnect: %w", err)
	}

	clientStream.Close()
	serverStream.Close()
	time.Sleep(50 * time.Millisecond)

	newClientStream, newServerStream, tcpCleanup2, err := newTCPPipe()
	if err != nil {
		tcpCleanup1()
		return fmt.Errorf("create reconnect TCP pipe: %w", err)
	}

	newServer := ssh.NewServerSession(ssh.NewDefaultConfigWithReconnect())
	newServer.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	newServer.Credentials = &ssh.ServerCredentials{PublicKeys: []ssh.KeyPair{hostKey}}
	newServer.ReconnectableSessions = reconnectableSessions

	wg.Add(1)
	go func() { defer wg.Done(); serverErr = newServer.Connect(ctx, newServerStream) }()
	clientErr = client.Reconnect(ctx, newClientStream)
	wg.Wait()

	defer func() {
		client.Close()
		newServer.Close()
		tcpCleanup1()
		tcpCleanup2()
	}()

	if clientErr != nil {
		return fmt.Errorf("reconnect: %w", clientErr)
	}

	// Verify session is usable after reconnect — open channel and send data.
	clientCh, serverCh, err := openChannel(&client.Session, &newServer.Session)
	if err != nil {
		return fmt.Errorf("open channel after reconnect: %w", err)
	}

	testData := []byte("reconnect verify")
	var received []byte
	done := make(chan struct{})
	serverCh.SetDataReceivedHandler(func(data []byte) {
		received = append(received, data...)
		serverCh.AdjustWindow(uint32(len(data)))
		if len(received) >= len(testData) {
			close(done)
		}
	})

	if err := clientCh.Send(ctx, testData); err != nil {
		return fmt.Errorf("send after reconnect: %w", err)
	}

	select {
	case <-done:
	case <-ctx.Done():
		return fmt.Errorf("timeout waiting for data after reconnect")
	}

	if !bytes.Equal(received, testData) {
		return fmt.Errorf("received data does not match after reconnect")
	}
	return nil
}
