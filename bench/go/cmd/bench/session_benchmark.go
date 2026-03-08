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
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// --- Session setup benchmarks ---

func sessionSetupScenarios() []benchmarkScenario {
	return []benchmarkScenario{
		{
			name:     "session",
			category: "session-setup",
			tags:     map[string]string{"latency": "0"},
			run:      func(runs int) []metric { return runSessionSetupBenchmark(runs, false) },
			verify:   verifySessionSetup,
		},
		{
			name:     "session-with-latency",
			category: "session-setup",
			tags:     map[string]string{"latency": "100"},
			run:      func(runs int) []metric { return runSessionSetupBenchmark(runs, true) },
			verify:   verifySessionSetup,
		},
	}
}

func runSessionSetupBenchmark(runs int, withLatency bool) []metric {
	connectTimes := make([]float64, 0, runs)
	encryptTimes := make([]float64, 0, runs)
	authTimes := make([]float64, 0, runs)
	channelTimes := make([]float64, 0, runs)
	totalTimes := make([]float64, 0, runs)
	latencies := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		// Create listener + host key outside the timed region (matching C#/TS
		// where the server is already listening before timing starts).
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating listener: %v\n", err)
			continue
		}

		config := ssh.NewDefaultConfigWithReconnect()
		config.KeyRotationThreshold = 0

		hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
		if err != nil {
			ln.Close()
			fmt.Fprintf(os.Stderr, "Error generating host key: %v\n", err)
			continue
		}

		client := ssh.NewClientSession(config)
		client.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		}

		serverConfig := ssh.NewDefaultConfigWithReconnect()
		serverConfig.KeyRotationThreshold = 0
		server := ssh.NewServerSession(serverConfig)
		server.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		}
		server.Credentials = &ssh.ServerCredentials{
			PublicKeys: []ssh.KeyPair{hostKey},
		}

		// Track Connect() completion as the encrypt mark (version exchange + KEX).
		// Connect mark is when the server accepts the TCP connection (matching
		// C#'s SessionOpened event and TS's onSessionOpened callback).
		var mu sync.Mutex
		var connectMark float64
		var start time.Time

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

		// --- Timer starts: TCP dial + accept is in the timed region ---
		start = time.Now()

		// Accept on server side (fires "connect mark" when TCP is established).
		var serverConn net.Conn
		var acceptErr error
		accepted := make(chan struct{})
		go func() {
			serverConn, acceptErr = ln.Accept()
			if serverConn != nil {
				configureSocket(serverConn)
			}
			mu.Lock()
			connectMark = float64(time.Since(start).Nanoseconds()) / 1e6
			mu.Unlock()
			close(accepted)
		}()

		// Dial from client side.
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			cancel()
			ln.Close()
			fmt.Fprintf(os.Stderr, "Error dialing: %v\n", err)
			continue
		}
		configureSocket(clientConn)
		<-accepted
		if acceptErr != nil {
			cancel()
			clientConn.Close()
			ln.Close()
			fmt.Fprintf(os.Stderr, "Error accepting: %v\n", acceptErr)
			continue
		}

		// Wrap streams with latency if needed.
		var cs, ss io.ReadWriteCloser = clientConn, serverConn
		if withLatency {
			cs = &latencyStream{stream: clientConn, delay: 100 * time.Millisecond}
			ss = &latencyStream{stream: serverConn, delay: 100 * time.Millisecond}
		}

		// Connect both sessions (version exchange + KEX).
		var wg sync.WaitGroup
		var clientErr, serverErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			clientErr = client.Connect(ctx, cs)
		}()
		go func() {
			defer wg.Done()
			serverErr = server.Connect(ctx, ss)
		}()
		wg.Wait()

		// Encrypt mark = Connect() returns (version exchange + KEX done).
		encryptMark := float64(time.Since(start).Nanoseconds()) / 1e6

		if clientErr != nil || serverErr != nil {
			cancel()
			ln.Close()
			fmt.Fprintf(os.Stderr, "Session setup error: client=%v server=%v\n", clientErr, serverErr)
			continue
		}

		// Authenticate the client (matching C#'s AuthenticateServerAsync +
		// AuthenticateClientAsync and TS's authenticateServer + authenticateClient).
		_, err = client.Authenticate(ctx, &ssh.ClientCredentials{
			Username: "benchmark",
			Password: "benchmark",
		})
		if err != nil {
			cancel()
			ln.Close()
			fmt.Fprintf(os.Stderr, "Auth error: %v\n", err)
			continue
		}

		authMark := float64(time.Since(start).Nanoseconds()) / 1e6

		// Open a channel to complete the full session setup.
		var clientCh *ssh.Channel
		wg.Add(2)
		go func() {
			defer wg.Done()
			clientCh, clientErr = client.OpenChannel(ctx)
		}()
		go func() {
			defer wg.Done()
			_, serverErr = server.AcceptChannel(ctx)
		}()
		wg.Wait()

		channelMark := float64(time.Since(start).Nanoseconds()) / 1e6

		if clientErr != nil || serverErr != nil {
			cancel()
			ln.Close()
			fmt.Fprintf(os.Stderr, "Channel open error: client=%v server=%v\n", clientErr, serverErr)
			continue
		}

		mu.Lock()
		cm := connectMark
		mu.Unlock()

		connectTimes = append(connectTimes, cm)
		encryptTimes = append(encryptTimes, encryptMark-cm)
		authTimes = append(authTimes, authMark-encryptMark)
		channelTimes = append(channelTimes, channelMark-authMark)
		totalTimes = append(totalTimes, channelMark)

		// Send request-reply pairs until latency is measured. The reconnect
		// extension (which carries latency timestamps) is enabled asynchronously
		// after extension-info exchange, so early requests may not carry the info.
		var latencyMs float64
		latencyCtx, latencyCancel := context.WithTimeout(context.Background(), 10*time.Second)
		for latencyCtx.Err() == nil {
			clientCh.Request(latencyCtx, &messages.ChannelRequestMessage{
				RequestType: "benchmark",
				WantReply:   true,
			})
			latencyMs = float64(client.Metrics().LatencyAverageMs())
			if latencyMs > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		latencyCancel()
		latencies = append(latencies, latencyMs)

		fmt.Print(".")

		cancel()
		client.Close()
		server.Close()
		ln.Close()
	}

	return []metric{
		{Name: "Connect time", Unit: "ms", Values: connectTimes, HigherIsBetter: false},
		{Name: "Encrypt time", Unit: "ms", Values: encryptTimes, HigherIsBetter: false},
		{Name: "Authenticate time", Unit: "ms", Values: authTimes, HigherIsBetter: false},
		{Name: "Channel open time", Unit: "ms", Values: channelTimes, HigherIsBetter: false},
		{Name: "Total setup time", Unit: "ms", Values: totalTimes, HigherIsBetter: false},
		{Name: "Latency", Unit: "ms", Values: latencies, HigherIsBetter: false},
	}
}

// --- Throughput benchmarks ---

func throughputScenarios() []benchmarkScenario {
	type tpSpec struct {
		size      int
		encrypted bool
		scenName  string
	}

	specs := []tpSpec{
		{10, true, "encrypted-10"},
		{200, true, "encrypted-200"},
		{50000, true, "encrypted-50000"},
		{1000000, true, "encrypted-1000000"},
		{10, false, "unencrypted-10"},
		{200, false, "unencrypted-200"},
		{50000, false, "unencrypted-50000"},
		{1000000, false, "unencrypted-1000000"},
	}

	var scenarios []benchmarkScenario
	for _, spec := range specs {
		spec := spec
		scenarios = append(scenarios, benchmarkScenario{
			name:     spec.scenName,
			category: "session-throughput",
			tags: map[string]string{
				"encryption": fmt.Sprintf("%t", spec.encrypted),
				"size":       fmt.Sprintf("%d", spec.size),
			},
			run:    func(runs int) []metric { return runThroughputBenchmark(spec.size, spec.encrypted, runs) },
			verify: func() error { return verifyThroughput(spec.size, spec.encrypted) },
		})
	}
	return scenarios
}

func runThroughputBenchmark(messageSize int, encrypted bool, runs int) []metric {
	client, server, err := createSessionPair(encrypted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating session pair: %v\n", err)
		return nil
	}
	defer client.Close()
	defer server.Close()

	clientCh, serverCh, err := openChannel(&client.Session, &server.Session)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening channel: %v\n", err)
		return nil
	}

	// Set up server-side data drain.
	serverCh.SetDataReceivedHandler(func(data []byte) {
		serverCh.AdjustWindow(uint32(len(data)))
	})

	data := make([]byte, messageSize)
	rand.Read(data)

	ctx := context.Background()
	const benchDuration = 2 * time.Second

	msgRates := make([]float64, 0, runs)
	byteRates := make([]float64, 0, runs)

	for i := 0; i < runs; i++ {
		messageCount := 0
		start := time.Now()

		for time.Since(start) < benchDuration {
			if err := clientCh.Send(ctx, data); err != nil {
				fmt.Fprintf(os.Stderr, "Send error: %v\n", err)
				break
			}
			messageCount++
		}

		elapsed := time.Since(start)
		seconds := elapsed.Seconds()
		if seconds > 0 {
			msgRates = append(msgRates, float64(messageCount)/seconds)
			bytesPerSecond := float64(messageCount*messageSize) / seconds
			byteRates = append(byteRates, bytesPerSecond/(1024*1024))
		}

		fmt.Print(".")
	}

	clientCh.Close()

	return []metric{
		{Name: "Throughput", Unit: "msgs/s", Values: msgRates, HigherIsBetter: true},
		{Name: "Throughput", Unit: "MB/s", Values: byteRates, HigherIsBetter: true},
	}
}

// --- Verification functions ---

func verifySessionSetup() error {
	client, server, err := createSessionPair(true)
	if err != nil {
		return fmt.Errorf("create session pair: %w", err)
	}
	defer client.Close()
	defer server.Close()

	clientCh, serverCh, err := openChannel(&client.Session, &server.Session)
	if err != nil {
		return fmt.Errorf("open channel: %w", err)
	}

	// Send test data through the channel.
	testData := []byte("verification test message")
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

func verifyThroughput(messageSize int, encrypted bool) error {
	client, server, err := createSessionPair(encrypted)
	if err != nil {
		return fmt.Errorf("create session pair: %w", err)
	}
	defer client.Close()
	defer server.Close()

	clientCh, serverCh, err := openChannel(&client.Session, &server.Session)
	if err != nil {
		return fmt.Errorf("open channel: %w", err)
	}

	data := make([]byte, messageSize)
	rand.Read(data)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var totalReceived int
	done := make(chan struct{})
	serverCh.SetDataReceivedHandler(func(d []byte) {
		totalReceived += len(d)
		serverCh.AdjustWindow(uint32(len(d)))
		if totalReceived >= messageSize {
			close(done)
		}
	})

	if err := clientCh.Send(ctx, data); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	select {
	case <-done:
	case <-ctx.Done():
		return fmt.Errorf("timeout waiting for data (received %d/%d bytes)", totalReceived, messageSize)
	}

	if totalReceived != messageSize {
		return fmt.Errorf("received %d bytes, expected %d", totalReceived, messageSize)
	}
	return nil
}
