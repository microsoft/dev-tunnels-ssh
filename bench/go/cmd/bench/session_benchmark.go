// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
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
		},
		{
			name:     "session-with-latency",
			category: "session-setup",
			tags:     map[string]string{"latency": "100"},
			run:      func(runs int) []metric { return runSessionSetupBenchmark(runs, true) },
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
		clientStream, serverStream := newDuplexPipe()

		// Wrap streams with latency if needed.
		var cs, ss io.ReadWriteCloser = clientStream, serverStream
		if withLatency {
			cs = &latencyStream{stream: clientStream, delay: 100 * time.Millisecond}
			ss = &latencyStream{stream: serverStream, delay: 100 * time.Millisecond}
		}

		config := ssh.NewDefaultConfigWithReconnect()
		config.KeyRotationThreshold = 0

		hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
		if err != nil {
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

		// Track phase timings via progress callbacks on the client session.
		// Connect time: 0 → version exchange done
		// Encrypt time: version done → KEX done
		// Auth time: KEX done → Connect() returns (auth handshake completes)
		// Channel time: Connect done → channel opened
		var mu sync.Mutex
		var connectMark, encryptMark float64
		var start time.Time

		client.OnReportProgress = func(p ssh.Progress) {
			mu.Lock()
			defer mu.Unlock()
			ms := float64(time.Since(start).Nanoseconds()) / 1e6
			switch p {
			case ssh.ProgressCompletedProtocolVersionExchange:
				connectMark = ms
			case ssh.ProgressCompletedKeyExchange:
				encryptMark = ms
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

		start = time.Now()

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

		// Auth mark = when both Connect() calls return (auth is complete).
		authMark := float64(time.Since(start).Nanoseconds()) / 1e6

		if clientErr != nil || serverErr != nil {
			cancel()
			fmt.Fprintf(os.Stderr, "Session setup error: client=%v server=%v\n", clientErr, serverErr)
			continue
		}

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
		cancel()

		if clientErr != nil || serverErr != nil {
			fmt.Fprintf(os.Stderr, "Channel open error: client=%v server=%v\n", clientErr, serverErr)
			continue
		}

		mu.Lock()
		cm := connectMark
		em := encryptMark
		mu.Unlock()

		connectTimes = append(connectTimes, cm)
		encryptTimes = append(encryptTimes, em-cm)
		authTimes = append(authTimes, authMark-em)
		channelTimes = append(channelTimes, channelMark-authMark)
		totalTimes = append(totalTimes, channelMark)

		// Send request-reply pairs until latency is measured. The reconnect
		// extension (which carries latency timestamps) is enabled asynchronously
		// after extension-info exchange, so early requests may not carry the info.
		// With injected latency the enable round-trip itself takes 200ms+.
		var latencyMs float64
		latencyDeadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(latencyDeadline) {
			clientCh.Request(ctx, &messages.ChannelRequestMessage{
				RequestType: "benchmark",
				WantReply:   true,
			})
			latencyMs = float64(client.Metrics().LatencyAverageMs())
			if latencyMs > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		latencies = append(latencies, latencyMs)

		fmt.Print(".")

		_ = clientCh
		client.Close()
		server.Close()
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
			run: func(runs int) []metric { return runThroughputBenchmark(spec.size, spec.encrypted, runs) },
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
