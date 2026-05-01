// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// --- Channel Throughput Benchmarks ---

// BenchmarkChannelThroughput measures single-channel data throughput
// over a no-security session (no encryption overhead).
func BenchmarkChannelThroughput(b *testing.B) {
	benchmarkChannelThroughput(b, nil, nil)
}

// BenchmarkChannelThroughputEncrypted measures single-channel data throughput
// over an encrypted session (ECDSA P-256 + AES-256-CTR + HMAC-SHA-256).
func BenchmarkChannelThroughputEncrypted(b *testing.B) {
	makeConfig := func() *SessionConfig {
		c := &SessionConfig{
			ProtocolExtensions:    []string{ExtensionServerSignatureAlgorithms},
			AuthenticationMethods: []string{AuthMethodNone},
			KeyExchangeAlgorithms: []string{AlgoKexEcdhNistp256},
			PublicKeyAlgorithms:   []string{AlgoPKEcdsaSha2P256},
			EncryptionAlgorithms:  []string{AlgoEncAes256Ctr},
			HmacAlgorithms:        []string{AlgoHmacSha256},
			CompressionAlgorithms: []string{AlgoCompNone},
			KeyRotationThreshold:  0, // disable rekey during benchmark
		}
		registerDefaultServices(c)
		return c
	}
	benchmarkChannelThroughput(b, makeConfig(), makeConfig())
}

func benchmarkChannelThroughput(b *testing.B, clientConfig, serverConfig *SessionConfig) {
	b.Helper()

	client, server := benchCreateSessionPairDirect(b, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	ctx := context.Background()

	clientCh, serverCh := benchOpenChannel(b, ctx, &client.Session, &server.Session)

	// 32KB chunks (default max packet size).
	const chunkSize = 32 * 1024
	data := make([]byte, chunkSize)
	rand.Read(data)

	// Drain server side using direct OnDataReceived callback.
	// This calls AdjustWindow from the dispatch goroutine, which can
	// block on pipe writes for WindowAdjust messages, but this never
	// deadlocks because the client dispatch goroutine independently
	// reads those messages and releases the block.
	drainDone := drainChannel(serverCh)

	b.SetBytes(chunkSize)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := clientCh.Send(ctx, data); err != nil {
			b.Fatalf("send: %v", err)
		}
	}

	b.StopTimer()
	clientCh.Close()
	<-drainDone
}

// BenchmarkMultiChannelThroughput measures aggregate throughput across
// multiple channels on a single session.
func BenchmarkMultiChannelThroughput(b *testing.B) {
	const numChannels = 10

	client, server := benchCreateSessionPairDirect(b, nil, nil)
	defer client.Close()
	defer server.Close()

	ctx := context.Background()

	type channelPair struct {
		clientCh *Channel
		serverCh *Channel
	}

	// Open all channels.
	pairs := make([]channelPair, numChannels)
	for i := 0; i < numChannels; i++ {
		clientCh, serverCh := benchOpenChannel(b, ctx, &client.Session, &server.Session)
		pairs[i] = channelPair{clientCh: clientCh, serverCh: serverCh}
	}

	const chunkSize = 32 * 1024
	data := make([]byte, chunkSize)
	rand.Read(data)

	// Drain all server channels using direct callbacks.
	drainChans := make([]<-chan int64, numChannels)
	for i := 0; i < numChannels; i++ {
		drainChans[i] = drainChannel(pairs[i].serverCh)
	}

	// Total bytes = chunkSize * numChannels per iteration.
	b.SetBytes(chunkSize * numChannels)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	}

	b.StopTimer()
	for i := 0; i < numChannels; i++ {
		pairs[i].clientCh.Close()
	}
	for i := 0; i < numChannels; i++ {
		<-drainChans[i]
	}
}

// --- Session Setup Benchmarks ---

// BenchmarkSessionSetup measures the time to create a connected encrypted session pair.
func BenchmarkSessionSetup(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, server := benchCreateSessionPairDirect(b, nil, nil)
		client.Close()
		server.Close()
	}
}

// BenchmarkSessionSetupWithLatency measures session setup with 100ms simulated latency.
func BenchmarkSessionSetupWithLatency(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clientStream, serverStream := duplexPipe()
		cs := &benchLatencyStream{stream: clientStream, delay: 100 * time.Millisecond}
		ss := &benchLatencyStream{stream: serverStream, delay: 100 * time.Millisecond}
		client, server := benchCreateSessionPairWithStreams(b, cs, ss, nil, nil)
		client.Close()
		server.Close()
	}
}

// --- Throughput Benchmarks (Multi-Size) ---

func BenchmarkThroughputEncrypted10B(b *testing.B) {
	benchmarkThroughputSize(b, 10, true)
}

func BenchmarkThroughputEncrypted200B(b *testing.B) {
	benchmarkThroughputSize(b, 200, true)
}

func BenchmarkThroughputEncrypted50KB(b *testing.B) {
	benchmarkThroughputSize(b, 50*1024, true)
}

func BenchmarkThroughputEncrypted1MB(b *testing.B) {
	benchmarkThroughputSize(b, 1024*1024, true)
}

func BenchmarkThroughputUnencrypted10B(b *testing.B) {
	benchmarkThroughputSize(b, 10, false)
}

func BenchmarkThroughputUnencrypted200B(b *testing.B) {
	benchmarkThroughputSize(b, 200, false)
}

func BenchmarkThroughputUnencrypted50KB(b *testing.B) {
	benchmarkThroughputSize(b, 50*1024, false)
}

func BenchmarkThroughputUnencrypted1MB(b *testing.B) {
	benchmarkThroughputSize(b, 1024*1024, false)
}

func benchmarkThroughputSize(b *testing.B, chunkSize int, encrypted bool) {
	b.Helper()

	var clientConfig, serverConfig *SessionConfig
	if encrypted {
		clientConfig = newEncryptedBenchConfig()
		serverConfig = newEncryptedBenchConfig()
	}

	client, server := benchCreateSessionPairDirect(b, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	clientCh, serverCh := benchOpenChannel(b, ctx, &client.Session, &server.Session)

	data := make([]byte, chunkSize)
	rand.Read(data)

	drainDone := drainChannel(serverCh)

	b.SetBytes(int64(chunkSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := clientCh.Send(ctx, data); err != nil {
			b.Fatalf("send: %v", err)
		}
	}

	b.StopTimer()
	clientCh.Close()
	<-drainDone
}

// --- Message Serialization Benchmarks ---

// BenchmarkMessageSerialize benchmarks serialization of various SSH message
// types. This measures the overhead of the message framing layer.
func BenchmarkMessageSerialize(b *testing.B) {
	b.Run("ChannelData", func(b *testing.B) {
		data := make([]byte, 32*1024)
		rand.Read(data)
		msg := &messages.ChannelDataMessage{
			RecipientChannel: 1,
			Data:             data,
		}
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = msg.ToBuffer()
		}
	})

	b.Run("ChannelOpen", func(b *testing.B) {
		msg := &messages.ChannelOpenMessage{
			ChannelType:   "session",
			SenderChannel: 42,
			MaxWindowSize: DefaultMaxWindowSize,
			MaxPacketSize: DefaultMaxPacketSize,
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = msg.ToBuffer()
		}
	})

	b.Run("ChannelWindowAdjust", func(b *testing.B) {
		msg := &messages.ChannelWindowAdjustMessage{
			RecipientChannel: 1,
			BytesToAdd:       65536,
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = msg.ToBuffer()
		}
	})

	b.Run("KeyExchangeInit", func(b *testing.B) {
		var cookie [16]byte
		rand.Read(cookie[:])
		msg := &messages.KeyExchangeInitMessage{
			Cookie:                              cookie,
			KeyExchangeAlgorithms:               []string{"ecdh-sha2-nistp384", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"},
			ServerHostKeyAlgorithms:             []string{"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "rsa-sha2-256"},
			EncryptionAlgorithmsClientToServer:  []string{"aes256-gcm@openssh.com", "aes256-ctr"},
			EncryptionAlgorithmsServerToClient:  []string{"aes256-gcm@openssh.com", "aes256-ctr"},
			MacAlgorithmsClientToServer:         []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"},
			MacAlgorithmsServerToClient:         []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"},
			CompressionAlgorithmsClientToServer: []string{"none"},
			CompressionAlgorithmsServerToClient: []string{"none"},
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = msg.ToBuffer()
		}
	})

	b.Run("Disconnect", func(b *testing.B) {
		msg := &messages.DisconnectMessage{
			ReasonCode:  11,
			Description: "connection closed by peer",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = msg.ToBuffer()
		}
	})

	b.Run("RoundTrip-ChannelData", func(b *testing.B) {
		data := make([]byte, 4*1024)
		rand.Read(data)
		msg := &messages.ChannelDataMessage{
			RecipientChannel: 1,
			Data:             data,
		}
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := msg.ToBuffer()
			var out messages.ChannelDataMessage
			if err := messages.ReadMessage(&out, buf); err != nil {
				b.Fatalf("read: %v", err)
			}
		}
	})
}

// --- Benchmark Helpers ---

// benchCreateSessionPairDirect creates a connected session pair using
// duplexPipe. The caller is responsible for closing the sessions.
func benchCreateSessionPairDirect(b *testing.B, clientConfig, serverConfig *SessionConfig) (*ClientSession, *ServerSession) {
	b.Helper()

	if clientConfig == nil {
		clientConfig = NewNoSecurityConfig()
		clientConfig.KeyRotationThreshold = 0 // disable rekey during benchmark
	}
	if serverConfig == nil {
		serverConfig = NewNoSecurityConfig()
		serverConfig.KeyRotationThreshold = 0 // disable rekey during benchmark
	}

	clientStream, serverStream := duplexPipe()

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewServerSession(serverConfig)
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	// For encrypted benchmarks, generate a host key.
	if hasNonNone(serverConfig.KeyExchangeAlgorithms) {
		hostKey, err := GenerateKeyPair(serverConfig.PublicKeyAlgorithms[0])
		if err != nil {
			b.Fatalf("generate key pair: %v", err)
		}
		server.Credentials = &ServerCredentials{
			PublicKeys: []KeyPair{hostKey},
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
		b.Fatalf("client connect: %v", clientErr)
	}
	if serverErr != nil {
		b.Fatalf("server connect: %v", serverErr)
	}

	return client, server
}

func benchOpenChannel(b *testing.B, ctx context.Context, client, server *Session) (*Channel, *Channel) {
	b.Helper()

	var clientCh, serverCh *Channel
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
		b.Fatalf("open channel: %v", openErr)
	}
	if acceptErr != nil {
		b.Fatalf("accept channel: %v", acceptErr)
	}

	return clientCh, serverCh
}

// benchOpenChannelT is the testing.T version for stress tests.
func benchOpenChannelT(t *testing.T, ctx context.Context, client, server *Session) (*Channel, *Channel) {
	t.Helper()

	var clientCh, serverCh *Channel
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
		t.Fatalf("open channel: %v", openErr)
	}
	if acceptErr != nil {
		t.Fatalf("accept channel: %v", acceptErr)
	}

	return clientCh, serverCh
}

// drainChannel drains received data directly via OnDataReceived callback.
// AdjustWindow is called from the dispatch goroutine so WindowAdjust messages
// are sent synchronously (may briefly block the dispatch goroutine on pipe
// writes), but this avoids the Stream readReady signal-loss issue entirely.
func drainChannel(ch *Channel) <-chan int64 {
	done := make(chan int64, 1)
	var total int64
	ch.SetDataReceivedHandler(func(data []byte) {
		total += int64(len(data))
		ch.AdjustWindow(uint32(len(data)))
	})
	go func() {
		<-ch.closeDone
		done <- total
	}()
	return done
}

// drainStream reads all data from a stream until it closes or errors.
func drainStream(r io.Reader) <-chan int64 {
	done := make(chan int64, 1)
	go func() {
		var total int64
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			total += int64(n)
			if err != nil {
				break
			}
		}
		done <- total
	}()
	return done
}

// newEncryptedBenchConfig creates an encrypted session config for benchmarks.
func newEncryptedBenchConfig() *SessionConfig {
	c := &SessionConfig{
		ProtocolExtensions:    []string{ExtensionServerSignatureAlgorithms},
		AuthenticationMethods: []string{AuthMethodNone},
		KeyExchangeAlgorithms: []string{AlgoKexEcdhNistp256},
		PublicKeyAlgorithms:   []string{AlgoPKEcdsaSha2P256},
		EncryptionAlgorithms:  []string{AlgoEncAes256Ctr},
		HmacAlgorithms:        []string{AlgoHmacSha256},
		CompressionAlgorithms: []string{AlgoCompNone},
		KeyRotationThreshold:  0,
	}
	registerDefaultServices(c)
	return c
}

// benchLatencyStream wraps a stream and adds a delay to each read and write.
type benchLatencyStream struct {
	stream io.ReadWriteCloser
	delay  time.Duration
}

func (s *benchLatencyStream) Read(b []byte) (int, error) {
	time.Sleep(s.delay / 2)
	return s.stream.Read(b)
}

func (s *benchLatencyStream) Write(b []byte) (int, error) {
	time.Sleep(s.delay / 2)
	return s.stream.Write(b)
}

func (s *benchLatencyStream) Close() error { return s.stream.Close() }

// benchCreateSessionPairWithStreams creates a connected session pair using provided streams.
func benchCreateSessionPairWithStreams(b *testing.B, clientStream, serverStream io.ReadWriteCloser, clientConfig, serverConfig *SessionConfig) (*ClientSession, *ServerSession) {
	b.Helper()

	if clientConfig == nil {
		clientConfig = NewNoSecurityConfig()
		clientConfig.KeyRotationThreshold = 0
	}
	if serverConfig == nil {
		serverConfig = NewNoSecurityConfig()
		serverConfig.KeyRotationThreshold = 0
	}

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewServerSession(serverConfig)
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	if hasNonNone(serverConfig.KeyExchangeAlgorithms) {
		hostKey, err := GenerateKeyPair(serverConfig.PublicKeyAlgorithms[0])
		if err != nil {
			b.Fatalf("generate key pair: %v", err)
		}
		server.Credentials = &ServerCredentials{
			PublicKeys: []KeyPair{hostKey},
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
		b.Fatalf("client connect: %v", clientErr)
	}
	if serverErr != nil {
		b.Fatalf("server connect: %v", serverErr)
	}

	return client, server
}
