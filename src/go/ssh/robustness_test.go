// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Session Lifecycle Races
// ---------------------------------------------------------------------------

// TestConcurrentChannelOpenAndClose opens channels sequentially then closes
// them concurrently. Verifies no race with -race flag.
func TestConcurrentChannelOpenAndClose(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Open channels sequentially (io.Pipe is synchronous).
	const numChannels = 10
	clientChannels := make([]*Channel, numChannels)
	serverChannels := make([]*Channel, numChannels)

	for i := 0; i < numChannels; i++ {
		var wg sync.WaitGroup
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := server.AcceptChannel(ctx)
			if err != nil {
				t.Errorf("AcceptChannel[%d]: %v", idx, err)
				return
			}
			serverChannels[idx] = ch
		}()

		ch, err := client.OpenChannel(ctx)
		if err != nil {
			t.Fatalf("OpenChannel[%d]: %v", i, err)
		}
		clientChannels[i] = ch
		wg.Wait()
	}

	// Close all channels concurrently.
	var closeWg sync.WaitGroup
	for i := 0; i < numChannels; i++ {
		closeWg.Add(1)
		go func(idx int) {
			defer closeWg.Done()
			clientChannels[idx].Close()
		}(i)
	}
	closeWg.Wait()

	// Verify all channels are closed.
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < numChannels; i++ {
		if !clientChannels[i].IsClosed() {
			t.Errorf("client channel[%d] not closed", i)
		}
	}
}

// TestConcurrentSendAndClose sends data on a channel while simultaneously
// closing the session, verifying no panic or race.
func TestConcurrentSendAndClose(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	if serverCh != nil {
		_ = NewStream(serverCh) // consume data
	}

	// Send data and close concurrently.
	wg.Add(2)
	go func() {
		defer wg.Done()
		data := make([]byte, 1024)
		for i := 0; i < 50; i++ {
			if err := clientCh.Send(ctx, data); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Millisecond)
		client.Close()
	}()

	wg.Wait()
}

// TestConcurrentAuthAndDisconnect verifies that disconnecting during the
// authentication phase does not panic or deadlock.
func TestConcurrentAuthAndDisconnect(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	clientStream, serverStream := duplexPipe()

	clientConfig := NewDefaultConfig()
	serverConfig := NewDefaultConfig()

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewServerSession(serverConfig)
	server.Credentials = &ServerCredentials{PublicKeys: []KeyPair{serverKey}}
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		client.Connect(ctx, clientStream)
	}()
	go func() {
		defer wg.Done()
		server.Connect(ctx, serverStream)
	}()

	// Disconnect mid-handshake.
	time.Sleep(5 * time.Millisecond)
	clientStream.Close()
	serverStream.Close()

	wg.Wait()
	// Success: no panic, no deadlock.
}

// TestConcurrentRekeyAndDataTransfer verifies that data transfer continues
// correctly even during a key rotation (rekey).
func TestConcurrentRekeyAndDataTransfer(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	clientConfig := NewDefaultConfig()
	clientConfig.KeyRotationThreshold = 4096 // trigger rekey quickly
	serverConfig := NewDefaultConfig()
	serverConfig.KeyRotationThreshold = 4096

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig:      clientConfig,
		ServerConfig:      serverConfig,
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{serverKey}},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	serverStream := NewStream(serverCh)

	// Send enough data to trigger at least one rekey, and receive concurrently.
	const totalSize = 32 * 1024
	sent := make([]byte, totalSize)
	for i := range sent {
		sent[i] = byte(i % 256)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		clientCh.Send(ctx, sent)
	}()

	received := make([]byte, totalSize)
	n, readErr := io.ReadFull(serverStream, received)
	wg.Wait()

	if readErr != nil {
		t.Fatalf("ReadFull failed: %v (read %d bytes)", readErr, n)
	}

	for i := 0; i < totalSize; i++ {
		if sent[i] != received[i] {
			t.Fatalf("data mismatch at byte %d: sent %d, got %d", i, sent[i], received[i])
		}
	}
}

// TestConcurrentChannelOperations opens, sends data on, and closes multiple
// channels concurrently. Verifies no race or panic.
func TestConcurrentChannelOperations(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const numChannels = 5
	clientChannels := make([]*Channel, numChannels)
	serverChannels := make([]*Channel, numChannels)

	// Open channels sequentially to avoid io.Pipe contention.
	for i := 0; i < numChannels; i++ {
		var wg sync.WaitGroup
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := server.AcceptChannel(ctx)
			if err != nil {
				t.Errorf("AcceptChannel[%d]: %v", idx, err)
				return
			}
			serverChannels[idx] = ch
		}()

		ch, err := client.OpenChannel(ctx)
		if err != nil {
			t.Fatalf("OpenChannel[%d]: %v", i, err)
		}
		clientChannels[i] = ch
		wg.Wait()
	}

	// Set up echo handlers on server channels.
	for i := 0; i < numChannels; i++ {
		sCh := serverChannels[i]
		stream := NewStream(sCh)
		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := stream.Read(buf)
				if err != nil {
					return
				}
				sCh.Send(ctx, buf[:n])
			}
		}()
	}

	// Concurrently send data and then close all channels.
	var wg sync.WaitGroup
	for i := 0; i < numChannels; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			data := []byte("hello from channel")
			clientChannels[idx].Send(ctx, data)
			time.Sleep(5 * time.Millisecond)
			clientChannels[idx].Close()
		}(i)
	}
	wg.Wait()
}

// TestConcurrentReconnectAndSend verifies that attempting to send data while
// a reconnect is happening does not panic.
func TestConcurrentReconnectAndSend(t *testing.T) {
	pair := newReconnectTestPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = pair.server.AcceptChannel(ctx)
	}()

	clientCh, err := pair.client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	if serverCh != nil {
		_ = NewStream(serverCh)
	}

	// Disconnect and attempt send concurrently.
	wg.Add(2)
	go func() {
		defer wg.Done()
		data := []byte("data during reconnect")
		for i := 0; i < 10; i++ {
			clientCh.Send(ctx, data)
		}
	}()
	go func() {
		defer wg.Done()
		pair.disconnect()
	}()
	wg.Wait()

	// No panic/deadlock is the success criterion.
}

// ---------------------------------------------------------------------------
// Callback Races
// ---------------------------------------------------------------------------

// TestSetChannelOpenCallbackDuringOpen verifies that setting OnChannelOpening
// from one goroutine while channels are opening from another is race-free.
func TestSetChannelOpenCallbackDuringOpen(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var callbackCount int32
	var wg sync.WaitGroup

	// Goroutine 1: repeatedly set OnChannelOpening.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			server.SetChannelOpeningHandler(func(args *ChannelOpeningEventArgs) {
				atomic.AddInt32(&callbackCount, 1)
			})
		}
	}()

	// Goroutine 2: open channels.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			ch, err := client.OpenChannel(ctx)
			if err != nil {
				return
			}
			ch.Close()
		}
	}()

	wg.Wait()
	// Success: no race. Callback may or may not have fired.
}

// ---------------------------------------------------------------------------
// Window Management
// ---------------------------------------------------------------------------

// TestChannelSendZeroBytes verifies that sending zero bytes (which sends EOF
// per the API contract) does not panic and correctly prevents further sends.
func TestChannelSendZeroBytes(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	_ = NewStream(serverCh)

	// Send actual data first.
	err = clientCh.Send(ctx, []byte("hello"))
	if err != nil {
		t.Fatalf("Send(hello) returned error: %v", err)
	}

	// Send zero bytes — per API contract, this sends EOF.
	err = clientCh.Send(ctx, []byte{})
	if err != nil {
		t.Fatalf("Send(empty/EOF) returned error: %v", err)
	}

	// Sending data after EOF should return an error (not panic).
	err = clientCh.Send(ctx, []byte("after eof"))
	if err == nil {
		t.Error("Send after EOF should return error")
	}
}

// ---------------------------------------------------------------------------
// Authentication Edge Cases
// ---------------------------------------------------------------------------

// TestAuthWithEmptyUsername verifies that authentication with an empty username
// completes without panic.
func TestAuthWithEmptyUsername(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			// Accept any auth.
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "",
		Password: "pass",
	})
	if err != nil {
		t.Fatalf("Authenticate with empty username error: %v", err)
	}
	if !success {
		t.Error("expected authentication to succeed with empty username")
	}
}

// TestAuthWithMaxLengthPassword verifies that authentication with a very long
// password does not panic or truncate.
func TestAuthWithMaxLengthPassword(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	longPassword := strings.Repeat("a", 8192)
	var receivedPassword string
	var mu sync.Mutex

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			receivedPassword = args.Password
			mu.Unlock()
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: longPassword,
	})
	if err != nil {
		t.Fatalf("Authenticate with long password error: %v", err)
	}
	if !success {
		t.Error("expected authentication to succeed")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedPassword != longPassword {
		t.Errorf("password truncated: sent %d bytes, received %d bytes",
			len(longPassword), len(receivedPassword))
	}
}

// TestMultipleAuthAttempts verifies that multiple authentication attempts
// work correctly, with failures followed by a success.
func TestMultipleAuthAttempts(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var attempts int32

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			count := atomic.AddInt32(&attempts, 1)
			if count >= 2 && args.AuthenticationType == AuthClientPassword {
				args.AuthenticationResult = true
			}
			// First attempt is rejected (AuthenticationResult stays nil).
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First attempt: wrong password.
	success, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "user",
		Password: "wrong",
	})
	if err != nil {
		t.Fatalf("first Authenticate error: %v", err)
	}

	// Second attempt: correct password.
	success, err = client.Authenticate(ctx, &ClientCredentials{
		Username: "user",
		Password: "correct",
	})
	if err != nil {
		t.Fatalf("second Authenticate error: %v", err)
	}
	if !success {
		t.Error("expected second authentication to succeed")
	}
}

// ---------------------------------------------------------------------------
// API Contract
// ---------------------------------------------------------------------------

// TestSessionImplementsCloser verifies that Session satisfies io.Closer at runtime.
func TestSessionImplementsCloser(t *testing.T) {
	cs := NewClientSession(NewNoSecurityConfig())
	var closer io.Closer = &cs.Session
	if closer == nil {
		t.Fatal("session should implement io.Closer")
	}

	ss := NewServerSession(NewNoSecurityConfig())
	closer = &ss.Session
	if closer == nil {
		t.Fatal("server session should implement io.Closer")
	}
}

// TestStreamImplementsReadWriteCloser verifies that Stream satisfies io.ReadWriteCloser.
func TestStreamImplementsReadWriteCloser(t *testing.T) {
	// Compile-time check already exists in stream.go, verify at runtime too.
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	stream := NewStream(clientCh)
	var rwc io.ReadWriteCloser = stream
	if rwc == nil {
		t.Fatal("stream should implement io.ReadWriteCloser")
	}
	_ = NewStream(serverCh)
}

// TestChannelImplementsReadWriteCloser verifies that a Channel wrapped in
// a Stream provides io.ReadWriteCloser semantics.
func TestChannelImplementsReadWriteCloser(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	clientStream := NewStream(clientCh)
	serverStream := NewStream(serverCh)

	// Write through stream.
	data := []byte("test data")
	n, err := clientStream.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Write: n=%d, want %d", n, len(data))
	}

	// Read through stream.
	buf := make([]byte, len(data))
	n, err = io.ReadFull(serverStream, buf)
	if err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}
	if string(buf) != string(data) {
		t.Errorf("read %q, want %q", buf, data)
	}

	// Close.
	if err := clientStream.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

// TestDefaultConfigAlgorithms verifies that NewDefaultConfig has the expected
// algorithm categories populated (non-empty).
func TestDefaultConfigAlgorithms(t *testing.T) {
	config := NewDefaultConfig()

	checks := []struct {
		name string
		algs []string
	}{
		{"KeyExchangeAlgorithms", config.KeyExchangeAlgorithms},
		{"PublicKeyAlgorithms", config.PublicKeyAlgorithms},
		{"EncryptionAlgorithms", config.EncryptionAlgorithms},
		{"HmacAlgorithms", config.HmacAlgorithms},
		{"CompressionAlgorithms", config.CompressionAlgorithms},
	}

	for _, check := range checks {
		if len(check.algs) == 0 {
			t.Errorf("%s should not be empty in default config", check.name)
		}
		// None of them should be "none" in the default (secure) config,
		// except compression which is always "none".
		if check.name != "CompressionAlgorithms" {
			for _, alg := range check.algs {
				if alg == "none" {
					t.Errorf("%s should not contain 'none' in default config", check.name)
				}
			}
		}
	}
}

// TestConfigImmutableAfterSessionStart verifies that mutating the config after
// session start does not affect the running session.
func TestConfigImmutableAfterSessionStart(t *testing.T) {
	config := NewNoSecurityConfig()
	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: config,
	})

	// Mutate the config after session is connected.
	config.KeyExchangeAlgorithms = nil
	config.ProtocolExtensions = nil

	// Session should still be connected and functional.
	if !client.IsConnected() {
		t.Error("client should still be connected after config mutation")
	}
}

// TestNilAlgorithmMeansNone verifies that the no-security config uses "none"
// for all algorithm categories (matching the convention that nil/none = no security).
func TestNilAlgorithmMeansNone(t *testing.T) {
	config := NewNoSecurityConfig()

	if len(config.KeyExchangeAlgorithms) != 1 || config.KeyExchangeAlgorithms[0] != AlgoKexNone {
		t.Error("no-security config should have kex:none")
	}
	if len(config.PublicKeyAlgorithms) != 1 || config.PublicKeyAlgorithms[0] != AlgoPKNone {
		t.Error("no-security config should have pk:none")
	}
	if len(config.EncryptionAlgorithms) != 1 || config.EncryptionAlgorithms[0] != AlgoEncNone {
		t.Error("no-security config should have enc:none")
	}
	if len(config.HmacAlgorithms) != 1 || config.HmacAlgorithms[0] != AlgoHmacNone {
		t.Error("no-security config should have hmac:none")
	}
}

// TestOnAuthenticatingCalled verifies that the OnAuthenticating callback fires
// during authentication with secure config.
func TestOnAuthenticatingCalled(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var serverAuthCalled int32
	var clientAuthCalled int32

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			atomic.AddInt32(&serverAuthCalled, 1)
			args.AuthenticationResult = true
		},
		ClientOnAuthenticating: func(args *AuthenticatingEventArgs) {
			atomic.AddInt32(&clientAuthCalled, 1)
			args.AuthenticationResult = true
		},
	})

	// Authenticate to trigger server-side auth callback.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client.Authenticate(ctx, &ClientCredentials{
		Username: "test",
		Password: "test",
	})

	if atomic.LoadInt32(&serverAuthCalled) == 0 {
		t.Error("server OnAuthenticating was never called")
	}
	if atomic.LoadInt32(&clientAuthCalled) == 0 {
		t.Error("client OnAuthenticating was never called")
	}
}

// TestOnChannelOpeningCalled verifies that the OnChannelOpening callback fires
// when a channel is opened.
func TestOnChannelOpeningCalled(t *testing.T) {
	var callbackFired int32

	client, server := createSessionPair(t, nil)
	server.SetChannelOpeningHandler(func(args *ChannelOpeningEventArgs) {
		atomic.AddInt32(&callbackFired, 1)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.AcceptChannel(ctx)
	}()

	_, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	if atomic.LoadInt32(&callbackFired) == 0 {
		t.Error("OnChannelOpening was never called")
	}
}

// TestOnDisconnectedCalled verifies that the OnDisconnected callback fires
// when a reconnect-enabled session disconnects.
func TestOnDisconnectedCalled(t *testing.T) {
	pair := newReconnectTestPair(t)

	disconnectedCh := make(chan struct{})
	var once sync.Once
	pair.client.OnDisconnected = func() {
		once.Do(func() {
			close(disconnectedCh)
		})
	}

	pair.disconnect()

	select {
	case <-disconnectedCh:
		// Success: OnDisconnected fired.
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for OnDisconnected")
	}
}

// TestOnReconnectedCalled verifies that the server's OnReconnected callback
// fires after a successful reconnect.
func TestOnReconnectedCalled(t *testing.T) {
	pair := newReconnectTestPair(t)

	reconnectedCh := make(chan struct{})
	var once sync.Once
	pair.server.SetReconnectedHandler(func() {
		once.Do(func() {
			close(reconnectedCh)
		})
	})

	// Disconnect and reconnect.
	pair.disconnect()
	pair.waitDisconnected(t)
	pair.reconnect(t)

	select {
	case <-reconnectedCh:
		// Success: OnReconnected fired.
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for OnReconnected")
	}
}

// ---------------------------------------------------------------------------
// Memory Leak / Goroutine Leak
// ---------------------------------------------------------------------------

// TestNoGoroutineLeakOnSessionClose verifies that closing a session does not
// leave goroutines behind. It takes a baseline count, creates and closes
// sessions, and verifies goroutine count returns to baseline.
func TestNoGoroutineLeakOnSessionClose(t *testing.T) {
	// Warm up: create and close one session to get baseline stable.
	warmup, warmupServer := createNoSecuritySessionPair(t)
	warmup.Close()
	warmupServer.Close()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	baseline := runtime.NumGoroutine()

	// Create and close 5 sessions.
	for i := 0; i < 5; i++ {
		c, s := createNoSecuritySessionPair(t)
		c.Close()
		s.Close()
	}

	// Wait for goroutines to settle.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	final := runtime.NumGoroutine()

	// Allow a margin of 3 goroutines for GC, runtime, etc.
	if final > baseline+3 {
		t.Errorf("goroutine leak: baseline=%d, after=%d (delta=%d)",
			baseline, final, final-baseline)
	}
}

// TestNoGoroutineLeakOnChannelClose verifies that opening and closing many
// channels does not leak goroutines.
func TestNoGoroutineLeakOnChannelClose(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Open and close one channel to warm up.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ch, _ := server.AcceptChannel(ctx)
		if ch != nil {
			ch.Close()
		}
	}()
	ch, _ := client.OpenChannel(ctx)
	if ch != nil {
		ch.Close()
	}
	wg.Wait()
	time.Sleep(50 * time.Millisecond)
	runtime.GC()

	baseline := runtime.NumGoroutine()

	// Open and close 10 channels.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sCh, err := server.AcceptChannel(ctx)
			if err == nil && sCh != nil {
				sCh.Close()
			}
		}()

		cCh, err := client.OpenChannel(ctx)
		if err != nil {
			t.Fatalf("OpenChannel[%d] failed: %v", i, err)
		}
		cCh.Close()
		wg.Wait()
	}

	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	final := runtime.NumGoroutine()

	if final > baseline+3 {
		t.Errorf("goroutine leak after channel close: baseline=%d, after=%d (delta=%d)",
			baseline, final, final-baseline)
	}
}

// TestNoMemoryLeakOnReconnect verifies that reconnecting does not leak
// goroutines.
func TestNoMemoryLeakOnReconnect(t *testing.T) {
	pair := newReconnectTestPair(t)

	// First reconnect to warm up.
	pair.disconnect()
	pair.waitDisconnected(t)
	pair.reconnect(t)
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	baseline := runtime.NumGoroutine()

	// Perform additional reconnects.
	for i := 0; i < 3; i++ {
		pair.disconnect()
		pair.waitDisconnected(t)
		pair.reconnect(t)
	}

	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	final := runtime.NumGoroutine()

	// Allow margin for timing-sensitive goroutine cleanup.
	if final > baseline+5 {
		t.Errorf("goroutine leak after reconnects: baseline=%d, after=%d (delta=%d)",
			baseline, final, final-baseline)
	}
}

// TestPipeCleanupOnClose verifies that a channel pipe cleans up properly when
// the underlying session is closed.
func TestPipeCleanupOnClose(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open channel pair for piping.
	var serverCh1, serverCh2 *Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		serverCh1, _ = server.AcceptChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		serverCh2, _ = server.AcceptChannel(ctx)
	}()

	clientCh1, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel1 failed: %v", err)
	}
	clientCh2, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel2 failed: %v", err)
	}
	wg.Wait()

	// Pipe the two server-side channels together.
	pipeDone := make(chan error, 1)
	go func() {
		pipeDone <- serverCh1.Pipe(ctx, serverCh2)
	}()

	// Send data through the pipe.
	data := []byte("pipe test")
	_ = clientCh1.Send(ctx, data)
	time.Sleep(50 * time.Millisecond)

	// Close the session — pipe should terminate.
	client.Close()

	select {
	case <-pipeDone:
		// Pipe exited — success.
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not terminate after session close")
	}

	// Verify channels are closed.
	if !clientCh1.IsClosed() {
		t.Error("clientCh1 should be closed")
	}
	if !clientCh2.IsClosed() {
		t.Error("clientCh2 should be closed")
	}
}

// ---------------------------------------------------------------------------
// Helpers — createHmacPair is defined in reconnect_session_test.go
// ---------------------------------------------------------------------------
