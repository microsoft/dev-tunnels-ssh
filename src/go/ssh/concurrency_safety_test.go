// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestProtocolExtensionsConcurrentAccess verifies that reading ProtocolExtensions
// from one goroutine while the dispatch loop writes it does not trigger a race.
// Run with: go test -race ./ssh/...
func TestProtocolExtensionsConcurrentAccess(t *testing.T) {
	client, server := createSessionPair(t, nil)

	var wg sync.WaitGroup

	// Goroutine 1: repeatedly read ProtocolExtensions on the server.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			server.mu.Lock()
			ext := server.ProtocolExtensions
			server.mu.Unlock()
			_ = ext
		}
	}()

	// Goroutine 2: repeatedly read ProtocolExtensions on the client.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			client.mu.Lock()
			ext := client.ProtocolExtensions
			client.mu.Unlock()
			_ = ext
		}
	}()

	// Goroutine 3: write ProtocolExtensions on the server (simulating dispatch loop).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			server.mu.Lock()
			server.ProtocolExtensions = map[string]string{
				"test-ext": "value",
			}
			server.mu.Unlock()
		}
	}()

	wg.Wait()

	// Also verify getExtensionSupport (user-facing method) is race-free.
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = server.getExtensionSupport(ExtensionSessionReconnect)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			server.mu.Lock()
			server.ProtocolExtensions = map[string]string{
				ExtensionSessionReconnect: "",
			}
			server.mu.Unlock()
		}
	}()
	wg.Wait()
}

// TestChannelsMapConcurrentAccess verifies that calling Channels() while channels
// are being opened/closed by the dispatch loop does not trigger a race.
func TestChannelsMapConcurrentAccess(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Goroutine 1: repeatedly call Channels() to get a snapshot.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			chs := server.Channels()
			// Iterate the snapshot — should be safe even if the internal map changes.
			for id, ch := range chs {
				_ = id
				_ = ch
			}
		}
	}()

	// Goroutine 2: open channels from the client, which causes the server's
	// dispatch loop to add entries to the internal channels map.
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

	// Verify the snapshot is a copy, not a reference.
	snapshot1 := server.Channels()
	snapshot2 := server.Channels()

	// Mutating snapshot1 should not affect snapshot2 or the internal map.
	snapshot1[999] = nil
	if _, ok := snapshot2[999]; ok {
		t.Error("Channels() returned reference to internal map, not a copy")
	}
}

// TestSetAuthCallbackDuringAuth verifies that setting OnAuthenticating from one
// goroutine while the dispatch goroutine reads it for auth does not trigger a
// data race. This specifically tests the handleAuthInfoRequest path (client side)
// which was previously missing the lock snapshot pattern.
func TestSetAuthCallbackDuringAuth(t *testing.T) {
	clientStream, serverStream := duplexPipe()

	client := NewClientSession(NewNoSecurityConfig())
	server := NewServerSession(NewNoSecurityConfig())

	// Set initial callbacks.
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

	// Concurrently overwrite the callback using the thread-safe setter
	// while connect/auth is happening. This tests the snapshot pattern.
	for i := 0; i < 50; i++ {
		server.SetAuthenticatingHandler(func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		})
		client.SetAuthenticatingHandler(func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		})
	}

	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server connect failed: %v", serverErr)
	}

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
}

// TestSharedConfigNotCorruptedByRekey verifies that sharing a config between two
// sessions does not cause one session's rekey to corrupt the other session's config.
// This tests the HIGH-06 fix: algorithm slices are copied before modification
// during remote-initiated key exchange.
func TestSharedConfigNotCorruptedByRekey(t *testing.T) {
	// Create a single shared config.
	sharedConfig := NewNoSecurityConfig()
	originalKexAlgos := make([]string, len(sharedConfig.KeyExchangeAlgorithms))
	copy(originalKexAlgos, sharedConfig.KeyExchangeAlgorithms)

	// Create two session pairs sharing the same config.
	client1, server1 := createSessionPair(t, &SessionPairOptions{
		ClientConfig: sharedConfig,
		ServerConfig: sharedConfig,
	})

	// After the first session pair connects (which triggers key exchange),
	// verify the original config is not corrupted.
	currentKexAlgos := sharedConfig.KeyExchangeAlgorithms
	if len(currentKexAlgos) != len(originalKexAlgos) {
		t.Errorf("shared config KeyExchangeAlgorithms length changed: got %d, want %d",
			len(currentKexAlgos), len(originalKexAlgos))
	}
	for i, algo := range currentKexAlgos {
		if algo != originalKexAlgos[i] {
			t.Errorf("shared config KeyExchangeAlgorithms[%d] changed: got %q, want %q",
				i, algo, originalKexAlgos[i])
		}
	}

	// Verify both sessions are functional.
	if !client1.IsConnected() {
		t.Error("client1 not connected")
	}
	if !server1.IsConnected() {
		t.Error("server1 not connected")
	}

	// Create a second pair with the same shared config.
	client2, server2 := createSessionPair(t, &SessionPairOptions{
		ClientConfig: sharedConfig,
		ServerConfig: sharedConfig,
	})

	// Verify config still not corrupted after second session.
	currentKexAlgos = sharedConfig.KeyExchangeAlgorithms
	if len(currentKexAlgos) != len(originalKexAlgos) {
		t.Errorf("shared config KeyExchangeAlgorithms length changed after second session: got %d, want %d",
			len(currentKexAlgos), len(originalKexAlgos))
	}

	if !client2.IsConnected() {
		t.Error("client2 not connected")
	}
	if !server2.IsConnected() {
		t.Error("server2 not connected")
	}
}
