// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// TestCallbackRaceOnChannelOpening verifies that setting OnChannelOpening from
// one goroutine while channels are being opened from another does not trigger
// a data race. Run with: go test -race ./ssh/...
func TestCallbackRaceOnChannelOpening(t *testing.T) {
	client, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var callbackCount int32
	var wg sync.WaitGroup

	// Goroutine 1: repeatedly set OnChannelOpening using the thread-safe setter
	// from a non-dispatch goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			server.SetChannelOpeningHandler(func(args *ChannelOpeningEventArgs) {
				atomic.AddInt32(&callbackCount, 1)
			})
		}
	}()

	// Goroutine 2: open channels from the client, which triggers OnChannelOpening
	// reads on the server's dispatch goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			_, err := client.OpenChannel(ctx)
			if err != nil {
				// Session might close during cleanup; that's fine.
				return
			}
		}
	}()

	wg.Wait()

	// Verify at least some callbacks fired (the exact count depends on timing).
	if atomic.LoadInt32(&callbackCount) == 0 {
		t.Error("expected OnChannelOpening to have fired at least once")
	}
}

// TestCallbackRaceOnRequest verifies that setting OnRequest from one goroutine
// while session requests arrive from another does not trigger a data race.
func TestCallbackRaceOnRequest(t *testing.T) {
	client, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var callbackCount int32
	var wg sync.WaitGroup

	// Goroutine 1: repeatedly set OnRequest using the thread-safe setter.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			server.SetRequestHandler(func(args *RequestEventArgs) {
				args.IsAuthorized = true
				atomic.AddInt32(&callbackCount, 1)
			})
		}
	}()

	// Goroutine 2: send session requests from the client.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			_, err := client.Request(ctx, &messages.SessionRequestMessage{
				RequestType: "test-request@test",
				WantReply:   true,
			})
			if err != nil {
				return
			}
		}
	}()

	wg.Wait()

	_ = atomic.LoadInt32(&callbackCount) // Just verify no race; callback may or may not fire.
}

// TestCallbackRaceOnAuthenticating verifies that setting OnAuthenticating from
// one goroutine while auth is in progress on the dispatch goroutine does not
// trigger a data race. Since auth happens during Connect, we verify this by
// using the thread-safe setter concurrently with the connect handshake.
func TestCallbackRaceOnAuthenticating(t *testing.T) {
	clientStream, serverStream := duplexPipe()

	client := NewClientSession(NewNoSecurityConfig())
	server := NewServerSession(NewNoSecurityConfig())

	// Set the callback before connect — normal usage path.
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

	// Concurrently overwrite the callback using thread-safe setter while
	// connect/auth is happening. Without the snapshot pattern this would race.
	for i := 0; i < 20; i++ {
		server.SetAuthenticatingHandler(func(args *AuthenticatingEventArgs) {
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
