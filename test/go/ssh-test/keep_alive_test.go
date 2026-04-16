// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const keepAliveTestTimeout = 10 * time.Second

// TestKeepAliveTimerFires verifies the timer fires multiple times with both
// success and failure events.
func TestKeepAliveTimerFires(t *testing.T) {
	clientConfig := ssh.NewNoSecurityConfig()
	clientConfig.KeepAliveIntervalSeconds = 1

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan string, 10)
	pair.ClientSession.OnKeepAliveSucceeded = func(count int) {
		select {
		case events <- "success":
		default:
		}
	}
	pair.ClientSession.OnKeepAliveFailed = func(count int) {
		select {
		case events <- "failure":
		default:
		}
	}

	pair.Connect(ctx)

	// Collect events for 3.5s
	var collected []string
	timer := time.NewTimer(3500 * time.Millisecond)
	defer timer.Stop()
loop:
	for {
		select {
		case e := <-events:
			collected = append(collected, e)
			t.Logf("Event: %s (total: %d)", e, len(collected))
		case <-timer.C:
			break loop
		case <-ctx.Done():
			break loop
		}
	}

	t.Logf("Total events collected: %v", collected)
	assert.GreaterOrEqual(t, len(collected), 2, "expected at least 2 keep-alive events")
}

// TestKeepAliveOneMessage verifies that a keep-alive request is sent after the
// configured interval and the success event fires on the client.
func TestKeepAliveOneMessage(t *testing.T) {
	clientConfig := ssh.NewNoSecurityConfig()
	clientConfig.KeepAliveIntervalSeconds = 1
	serverConfig := ssh.NewNoSecurityConfig()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), keepAliveTestTimeout)
	defer cancel()

	var keepAliveCount atomic.Int32
	keepAliveDone := make(chan struct{}, 1)
	pair.ClientSession.OnKeepAliveSucceeded = func(count int) {
		if keepAliveCount.Add(1) == 1 {
			select {
			case keepAliveDone <- struct{}{}:
			default:
			}
		}
	}

	pair.Connect(ctx)

	// Wait for at least one keep-alive success event.
	select {
	case <-keepAliveDone:
	case <-ctx.Done():
		t.Fatal("timeout waiting for keep-alive success event")
	}

	// Allow a brief window to confirm only 1 keep-alive fired so far.
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, int32(1), keepAliveCount.Load())
}

// TestNoKeepAliveWhenActive verifies that no keep-alive is sent when the session
// has recent message activity (timer resets on each received message).
func TestNoKeepAliveWhenActive(t *testing.T) {
	clientConfig := ssh.NewNoSecurityConfig()
	clientConfig.KeepAliveIntervalSeconds = 1
	serverConfig := ssh.NewNoSecurityConfig()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), keepAliveTestTimeout)
	defer cancel()

	var keepAliveEventFired atomic.Bool
	pair.ClientSession.OnKeepAliveSucceeded = func(count int) {
		keepAliveEventFired.Store(true)
	}
	pair.ClientSession.OnKeepAliveFailed = func(count int) {
		keepAliveEventFired.Store(true)
	}

	pair.Connect(ctx)

	// Send messages from server to client every 500ms to keep the session active.
	// This should prevent keep-alive timer from firing (1s interval > 500ms activity).
	for i := 0; i < 5; i++ {
		msg := &messages.SessionRequestMessage{
			RequestType: "test",
			WantReply:   false,
		}
		_, err := pair.ServerSession.Request(ctx, msg)
		require.NoError(t, err)
		time.Sleep(500 * time.Millisecond)
	}

	assert.False(t, keepAliveEventFired.Load(), "keep-alive should not fire when session is active")
}

// TestKeepAliveFailureEvent verifies that failure events fire when the remote side
// is not responding (blocked on a long-running request handler).
func TestKeepAliveFailureEvent(t *testing.T) {
	clientConfig := ssh.NewNoSecurityConfig()
	clientConfig.KeepAliveIntervalSeconds = 1
	serverConfig := ssh.NewNoSecurityConfig()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), keepAliveTestTimeout)
	defer cancel()

	var keepAliveFailedCount atomic.Int32
	pair.ClientSession.OnKeepAliveFailed = func(count int) {
		keepAliveFailedCount.Store(int32(count))
	}

	// Server handler blocks for 5s on "first" request, preventing
	// keep-alive responses from reaching the client during that time.
	pair.ServerSession.OnRequest = func(args *ssh.RequestEventArgs) {
		if args.RequestType == "first" {
			args.IsAuthorized = true
			time.Sleep(5 * time.Second)
		}
	}

	pair.Connect(ctx)

	msg := &messages.SessionRequestMessage{
		RequestType: "first",
		WantReply:   true,
	}
	success, err := pair.ClientSession.Request(ctx, msg)
	require.NoError(t, err)
	require.True(t, success)

	// During the 5s server delay, the keep-alive timer fires at ~1s, ~2s, ~3s, ~4s.
	// First fire sees keepAliveResponseReceived=true (from connection) → success.
	// Subsequent fires see false → failure events (count >= 2).
	assert.GreaterOrEqual(t, keepAliveFailedCount.Load(), int32(2))
}
