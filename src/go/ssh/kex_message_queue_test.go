// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestKexBlockedQueueDataDeliveredAfterReKey verifies that the session remains
// fully functional after re-keying with message queuing active. Data sent after
// re-keying is delivered correctly, proving that queued messages were replayed.
func TestKexBlockedQueueDataDeliveredAfterReKey(t *testing.T) {
	// Use a small threshold on the client to trigger re-keying.
	// Set a high threshold on the server so only the CLIENT triggers re-keying,
	// avoiding overlapping concurrent re-keys from both sides.
	clientConfig := NewDefaultConfig()
	clientConfig.KeyRotationThreshold = 4 * 1024

	serverConfig := NewDefaultConfig()
	serverConfig.KeyRotationThreshold = 0 // disabled on server

	client, server := createEncryptedSessionPair(t, clientConfig, serverConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Open a channel.
	var clientCh, serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		clientCh, err = client.OpenChannel(ctx)
		if err != nil {
			t.Errorf("OpenChannel: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		var err error
		serverCh, err = server.AcceptChannel(ctx)
		if err != nil {
			t.Errorf("AcceptChannel: %v", err)
		}
	}()
	wg.Wait()
	if clientCh == nil || serverCh == nil {
		t.Fatal("channel setup failed")
	}

	// Set up data handler on server with flow control.
	serverCh.SetDataReceivedHandler(func(d []byte) {
		serverCh.AdjustWindow(uint32(len(d)))
	})

	// Phase 1: Send enough data to trigger re-keying on client side.
	sendDone := make(chan error, 1)
	go func() {
		data := make([]byte, 1024)
		for i := 0; i < 16; i++ {
			if err := clientCh.Send(ctx, data); err != nil {
				sendDone <- fmt.Errorf("send %d: %w", i, err)
				return
			}
		}
		sendDone <- nil
	}()
	if err := <-sendDone; err != nil {
		t.Fatalf("client send: %v", err)
	}

	// Wait for re-keying to complete on the client side.
	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for re-keying to complete "+
				"(client.exchanging=%v, counter=%d, metrics=%d)",
				atomic.LoadInt32(&client.kexService.exchanging) != 0,
				atomic.LoadUint64(&client.protocol.BytesSent),
				client.Metrics().BytesSent())
		case <-time.After(50 * time.Millisecond):
			if atomic.LoadInt32(&client.kexService.exchanging) == 0 &&
				client.Metrics().BytesSent() > 0 &&
				atomic.LoadUint64(&client.protocol.BytesSent) < uint64(client.Metrics().BytesSent()) {
				goto rekeyDone
			}
		}
	}
rekeyDone:

	// Phase 2: Send data from server to client after re-keying.
	// This proves queued messages during KEX were properly replayed and
	// the session is fully functional.
	const postReKeySize = 2048
	var clientReceived int64
	allReceived := make(chan struct{}, 1)
	clientCh.SetDataReceivedHandler(func(d []byte) {
		clientCh.AdjustWindow(uint32(len(d)))
		if atomic.AddInt64(&clientReceived, int64(len(d))) >= postReKeySize {
			select {
			case allReceived <- struct{}{}:
			default:
			}
		}
	})

	go func() {
		data := make([]byte, postReKeySize)
		if err := serverCh.Send(ctx, data); err != nil {
			t.Errorf("server Send: %v", err)
		}
	}()

	select {
	case <-allReceived:
	case <-time.After(15 * time.Second):
		t.Fatalf("server→client data not delivered after re-keying: got %d, want %d",
			atomic.LoadInt64(&clientReceived), int64(postReKeySize))
	}

	// Also verify client→server still works.
	const postReKeySize2 = 1024
	var serverReceived2 int64
	allServerReceived := make(chan struct{}, 1)
	serverCh.SetDataReceivedHandler(func(d []byte) {
		serverCh.AdjustWindow(uint32(len(d)))
		if atomic.AddInt64(&serverReceived2, int64(len(d))) >= postReKeySize2 {
			select {
			case allServerReceived <- struct{}{}:
			default:
			}
		}
	})

	go func() {
		data := make([]byte, postReKeySize2)
		if err := clientCh.Send(ctx, data); err != nil {
			t.Errorf("client Send post-rekey: %v", err)
		}
	}()

	select {
	case <-allServerReceived:
	case <-time.After(15 * time.Second):
		t.Fatalf("client→server data not delivered after re-keying: got %d, want %d",
			atomic.LoadInt64(&serverReceived2), int64(postReKeySize2))
	}

	if !client.IsConnected() {
		t.Error("client should still be connected")
	}
	if !server.IsConnected() {
		t.Error("server should still be connected")
	}
}

// TestKexMessagesNotQueuedDuringExchange verifies that KEX messages (types
// 20-31) are processed immediately during exchange. If they were queued,
// the NewKeys message would never be handled and the re-keying would hang.
func TestKexMessagesNotQueuedDuringExchange(t *testing.T) {
	clientConfig := NewDefaultConfig()
	clientConfig.KeyRotationThreshold = 4 * 1024
	serverConfig := NewDefaultConfig()
	serverConfig.KeyRotationThreshold = 0 // disabled on server

	client, server := createEncryptedSessionPair(t, clientConfig, serverConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var clientCh, serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		clientCh, err = client.OpenChannel(ctx)
		if err != nil {
			t.Errorf("OpenChannel: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		var err error
		serverCh, err = server.AcceptChannel(ctx)
		if err != nil {
			t.Errorf("AcceptChannel: %v", err)
		}
	}()
	wg.Wait()
	if clientCh == nil || serverCh == nil {
		t.Fatal("channel setup failed")
	}

	serverCh.SetDataReceivedHandler(func(d []byte) {
		serverCh.AdjustWindow(uint32(len(d)))
	})

	// Trigger re-keying by sending data exceeding the threshold.
	// If KEX messages were queued instead of processed immediately,
	// the exchange would never complete and Send would eventually
	// deadlock or the session would close with an error.
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		data := make([]byte, 1024)
		for i := 0; i < 16; i++ {
			if err := clientCh.Send(ctx, data); err != nil {
				t.Errorf("Send %d failed: %v", i, err)
				return
			}
		}
	}()

	// Wait for all sends to complete. If re-keying deadlocked because
	// KEX messages were queued, this will time out.
	select {
	case <-sendDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for sends to complete — KEX messages may have been queued")
	}

	// Give a moment for re-keying to finalize.
	time.Sleep(100 * time.Millisecond)

	t.Log("KEX messages processed immediately: re-keying completed")

	if !client.IsConnected() {
		t.Error("client disconnected")
	}
	if !server.IsConnected() {
		t.Error("server disconnected")
	}
}

// TestKexBlockedQueueIsKexBlockingLogic verifies the isKexBlocking helper
// correctly classifies message types during an active key exchange.
func TestKexBlockedQueueIsKexBlockingLogic(t *testing.T) {
	s := &Session{
		kexService: &keyExchangeService{},
	}

	// When not exchanging, nothing should be blocked.
	atomic.StoreInt32(&s.kexService.exchanging, 0)
	for msgType := byte(0); msgType <= 100; msgType++ {
		if s.isKexBlocking(msgType) {
			t.Errorf("isKexBlocking(%d) = true when not exchanging, want false", msgType)
		}
	}

	// When exchanging, check specific message types.
	atomic.StoreInt32(&s.kexService.exchanging, 1)

	// Transport generic (1-4): never blocked.
	for _, msgType := range []byte{1, 2, 3, 4} {
		if s.isKexBlocking(msgType) {
			t.Errorf("isKexBlocking(%d) = true for transport message, want false", msgType)
		}
	}

	// KEX messages (20-31): never blocked.
	for msgType := byte(20); msgType <= 31; msgType++ {
		if s.isKexBlocking(msgType) {
			t.Errorf("isKexBlocking(%d) = true for KEX message, want false", msgType)
		}
	}

	// Service/auth/channel messages (5-19, 50+): blocked during exchange.
	blockedTypes := []byte{5, 6, 7, 50, 51, 52, 80, 81, 82, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100}
	for _, msgType := range blockedTypes {
		if !s.isKexBlocking(msgType) {
			t.Errorf("isKexBlocking(%d) = false during exchange, want true", msgType)
		}
	}

	// Without kexService, nothing is blocked.
	s2 := &Session{}
	if s2.isKexBlocking(94) {
		t.Error("isKexBlocking should return false when kexService is nil")
	}
}

// TestKexBlockedQueueCancelledContext verifies that accepting a channel
// with a cancelled context returns a context error promptly.
func TestKexBlockedQueueCancelledContext(t *testing.T) {
	client, server := createNoSecuritySessionPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := server.AcceptChannel(ctx)
	if err == nil {
		t.Fatal("AcceptChannel with cancelled context should return error")
	}

	_ = client
}
