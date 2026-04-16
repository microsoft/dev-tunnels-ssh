// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"testing"
)

func TestProtocolMessageCacheDoesNotExceedMaxSize(t *testing.T) {
	// Test that recentSentMessages is bounded by maxCacheSize.
	// When more messages are cached than the limit, oldest are evicted.
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	// Set a small cache limit for testing.
	const cacheLimit = 5
	p1.maxCacheSize = cacheLimit

	// Enable reconnect caching on the sender (IncomingMessagesHaveReconnectInfo
	// on the sender controls whether sent messages are cached).
	p1.IncomingMessagesHaveReconnectInfo = 1

	// Send more messages than the cache limit.
	const totalMessages = 20
	payload := []byte{0x05, 0x01, 0x02}

	done := make(chan error, 1)
	go func() {
		for i := 0; i < totalMessages; i++ {
			if err := p1.sendMessage(payload); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i := 0; i < totalMessages; i++ {
		if _, err := p2.receiveMessage(); err != nil {
			t.Fatalf("receiveMessage %d failed: %v", i, err)
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	// Verify cache is bounded.
	p1.cacheMu.Lock()
	cacheLen := len(p1.recentSentMessages)
	p1.cacheMu.Unlock()

	if cacheLen > cacheLimit {
		t.Errorf("cache size = %d, want <= %d", cacheLen, cacheLimit)
	}
	if cacheLen != cacheLimit {
		t.Errorf("cache size = %d, want exactly %d (cache should be full)", cacheLen, cacheLimit)
	}

	// Verify the cached messages are the most recent ones (oldest evicted).
	p1.cacheMu.Lock()
	oldestSeq := p1.recentSentMessages[0].Sequence
	newestSeq := p1.recentSentMessages[cacheLen-1].Sequence
	p1.cacheMu.Unlock()

	expectedOldest := uint64(totalMessages - cacheLimit)
	if oldestSeq != expectedOldest {
		t.Errorf("oldest cached sequence = %d, want %d", oldestSeq, expectedOldest)
	}
	if newestSeq != uint64(totalMessages-1) {
		t.Errorf("newest cached sequence = %d, want %d", newestSeq, totalMessages-1)
	}
}

func TestProtocolMessageCacheUnlimited(t *testing.T) {
	// Test that with maxCacheSize = 0, the cache grows without limit.
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	// maxCacheSize = 0 means no limit (default).
	p1.maxCacheSize = 0
	p1.IncomingMessagesHaveReconnectInfo = 1

	const totalMessages = 50
	payload := []byte{0x05, 0x01}

	done := make(chan error, 1)
	go func() {
		for i := 0; i < totalMessages; i++ {
			if err := p1.sendMessage(payload); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i := 0; i < totalMessages; i++ {
		if _, err := p2.receiveMessage(); err != nil {
			t.Fatalf("receiveMessage %d failed: %v", i, err)
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	// With no limit, all messages should be cached.
	p1.cacheMu.Lock()
	cacheLen := len(p1.recentSentMessages)
	p1.cacheMu.Unlock()

	if cacheLen != totalMessages {
		t.Errorf("cache size = %d, want %d (unlimited cache)", cacheLen, totalMessages)
	}
}

func TestChannelNoAutoAdjustWindowWithoutHandler(t *testing.T) {
	// Test that a channel without an OnDataReceived handler does NOT
	// auto-adjust the window. This means the remote side will eventually
	// be back-pressured (window exhausted).
	session := &Session{
		Config: NewNoSecurityConfig(),
	}

	ch := newChannel(session, "test", 0)
	ch.RemoteChannelID = 1

	initialWindow := ch.windowSize

	// Simulate receiving data without a handler set.
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i)
	}

	// Deliver data to the channel (handler is nil, so it gets buffered).
	ch.handleDataReceived(data)

	// The window should NOT have been adjusted back up.
	// Since we consumed 1000 bytes, windowSize should remain at its initial value
	// because we're not calling AdjustWindow from handleDataReceived anymore.
	// The window tracking is done by AdjustWindow, which was previously called
	// auto. Now it's not called, so windowSize should remain unchanged.
	ch.mu.Lock()
	currentWindow := ch.windowSize
	pendingLen := len(ch.pendingData)
	ch.mu.Unlock()

	// Window should be unchanged since AdjustWindow was NOT called.
	if currentWindow != initialWindow {
		t.Errorf("windowSize changed from %d to %d; expected unchanged (no AdjustWindow call)", initialWindow, currentWindow)
	}

	// Data should be buffered.
	if pendingLen != 1 {
		t.Errorf("pendingData length = %d, want 1", pendingLen)
	}
}

func TestChannelSetDataReceivedHandlerFlushesBufferedData(t *testing.T) {
	// Ensure that buffered data is flushed when a handler is attached,
	// and the handler can call AdjustWindow to resume flow control.
	session := &Session{
		Config: NewNoSecurityConfig(),
	}

	ch := newChannel(session, "test", 0)
	ch.RemoteChannelID = 1

	// Buffer multiple data chunks without a handler.
	ch.handleDataReceived([]byte{1, 2, 3})
	ch.handleDataReceived([]byte{4, 5, 6})
	ch.handleDataReceived([]byte{7, 8, 9})

	ch.mu.Lock()
	pendingLen := len(ch.pendingData)
	ch.mu.Unlock()

	if pendingLen != 3 {
		t.Fatalf("pendingData length = %d, want 3", pendingLen)
	}

	// Attach a handler; it should receive all buffered data.
	var received [][]byte
	ch.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		received = append(received, buf)
	})

	if len(received) != 3 {
		t.Fatalf("handler called %d times, want 3", len(received))
	}

	// Verify each chunk.
	expected := [][]byte{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}}
	for i, exp := range expected {
		if len(received[i]) != len(exp) {
			t.Errorf("chunk %d: length = %d, want %d", i, len(received[i]), len(exp))
			continue
		}
		for j := range exp {
			if received[i][j] != exp[j] {
				t.Errorf("chunk %d byte %d: got %d, want %d", i, j, received[i][j], exp[j])
			}
		}
	}

	// After flushing, pendingData should be cleared.
	ch.mu.Lock()
	pendingLen = len(ch.pendingData)
	ch.mu.Unlock()
	if pendingLen != 0 {
		t.Errorf("pendingData after handler = %d, want 0", pendingLen)
	}
}
