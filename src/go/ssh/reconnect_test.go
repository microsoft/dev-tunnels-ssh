// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/algorithms"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

func TestProtocolSequenceTrackingUint64(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	// Verify initial sequences are 0.
	if p1.SendSequence != 0 {
		t.Errorf("initial SendSequence = %d, want 0", p1.SendSequence)
	}
	if atomic.LoadUint64(&p2.ReceiveSequence) != 0 {
		t.Errorf("initial ReceiveSequence = %d, want 0", atomic.LoadUint64(&p2.ReceiveSequence))
	}

	payload := []byte{0x05, 0x01, 0x02}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	_, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if p1.SendSequence != 1 {
		t.Errorf("SendSequence = %d, want 1", p1.SendSequence)
	}
	if atomic.LoadUint64(&p2.ReceiveSequence) != 1 {
		t.Errorf("ReceiveSequence = %d, want 1", atomic.LoadUint64(&p2.ReceiveSequence))
	}
}

func TestProtocolReconnectInfoRoundTrip(t *testing.T) {
	// Test that reconnect info bytes are appended on send and stripped on receive,
	// resulting in the original payload being received.
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	metrics1 := &SessionMetrics{}
	metrics2 := &SessionMetrics{}
	p1 := newSSHProtocol(s1, metrics1)
	p2 := newSSHProtocol(s2, metrics2)

	// Enable reconnect info (no latency).
	p1.OutgoingMessagesHaveReconnectInfo = 1
	p2.IncomingMessagesHaveReconnectInfo = 1

	// Also enable caching on p1 (p1 receives from p2, so p2's incoming triggers cache).
	// Actually: IncomingMessagesHaveReconnectInfo on the SENDER controls caching.
	// The receiver's IncomingMessagesHaveReconnectInfo controls stripping.
	// p1 sends, p2 receives. p2 strips. p1 caches based on p1.IncomingMessagesHaveReconnectInfo.
	p1.IncomingMessagesHaveReconnectInfo = 1

	payload := []byte{0x05, 0x01, 0x02, 0x03}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	// The received payload should be the original (reconnect info stripped).
	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}
}

func TestProtocolReconnectInfoWithLatencyRoundTrip(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	metrics1 := &SessionMetrics{}
	metrics2 := &SessionMetrics{}
	p1 := newSSHProtocol(s1, metrics1)
	p2 := newSSHProtocol(s2, metrics2)

	// Enable reconnect info WITH latency.
	p1.OutgoingMessagesHaveReconnectInfo = 1
	p1.OutgoingMessagesHaveLatencyInfo = 1
	p2.IncomingMessagesHaveReconnectInfo = 1
	p2.IncomingMessagesHaveLatencyInfo = 1

	payload := []byte{0x05, 0xAA, 0xBB, 0xCC, 0xDD}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}
}

func TestProtocolReconnectInfoEncryptedRoundTrip(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	metrics1 := &SessionMetrics{}
	metrics2 := &SessionMetrics{}
	p1 := newSSHProtocol(s1, metrics1)
	p2 := newSSHProtocol(s2, metrics2)

	// Set up encryption.
	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())
	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	// Enable reconnect info.
	p1.OutgoingMessagesHaveReconnectInfo = 1
	p2.IncomingMessagesHaveReconnectInfo = 1

	payload := []byte{0x15, 0x01, 0x02, 0x03, 0x04, 0x05}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}
}

func TestProtocolMessageCaching(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	// Enable caching: IncomingMessagesHaveReconnectInfo on sender.
	p1.IncomingMessagesHaveReconnectInfo = 1

	msg1 := []byte{0x05, 0x01}
	msg2 := []byte{0x05, 0x02}
	msg3 := []byte{0x05, 0x03}

	done := make(chan error, 1)
	go func() {
		if err := p1.sendMessage(msg1); err != nil {
			done <- err
			return
		}
		if err := p1.sendMessage(msg2); err != nil {
			done <- err
			return
		}
		if err := p1.sendMessage(msg3); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	for i := 0; i < 3; i++ {
		_, err := p2.receiveMessage()
		if err != nil {
			t.Fatalf("receiveMessage %d failed: %v", i, err)
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	// Verify 3 messages are cached.
	p1.cacheMu.Lock()
	cacheLen := len(p1.recentSentMessages)
	p1.cacheMu.Unlock()

	if cacheLen != 3 {
		t.Errorf("cache size = %d, want 3", cacheLen)
	}

	// Verify cached payloads match.
	p1.cacheMu.Lock()
	if !bytes.Equal(p1.recentSentMessages[0].Payload, msg1) {
		t.Errorf("cached[0] = %v, want %v", p1.recentSentMessages[0].Payload, msg1)
	}
	if !bytes.Equal(p1.recentSentMessages[1].Payload, msg2) {
		t.Errorf("cached[1] = %v, want %v", p1.recentSentMessages[1].Payload, msg2)
	}
	if !bytes.Equal(p1.recentSentMessages[2].Payload, msg3) {
		t.Errorf("cached[2] = %v, want %v", p1.recentSentMessages[2].Payload, msg3)
	}
	p1.cacheMu.Unlock()
}

func TestProtocolCachePurgeOnAcknowledge(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	metrics1 := &SessionMetrics{}
	metrics2 := &SessionMetrics{}
	p1 := newSSHProtocol(s1, metrics1)
	p2 := newSSHProtocol(s2, metrics2)

	// Enable reconnect info bidirectionally.
	// p1 sends with reconnect info, p2 strips it.
	// p2 sends with reconnect info, p1 strips it and purges cache.
	p1.OutgoingMessagesHaveReconnectInfo = 1
	p1.IncomingMessagesHaveReconnectInfo = 1
	p2.OutgoingMessagesHaveReconnectInfo = 1
	p2.IncomingMessagesHaveReconnectInfo = 1

	// p1 sends 3 messages.
	msg1 := []byte{0x05, 0x01}
	msg2 := []byte{0x05, 0x02}
	msg3 := []byte{0x05, 0x03}

	done := make(chan error, 1)
	go func() {
		if err := p1.sendMessage(msg1); err != nil {
			done <- err
			return
		}
		if err := p1.sendMessage(msg2); err != nil {
			done <- err
			return
		}
		if err := p1.sendMessage(msg3); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	// p2 receives the 3 messages.
	for i := 0; i < 3; i++ {
		_, err := p2.receiveMessage()
		if err != nil {
			t.Fatalf("p2.receiveMessage %d failed: %v", i, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("p1.sendMessage failed: %v", err)
	}

	// p1 should have 3 cached messages.
	p1.cacheMu.Lock()
	if len(p1.recentSentMessages) != 3 {
		t.Fatalf("p1 cache size = %d, want 3", len(p1.recentSentMessages))
	}
	p1.cacheMu.Unlock()

	// Now p2 sends a message back. This message will include p2's LastIncomingSequence
	// (ReceiveSequence-1 = 2, since p2 received 3 messages: seq 0, 1, 2).
	// When p1 receives this, it should purge cached messages with seq <= 2.
	reply := []byte{0x05, 0x99}
	done2 := make(chan error, 1)
	go func() {
		done2 <- p2.sendMessage(reply)
	}()

	_, err := p1.receiveMessage()
	if err != nil {
		t.Fatalf("p1.receiveMessage failed: %v", err)
	}
	if err := <-done2; err != nil {
		t.Fatalf("p2.sendMessage failed: %v", err)
	}

	// All 3 messages (seq 0, 1, 2) should be purged since p2 acknowledged seq 2.
	p1.cacheMu.Lock()
	remaining := len(p1.recentSentMessages)
	p1.cacheMu.Unlock()

	if remaining != 0 {
		t.Errorf("p1 cache size after purge = %d, want 0", remaining)
	}
}

func TestProtocolGetSentMessagesUpToDate(t *testing.T) {
	p := newSSHProtocol(nil, nil)

	// If the starting sequence equals the current send sequence,
	// the remote side is up to date.
	result := p.GetSentMessages(0)
	if result == nil || len(result) != 0 {
		t.Errorf("expected empty slice for up-to-date, got %v", result)
	}
}

func TestProtocolGetSentMessagesPurged(t *testing.T) {
	p := newSSHProtocol(nil, nil)
	p.IncomingMessagesHaveReconnectInfo = 1

	// Manually add cached messages starting at sequence 5.
	p.cacheMu.Lock()
	p.recentSentMessages = append(p.recentSentMessages,
		SequencedMessage{Sequence: 5, Payload: []byte{0x05, 0x01}},
		SequencedMessage{Sequence: 6, Payload: []byte{0x05, 0x02}},
	)
	p.cacheMu.Unlock()
	p.SendSequence = 7

	// Request from sequence 3, which is before our earliest cached message.
	result := p.GetSentMessages(3)
	if result != nil {
		t.Errorf("expected nil for purged messages, got %v", result)
	}
}

func TestProtocolGetSentMessagesRetrieval(t *testing.T) {
	p := newSSHProtocol(nil, nil)
	p.IncomingMessagesHaveReconnectInfo = 1

	// Add cached messages.
	p.cacheMu.Lock()
	p.recentSentMessages = append(p.recentSentMessages,
		SequencedMessage{Sequence: 0, Payload: []byte{0x05, 0x01}},
		SequencedMessage{Sequence: 1, Payload: []byte{0x05, 0x02}},
		SequencedMessage{Sequence: 2, Payload: []byte{0x05, 0x03}},
		SequencedMessage{Sequence: 3, Payload: []byte{0x05, 0x04}},
	)
	p.cacheMu.Unlock()
	p.SendSequence = 4

	// Get messages from sequence 2.
	result := p.GetSentMessages(2)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(result))
	}
	if !bytes.Equal(result[0], []byte{0x05, 0x03}) {
		t.Errorf("result[0] = %v, want [5 3]", result[0])
	}
	if !bytes.Equal(result[1], []byte{0x05, 0x04}) {
		t.Errorf("result[1] = %v, want [5 4]", result[1])
	}
}

func TestProtocolGetSentMessagesFiltersKexAndDisconnect(t *testing.T) {
	p := newSSHProtocol(nil, nil)
	p.IncomingMessagesHaveReconnectInfo = 1

	// Add cached messages with mixed types.
	p.cacheMu.Lock()
	p.recentSentMessages = append(p.recentSentMessages,
		SequencedMessage{Sequence: 0, Payload: []byte{messages.MsgNumChannelData, 0x01}},       // should keep
		SequencedMessage{Sequence: 1, Payload: []byte{messages.MsgNumKeyExchangeInit, 0x02}},   // should filter
		SequencedMessage{Sequence: 2, Payload: []byte{messages.MsgNumNewKeys}},                  // should filter
		SequencedMessage{Sequence: 3, Payload: []byte{messages.MsgNumDisconnect, 0x03}},         // should filter
		SequencedMessage{Sequence: 4, Payload: []byte{messages.MsgNumChannelOpen, 0x04}},        // should keep
		SequencedMessage{Sequence: 5, Payload: []byte{messages.MsgNumKeyExchangeDhInit, 0x05}},  // should filter
		SequencedMessage{Sequence: 6, Payload: []byte{messages.MsgNumKeyExchangeDhReply, 0x06}}, // should filter
	)
	p.cacheMu.Unlock()
	p.SendSequence = 7

	result := p.GetSentMessages(0)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 messages (filtered KEX + disconnect), got %d", len(result))
	}
	if result[0][0] != messages.MsgNumChannelData {
		t.Errorf("result[0] type = %d, want %d", result[0][0], messages.MsgNumChannelData)
	}
	if result[1][0] != messages.MsgNumChannelOpen {
		t.Errorf("result[1] type = %d, want %d", result[1][0], messages.MsgNumChannelOpen)
	}
}

func TestProtocolLastIncomingSequence(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	// Send 3 messages from p1 to p2.
	payloads := [][]byte{
		{0x05, 0x01},
		{0x05, 0x02},
		{0x05, 0x03},
	}

	done := make(chan error, 1)
	go func() {
		for _, p := range payloads {
			if err := p1.sendMessage(p); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i := 0; i < 3; i++ {
		_, err := p2.receiveMessage()
		if err != nil {
			t.Fatalf("receiveMessage %d failed: %v", i, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	// p2 received 3 messages (seq 0, 1, 2). LastIncomingSequence = 2.
	lastSeq := p2.LastIncomingSequence()
	if lastSeq != 2 {
		t.Errorf("LastIncomingSequence = %d, want 2", lastSeq)
	}
}

func TestProtocolReconnectInfoSendsLastIncomingSequence(t *testing.T) {
	// Verify that the reconnect info bytes contain the correct LastIncomingSequence.
	// Use a buffer-based stream to inspect wire bytes.
	buf := &bufferCloser{}
	metrics := &SessionMetrics{}
	p := newSSHProtocol(buf, metrics)
	p.OutgoingMessagesHaveReconnectInfo = 1

	// Simulate that p has received 5 messages (ReceiveSequence = 5).
	p.ReceiveSequence = 5

	payload := []byte{0x05, 0x01, 0x02}
	err := p.sendMessage(payload)
	if err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	// Read the wire bytes: the payload portion should contain the original payload
	// + 8 bytes of LastIncomingSequence (which should be 4 = ReceiveSequence-1).
	wireBytes := buf.Bytes()
	if len(wireBytes) == 0 {
		t.Fatal("no wire bytes written")
	}

	// Parse the packet to extract the payload portion.
	packetLength := binary.BigEndian.Uint32(wireBytes[0:4])
	paddingLength := wireBytes[4]
	payloadLen := int(packetLength) - 1 - int(paddingLength) // -1 for padding_length byte
	rawPayload := wireBytes[5 : 5+payloadLen]

	// The raw payload should be: original (3 bytes) + reconnect info (8 bytes) = 11 bytes.
	expectedLen := len(payload) + 8
	if len(rawPayload) != expectedLen {
		t.Fatalf("raw payload len = %d, want %d", len(rawPayload), expectedLen)
	}

	// Verify the original payload.
	if !bytes.Equal(rawPayload[:len(payload)], payload) {
		t.Errorf("original payload mismatch")
	}

	// Verify the LastIncomingSequence value.
	lastSeq := binary.BigEndian.Uint64(rawPayload[len(payload):])
	if lastSeq != 4 {
		t.Errorf("LastIncomingSequence in wire = %d, want 4", lastSeq)
	}
}

func TestReconnectTokenCreateAndVerify(t *testing.T) {
	// Create two sessions with encryption so they have HMAC algorithms.
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	metrics1 := &SessionMetrics{}
	p1 := newSSHProtocol(s1, metrics1)
	session := &Session{
		Config:   NewDefaultConfig(),
		protocol: p1,
	}

	// Set up test algorithms with HMAC signer/verifier.
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())
	session.currentAlgorithms = &sessionAlgorithms{
		Signer:   signer,
		Verifier: verifier,
	}

	previousSessionID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}
	newSessionID := []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40}

	// Create token.
	token, err := session.CreateReconnectToken(previousSessionID, newSessionID)
	if err != nil {
		t.Fatalf("CreateReconnectToken failed: %v", err)
	}
	if len(token) == 0 {
		t.Fatal("token is empty")
	}

	// Verify token (should succeed).
	valid, err := session.VerifyReconnectToken(previousSessionID, newSessionID, token)
	if err != nil {
		t.Fatalf("VerifyReconnectToken failed: %v", err)
	}
	if !valid {
		t.Error("expected token to be valid")
	}
}

func TestReconnectTokenVerifyFailsWithWrongSessionID(t *testing.T) {
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())
	session := &Session{
		Config: NewDefaultConfig(),
		currentAlgorithms: &sessionAlgorithms{
			Signer:   signer,
			Verifier: verifier,
		},
	}

	previousSessionID := make([]byte, 32)
	newSessionID := make([]byte, 32)
	for i := range previousSessionID {
		previousSessionID[i] = byte(i)
	}
	for i := range newSessionID {
		newSessionID[i] = byte(i + 32)
	}

	token, err := session.CreateReconnectToken(previousSessionID, newSessionID)
	if err != nil {
		t.Fatalf("CreateReconnectToken failed: %v", err)
	}

	// Verify with wrong previousSessionID.
	wrongPrevID := make([]byte, 32)
	copy(wrongPrevID, previousSessionID)
	wrongPrevID[0] = 0xFF

	valid, err := session.VerifyReconnectToken(wrongPrevID, newSessionID, token)
	if err != nil {
		t.Fatalf("VerifyReconnectToken failed: %v", err)
	}
	if valid {
		t.Error("expected token to be invalid with wrong previousSessionID")
	}

	// Verify with wrong newSessionID.
	wrongNewID := make([]byte, 32)
	copy(wrongNewID, newSessionID)
	wrongNewID[0] = 0xFF

	valid, err = session.VerifyReconnectToken(previousSessionID, wrongNewID, token)
	if err != nil {
		t.Fatalf("VerifyReconnectToken failed: %v", err)
	}
	if valid {
		t.Error("expected token to be invalid with wrong newSessionID")
	}
}

func TestReconnectTokenVerifyFailsWithWrongToken(t *testing.T) {
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())
	session := &Session{
		Config: NewDefaultConfig(),
		currentAlgorithms: &sessionAlgorithms{
			Signer:   signer,
			Verifier: verifier,
		},
	}

	previousSessionID := make([]byte, 32)
	newSessionID := make([]byte, 32)
	for i := range previousSessionID {
		previousSessionID[i] = byte(i)
	}
	for i := range newSessionID {
		newSessionID[i] = byte(i + 32)
	}

	// Create a token and then tamper with it.
	token, err := session.CreateReconnectToken(previousSessionID, newSessionID)
	if err != nil {
		t.Fatalf("CreateReconnectToken failed: %v", err)
	}

	tamperedToken := make([]byte, len(token))
	copy(tamperedToken, token)
	tamperedToken[0] ^= 0xFF

	valid, err := session.VerifyReconnectToken(previousSessionID, newSessionID, tamperedToken)
	if err != nil {
		t.Fatalf("VerifyReconnectToken failed: %v", err)
	}
	if valid {
		t.Error("expected tampered token to be invalid")
	}
}

func TestReconnectTokenFailsWithoutAlgorithms(t *testing.T) {
	session := &Session{
		Config: NewDefaultConfig(),
	}

	previousSessionID := make([]byte, 32)
	newSessionID := make([]byte, 32)

	// CreateReconnectToken should return error without algorithms.
	_, err := session.CreateReconnectToken(previousSessionID, newSessionID)
	if err == nil {
		t.Error("expected error without algorithms")
	}

	// VerifyReconnectToken should return error without algorithms.
	_, err = session.VerifyReconnectToken(previousSessionID, newSessionID, make([]byte, 32))
	if err == nil {
		t.Error("expected error without algorithms")
	}
}

func TestProtocolCacheNotPopulatedWithoutFlag(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	// Do NOT enable IncomingMessagesHaveReconnectInfo on p1.
	payload := []byte{0x05, 0x01}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	_, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	// Cache should be empty since IncomingMessagesHaveReconnectInfo is false.
	p1.cacheMu.Lock()
	cacheLen := len(p1.recentSentMessages)
	p1.cacheMu.Unlock()

	if cacheLen != 0 {
		t.Errorf("cache size = %d, want 0 (caching not enabled)", cacheLen)
	}
}

func TestReconnectTokenWithSha512(t *testing.T) {
	signer, verifier := createHmacPair(algorithms.NewHmacSha512())
	session := &Session{
		Config: NewDefaultConfig(),
		currentAlgorithms: &sessionAlgorithms{
			Signer:   signer,
			Verifier: verifier,
		},
	}

	previousSessionID := make([]byte, 32)
	newSessionID := make([]byte, 32)
	for i := range previousSessionID {
		previousSessionID[i] = byte(i)
	}
	for i := range newSessionID {
		newSessionID[i] = byte(i + 32)
	}

	token, err := session.CreateReconnectToken(previousSessionID, newSessionID)
	if err != nil {
		t.Fatalf("CreateReconnectToken failed: %v", err)
	}

	// SHA-512 HMAC produces 64-byte digest.
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64", len(token))
	}

	valid, err := session.VerifyReconnectToken(previousSessionID, newSessionID, token)
	if err != nil {
		t.Fatalf("VerifyReconnectToken failed: %v", err)
	}
	if !valid {
		t.Error("expected token to be valid")
	}
}
