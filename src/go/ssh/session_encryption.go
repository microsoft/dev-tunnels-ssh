// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"fmt"
	"sync/atomic"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/algorithms"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// activateNewKeys activates the negotiated encryption after receiving NewKeys.
func (s *Session) activateNewKeys() error {
	if s.kexService == nil {
		return nil
	}

	// Wait for our own NewKeys to be sent before activating send encryption.
	// This ensures NewKeys itself is sent with old (or no) encryption.
	if s.kexService.newKeysSent != nil {
		<-s.kexService.newKeysSent
		s.kexService.newKeysSent = nil
	}

	algs := s.kexService.finishKeyExchange()
	if algs == nil {
		return nil
	}

	// Store the negotiated algorithms for reconnect token operations.
	// Hold the session lock to synchronize with concurrent readers
	// (e.g., reconnectSigner/reconnectVerifier from reconnect goroutines).
	s.mu.Lock()
	s.currentAlgorithms = algs
	s.mu.Unlock()

	// Activate encryption on the protocol layer.
	s.protocol.SetEncryption(algs.Cipher, algs.Decipher, algs.Signer, algs.Verifier)

	// Reset byte counters for key rotation.
	atomic.StoreUint64(&s.protocol.BytesSent, 0)
	atomic.StoreUint64(&s.protocol.BytesReceived, 0)

	// Send extension info in a goroutine to avoid pipe deadlock.
	// Both sides' dispatch loops send extension info simultaneously after NewKeys;
	// using a goroutine lets the dispatch loop continue reading so the peer's
	// extension info write can complete.
	if algs.IsExtensionInfoRequested {
		kexSvc := s.kexService
		go func() {
			if err := kexSvc.sendExtensionInfo(); err != nil {
				s.close(messages.DisconnectProtocolError, err.Error(), false, false)
			}
		}()
	}

	// Signal that key exchange is complete.
	if s.kexDone != nil {
		select {
		case <-s.kexDone:
			// already closed
		default:
			close(s.kexDone)
		}
	}

	return nil
}

// isKexBlocking returns true if the message should be queued because a key
// exchange is in progress and this is not a KEX or transport-generic message.
// Only called from the dispatch loop (single-threaded).
func (s *Session) isKexBlocking(msgType byte) bool {
	if s.kexService == nil {
		return false
	}
	// KEX messages (20-31) are always processed immediately during exchange.
	if isKeyExchangeMessage(msgType) {
		return false
	}
	// Transport-layer generic messages (Disconnect=1, Ignore=2,
	// Unimplemented=3, Debug=4) are always processed immediately per RFC 4253.
	if msgType <= messages.MsgNumDebug {
		return false
	}
	return s.kexService.exchanging
}

// replayKexBlockedQueue replays messages that were queued during key exchange.
// Called from the dispatch loop after handleMessage returns, when the exchange
// may have just completed (NewKeys processed or kex:none activated).
// Only called from the dispatch loop (single-threaded).
func (s *Session) replayKexBlockedQueue() error {
	if len(s.kexBlockedQueue) == 0 {
		return nil
	}
	// Only replay if key exchange is no longer in progress.
	if s.kexService != nil && s.kexService.exchanging {
		return nil
	}

	queue := s.kexBlockedQueue
	s.kexBlockedQueue = nil

	for _, payload := range queue {
		msgType := payload[0]
		if err := s.handleMessage(msgType, payload); err != nil {
			return err
		}
		// Check if a replayed message triggered a close.
		s.mu.Lock()
		closed := s.isClosed
		s.mu.Unlock()
		if closed {
			return nil
		}
	}
	return nil
}

// CreateReconnectToken generates an HMAC-based reconnect token from previous and
// new session IDs. The token proves knowledge of the old session ID without
// disclosing it, and prevents replay attacks by including the new session ID.
// Uses the dedicated reconnect HMAC signer (not the GCM cipher, which would
// race with the dispatch loop's packet encryption).
func (s *Session) CreateReconnectToken(previousSessionID, newSessionID []byte) ([]byte, error) {
	signer := s.reconnectSigner()
	if signer == nil {
		return nil, &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "connection lost while creating reconnect token",
		}
	}

	data := make([]byte, len(previousSessionID)+len(newSessionID))
	copy(data, previousSessionID)
	copy(data[len(previousSessionID):], newSessionID)

	token := signer.Sign(data)
	return token, nil
}

// VerifyReconnectToken validates a reconnect token against the previous and new
// session IDs using the dedicated reconnect HMAC verifier.
func (s *Session) VerifyReconnectToken(previousSessionID, newSessionID, token []byte) (bool, error) {
	verifier := s.reconnectVerifier()
	if verifier == nil {
		return false, fmt.Errorf("hmac algorithm not available for reconnect token verification")
	}

	data := make([]byte, len(previousSessionID)+len(newSessionID))
	copy(data, previousSessionID)
	copy(data[len(previousSessionID):], newSessionID)

	return verifier.Verify(data, token), nil
}

// reconnectSigner returns the dedicated reconnect HMAC signer, falling back to the
// regular Signer if no dedicated one exists (non-GCM modes).
// Holds the session lock to synchronize with activateNewKeys updating currentAlgorithms.
func (s *Session) reconnectSigner() algorithms.MessageSigner {
	s.mu.Lock()
	algs := s.currentAlgorithms
	s.mu.Unlock()
	if algs == nil {
		return nil
	}
	if algs.ReconnectSigner != nil {
		return algs.ReconnectSigner
	}
	return algs.Signer
}

// reconnectVerifier returns the dedicated reconnect HMAC verifier, falling back to
// the regular Verifier if no dedicated one exists (non-GCM modes).
// Holds the session lock to synchronize with activateNewKeys updating currentAlgorithms.
func (s *Session) reconnectVerifier() algorithms.MessageVerifier {
	s.mu.Lock()
	algs := s.currentAlgorithms
	s.mu.Unlock()
	if algs == nil {
		return nil
	}
	if algs.ReconnectVerifier != nil {
		return algs.ReconnectVerifier
	}
	return algs.Verifier
}

// Protocol returns the session's protocol layer. Used by reconnection logic
// to access sequence tracking and message cache.
func (s *Session) Protocol() *SSHProtocol {
	return s.protocol
}

