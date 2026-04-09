// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// ReconnectableSessions is a thread-safe collection of disconnected server sessions
// awaiting reconnection. It must be shared across all ServerSession instances
// that should be able to reconnect to each other.
type ReconnectableSessions struct {
	mu       sync.Mutex
	sessions []*ServerSession
}

// NewReconnectableSessions creates a new empty collection.
func NewReconnectableSessions() *ReconnectableSessions {
	return &ReconnectableSessions{}
}

// Add adds a session to the collection if it isn't already present.
// Call this after a session is connected and reconnect is enabled to make
// it available for reconnection after disconnect.
func (r *ReconnectableSessions) Add(s *ServerSession) {
	r.add(s)
}

// add adds a session to the collection if it isn't already present.
func (r *ReconnectableSessions) add(s *ServerSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.sessions {
		if existing == s {
			return
		}
	}
	r.sessions = append(r.sessions, s)
}

// remove removes a session from the collection.
func (r *ReconnectableSessions) remove(s *ServerSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, existing := range r.sessions {
		if existing == s {
			r.sessions = append(r.sessions[:i], r.sessions[i+1:]...)
			return
		}
	}
}

// findByToken iterates through sessions and returns the one whose reconnect token
// matches. The matched session is removed from the collection.
// Uses the new session's algorithms for HMAC verification (matching C#/TS behavior).
// Falls back to old session's algorithms for kex:none (no-security mode).
func (r *ReconnectableSessions) findByToken(clientToken []byte, newSessionID []byte, newSession *Session) *ServerSession {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, s := range r.sessions {
		// Try new session's HMAC first (production path with real KEX).
		verifySession := newSession
		if newSession.reconnectVerifier() == nil {
			// Fall back to old session's algorithms (kex:none path).
			verifySession = &s.Session
		}
		valid, err := verifySession.VerifyReconnectToken(s.SessionID, newSessionID, clientToken)
		if err == nil && valid {
			// Remove from collection.
			r.sessions = append(r.sessions[:i], r.sessions[i+1:]...)
			return s
		}
	}
	return nil
}

// clear removes all sessions from the collection.
func (r *ReconnectableSessions) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions = nil
}

// enableReconnect activates reconnection support on this session.
// It sends an "enable-session-reconnect" session request to the remote side
// and enables outgoing reconnect info on the protocol.
//
// The enable message send and flag updates are performed atomically under
// protocol.sendMu. This prevents a concurrent sendMessage from sending a
// regular message between the enable message and the flag update — the remote
// side would expect reconnect info on that message but wouldn't find it.
func (s *Session) enableReconnect() error {
	enableMsg := &messages.SessionRequestMessage{
		RequestType: ExtensionRequestEnableSessionReconnect,
		WantReply:   false,
	}

	// Determine latency support before acquiring sendMu to avoid holding
	// the lock while reading session state.
	// Also snapshot the protocol pointer under mu to avoid a race with
	// handleReconnectRequest which may nil out protocol on a temporary session.
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil
	}
	proto := s.protocol
	extensions := s.ProtocolExtensions
	s.mu.Unlock()

	if proto == nil {
		return nil
	}

	hasLatencySupport := false
	if s.hasProtocolExtension(ExtensionSessionLatency) {
		if _, ok := extensions[ExtensionSessionLatency]; ok {
			hasLatencySupport = true
		}
	}

	// Acquire sendMu to atomically: send enable message + cache it + set flags.
	// No concurrent sendMessage can interleave between the enable message
	// and the flag update because sendMessage also acquires sendMu.
	proto.sendMu.Lock()
	enablePayload := enableMsg.ToBuffer()
	err := proto.sendMessageLocked(enablePayload)
	if err != nil {
		proto.sendMu.Unlock()
		return err
	}

	// Explicitly cache the enable message for reconnection retransmission.
	// This message is sent before IncomingMessagesHaveReconnectInfo is set
	// (the remote hasn't processed it yet), so sendMessageLocked's normal
	// caching path doesn't capture it. If the connection drops before the
	// remote receives this message, the next reconnect needs it in the cache.
	// Locking order: sendMu (held) → cacheMu (safe, matches sendMessageLocked).
	sentSeq := proto.SendSequence - 1 // sendMessageLocked already incremented
	sentTime := int64(0)
	if proto.metrics != nil {
		sentTime = proto.metrics.TimeMicroseconds()
	}
	proto.cacheMu.Lock()
	payloadCopy := make([]byte, len(enablePayload))
	copy(payloadCopy, enablePayload)
	proto.recentSentMessages = append(proto.recentSentMessages, SequencedMessage{
		Sequence: sentSeq,
		Payload:  payloadCopy,
		SentTime: sentTime,
	})
	proto.cacheMu.Unlock()

	// Set both flags before releasing sendMu so the next sendMessage sees them.
	if hasLatencySupport {
		atomic.StoreInt32(&proto.OutgoingMessagesHaveLatencyInfo, 1)
	}
	atomic.StoreInt32(&proto.OutgoingMessagesHaveReconnectInfo, 1)
	proto.sendMu.Unlock()

	// Mark reconnect as enabled on this session.
	s.mu.Lock()
	s.reconnectEnabled = true
	s.mu.Unlock()

	return nil
}

// handleEnableReconnectRequest processes the "enable-session-reconnect" session request
// from the remote side. This enables stripping of reconnect info from incoming messages
// and caching of our sent messages.
//
// Although the incoming flags are only read from the dispatch loop (same goroutine),
// we set the latency flag before the reconnect flag to maintain the invariant that
// once IncomingMessagesHaveReconnectInfo is set, IncomingMessagesHaveLatencyInfo
// already reflects the correct value. This mirrors the atomic pattern used in
// enableReconnect() for the outgoing side.
func (s *Session) handleEnableReconnectRequest() {
	// This is called from the dispatch loop, and ProtocolExtensions is only
	// written from the dispatch loop, so no lock is needed here.
	// Set latency flag BEFORE reconnect flag: once IncomingMessagesHaveReconnectInfo
	// is set, receiveMessage will strip reconnect info and must know the correct
	// size (with or without latency).
	if s.hasProtocolExtension(ExtensionSessionLatency) {
		if _, ok := s.ProtocolExtensions[ExtensionSessionLatency]; ok {
			atomic.StoreInt32(&s.protocol.IncomingMessagesHaveLatencyInfo, 1)
		}
	}
	atomic.StoreInt32(&s.protocol.IncomingMessagesHaveReconnectInfo, 1)

	// Signal that caching is now active. Reconnect() and handleReconnectRequest()
	// wait on this channel to guarantee caching before returning.
	s.protocol.reconnectInfoReadyOnce.Do(func() {
		close(s.protocol.reconnectInfoReady)
	})
}

// onDisconnected is called when the connection is lost. Returns true if the session
// should remain in a disconnected (but not closed) state for potential reconnection.
// Must be called with s.mu held.
func (s *Session) onDisconnected() bool {
	reconnecting := s.reconnecting
	reconnectEnabled := s.reconnectEnabled

	if reconnecting {
		// If we're in the middle of a reconnection attempt, don't keep disconnected
		// on the client side (the reconnect code manages state).
		return s.isClient == false
	}

	// Keep disconnected if reconnect extension was negotiated by both sides.
	if !reconnectEnabled {
		return false
	}

	if s.ProtocolExtensions == nil {
		return false
	}
	_, hasReconnect := s.ProtocolExtensions[ExtensionSessionReconnect]
	return hasReconnect
}

// disconnect transitions the session to a disconnected-but-not-closed state.
// The dispatch loop has already exited. Channels remain open for reconnection.
func (s *Session) disconnect(reason messages.SSHDisconnectReason, msg string) {
	s.mu.Lock()
	s.isConnected = false
kex := s.kexService
	onDisconnected := s.OnDisconnected
	s.mu.Unlock()

	s.trace(TraceLevelInfo, TraceEventSessionDisconnected,
		fmt.Sprintf("Session disconnected (reconnect enabled): reason=%d %s", reason, msg))

	// Reset current latency to 0 (disconnected).
	s.sessionMetrics.updateLatency(0)

	// Abort any in-progress key exchange.
	if kex != nil {
		kex.abortKeyExchange()
	}

	// Fire the disconnected callback.
	if onDisconnected != nil {
		onDisconnected()
	}
}

// reconnectState holds state saved before a reconnection attempt, used to restore
// session state if the reconnection fails at any step.
type reconnectState struct {
	protocol   *SSHProtocol
	sessionID  []byte
	algorithms *sessionAlgorithms
	hostKey    KeyPair
}

// restoreState restores session state after a failed reconnection step. If
// closeFirst is true, the current (new) connection is closed before restoring.
func (cs *ClientSession) restoreState(rs *reconnectState, closeFirst bool) {
	if closeFirst {
		cs.Close()
	}
	cs.protocol = rs.protocol
	cs.SessionID = rs.sessionID
	cs.mu.Lock()
	cs.currentAlgorithms = rs.algorithms
	cs.isConnected = false
	cs.isClosed = false
	cs.closedEventFired = false
	cs.mu.Unlock()
}

// Reconnect reconnects a disconnected client session over a new stream.
// The new stream must connect to the same server (same host key).
// After reconnection, channels continue operating normally.
func (cs *ClientSession) Reconnect(ctx context.Context, newStream io.ReadWriteCloser) error {
	cs.mu.Lock()
	if cs.isClosed {
		cs.mu.Unlock()
		return ErrSessionClosed
	}
	if cs.isConnected {
		cs.mu.Unlock()
		return fmt.Errorf("session is already connected")
	}
	if cs.reconnecting {
		cs.mu.Unlock()
		return fmt.Errorf("session is already reconnecting")
	}
	cs.reconnecting = true
	cs.mu.Unlock()

	defer func() {
		cs.mu.Lock()
		cs.reconnecting = false
		cs.mu.Unlock()
	}()

	// Save previous state for reconnection.
	prev := &reconnectState{
		protocol:  cs.protocol,
		sessionID: make([]byte, len(cs.SessionID)),
	}
	copy(prev.sessionID, cs.SessionID)
	cs.mu.Lock()
	prev.algorithms = cs.currentAlgorithms
	cs.mu.Unlock()
	if cs.kexService != nil {
		prev.hostKey = cs.kexService.getHostKey()
	}

	// Temporarily clear SessionID so the new Connect creates a new session ID.
	cs.SessionID = nil

	// Reset state for new connection.
	cs.mu.Lock()
	cs.isClosed = false
	cs.closedEventFired = false
	cs.mu.Unlock()

	// Connect over the new stream (version exchange + key exchange).
	if err := cs.Connect(ctx, newStream); err != nil {
		// Restore previous state on failure (Connect didn't succeed,
		// so no new connection to close — only reset fields).
		cs.protocol = prev.protocol
		cs.SessionID = prev.sessionID
		cs.mu.Lock()
		cs.isConnected = false
		cs.mu.Unlock()
		return &ReconnectError{
			Reason: messages.ReconnectFailureUnknownClientFailure,
			Msg:    fmt.Sprintf("failed to connect for reconnection: %v", err),
			Err:    err,
		}
	}

	newSessionID := cs.SessionID

	// The reconnect token uses the NEW (post-reconnect) session keys, matching
	// C#/TS behavior. The new Connect established new keys via key exchange;
	// both client and server use these new keys for token HMAC computation.
	// This proves both sides completed the same new key exchange.
	//
	// For kex:none (no-security mode), the new connection doesn't have HMAC keys.
	// In that case, preserve the old session's reconnect signer/verifier so token
	// operations still work.
	cs.mu.Lock()
	curAlgs := cs.currentAlgorithms
	cs.mu.Unlock()
	if curAlgs != nil && cs.reconnectSigner() == nil && prev.algorithms != nil {
		if curAlgs.ReconnectSigner == nil {
			curAlgs.ReconnectSigner = prev.algorithms.ReconnectSigner
		}
		if curAlgs.ReconnectVerifier == nil {
			curAlgs.ReconnectVerifier = prev.algorithms.ReconnectVerifier
		}
		// Also fall back to non-dedicated signer/verifier if still nil.
		if cs.reconnectSigner() == nil && prev.algorithms.Signer != nil {
			curAlgs.ReconnectSigner = prev.algorithms.Signer
		}
		if cs.reconnectVerifier() == nil && prev.algorithms.Verifier != nil {
			curAlgs.ReconnectVerifier = prev.algorithms.Verifier
		}
	}

	// Verify the server has the same host key.
	var newHostKey KeyPair
	if cs.kexService != nil {
		newHostKey = cs.kexService.getHostKey()
	}
	if prev.hostKey != nil && newHostKey != nil {
		prevKeyBytes, err1 := prev.hostKey.GetPublicKeyBytes()
		newKeyBytes, err2 := newHostKey.GetPublicKeyBytes()
		if err1 != nil || err2 != nil || !bytes.Equal(prevKeyBytes, newKeyBytes) {
			cs.restoreState(prev, true)
			return &ReconnectError{
				Reason: messages.ReconnectFailureDifferentServerHostKey,
				Msg:    "server host key changed during reconnection",
			}
		}
	}

	// Create reconnect token.
	reconnectToken, err := cs.CreateReconnectToken(prev.sessionID, newSessionID)
	if err != nil {
		cs.restoreState(prev, true)
		return &ReconnectError{
			Reason: messages.ReconnectFailureUnknownClientFailure,
			Msg:    fmt.Sprintf("failed to create reconnect token: %v", err),
			Err:    err,
		}
	}

	// Send reconnect request.
	reconnectMsg := &messages.SessionReconnectRequestMessage{
		RequestType:                ExtensionSessionReconnect,
		WantReply:                  true,
		ClientReconnectToken:       reconnectToken,
		LastReceivedSequenceNumber: prev.protocol.LastIncomingSequence(),
	}

	// Set up the reconnect response channel BEFORE sending the message.
	// The dispatch loop will route the response (type 81/82) to this channel
	// instead of pendingSessionRequests when reconnectResponseCh is non-nil.
	cs.mu.Lock()
	cs.reconnectResponseCh = make(chan *reconnectResponse, 1)
	cs.mu.Unlock()

	if err := cs.protocol.sendMessage(reconnectMsg.ToBuffer()); err != nil {
		cs.mu.Lock()
		cs.reconnectResponseCh = nil
		cs.mu.Unlock()
		cs.restoreState(prev, true)
		return &ReconnectError{
			Reason: messages.ReconnectFailureUnknownClientFailure,
			Msg:    fmt.Sprintf("failed to send reconnect request: %v", err),
			Err:    err,
		}
	}

	var response *reconnectResponse
	select {
	case response = <-cs.reconnectResponseCh:
	case <-cs.done:
		cs.restoreState(prev, false)
		return &ReconnectError{
			Reason: messages.ReconnectFailureUnknownClientFailure,
			Msg:    "session closed during reconnection",
		}
	case <-ctx.Done():
		cs.restoreState(prev, false)
		return ctx.Err()
	}

	cs.mu.Lock()
	cs.reconnectResponseCh = nil
	cs.mu.Unlock()

	if response.failure != nil {
		cs.restoreState(prev, true)
		return &ReconnectError{
			Reason: response.failure.ReasonCode,
			Msg:    response.failure.Description,
		}
	}

	// Verify server reconnect token.
	valid, err := cs.VerifyReconnectToken(prev.sessionID, newSessionID, response.success.ServerReconnectToken)
	if err != nil || !valid {
		cs.restoreState(prev, true)
		return &ReconnectError{
			Reason: messages.ReconnectFailureInvalidServerReconnectToken,
			Msg:    "server reconnect token verification failed",
			Err:    err,
		}
	}

	// Retransmit messages the server missed.
	// The server tells us the last sequence it received; we need to resend from +1.
	messagesToResend := prev.protocol.GetSentMessages(response.success.LastReceivedSequenceNumber + 1)
	if messagesToResend == nil {
		cs.restoreState(prev, true)
		return &ReconnectError{
			Reason: messages.ReconnectFailureClientDroppedMessages,
			Msg:    "client dropped messages needed for retransmission",
		}
	}

	// Resend the missed messages through the new protocol.
	for _, payload := range messagesToResend {
		if err := cs.protocol.sendMessage(payload); err != nil {
			return fmt.Errorf("failed to resend message: %w", err)
		}
	}

	// Restore the original session ID (reconnected session keeps its identity).
	cs.SessionID = prev.sessionID

	// Enable reconnect info on the new protocol.
	cs.enableReconnect()

	// Wait for the server's enable-reconnect message to be processed by our
	// dispatch loop. This ensures IncomingMessagesHaveReconnectInfo is set and
	// message caching is active before Reconnect returns — matching C#/TS
	// behavior where the reconnect operation guarantees caching is established.
	select {
	case <-cs.protocol.reconnectInfoReady:
	case <-cs.done:
		return &ReconnectError{
			Reason: messages.ReconnectFailureUnknownClientFailure,
			Msg:    "session closed waiting for reconnect enable",
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	// Flush messages that were buffered while disconnected.
	if err := cs.flushDisconnectedBuffer(); err != nil {
		return fmt.Errorf("failed to flush disconnected buffer: %w", err)
	}

	// Update metrics.
	cs.sessionMetrics.addReconnection()

	return nil
}

// reconnectResponse holds the result of a reconnect request.
type reconnectResponse struct {
	success *messages.SessionReconnectResponseMessage
	failure *messages.SessionReconnectFailureMessage
}

// handleReconnectRequest processes an incoming reconnect request on the server side.
// This is called when a SessionRequestMessage with type "session-reconnect@microsoft.com"
// is received on a NEW server session. The old disconnected session is looked up and
// its protocol is swapped with the new session's protocol.
func (ss *ServerSession) handleReconnectRequest(payload []byte) error {
	msg := &messages.SessionReconnectRequestMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read reconnect request: %w", err)
	}

	// Find the reconnectable session matching the client's token.
	if ss.ReconnectableSessions == nil {
		// No reconnectable sessions collection — reject.
		failMsg := &messages.SessionReconnectFailureMessage{
			ReasonCode:  messages.ReconnectFailureSessionNotFound,
			Description: "Requested reconnect session was not found.",
		}
		return ss.protocol.sendMessage(failMsg.ToBuffer())
	}

	reconnectSession := ss.ReconnectableSessions.findByToken(
		msg.ClientReconnectToken, ss.SessionID, &ss.Session)

	if reconnectSession == nil || reconnectSession.IsClosed() {
		failMsg := &messages.SessionReconnectFailureMessage{
			ReasonCode:  messages.ReconnectFailureSessionNotFound,
			Description: "Requested reconnect session was not found.",
		}
		return ss.protocol.sendMessage(failMsg.ToBuffer())
	}

	// Check if the server can provide the messages the client needs retransmitted.
	messagesToResend := reconnectSession.protocol.GetSentMessages(
		msg.LastReceivedSequenceNumber + 1)
	if messagesToResend == nil {
		// Can't fulfill retransmission request — put session back and fail.
		ss.ReconnectableSessions.add(reconnectSession)
		failMsg := &messages.SessionReconnectFailureMessage{
			ReasonCode:  messages.ReconnectFailureServerDroppedMessages,
			Description: "Server dropped messages needed for retransmission.",
		}
		return ss.protocol.sendMessage(failMsg.ToBuffer())
	}

	// Create server reconnect token using the NEW session's HMAC algorithms,
	// matching C#/TS behavior. Both sides use post-reconnect keys for HMAC.
	// Falls back to old session for kex:none (no HMAC on new session).
	tokenSession := &ss.Session
	if ss.reconnectSigner() == nil {
		tokenSession = &reconnectSession.Session
	}
	serverToken, err := tokenSession.CreateReconnectToken(reconnectSession.SessionID, ss.SessionID)
	if err != nil {
		ss.ReconnectableSessions.add(reconnectSession)
		failMsg := &messages.SessionReconnectFailureMessage{
			ReasonCode:  messages.ReconnectFailureUnknownServerFailure,
			Description: "Failed to create server reconnect token.",
		}
		return ss.protocol.sendMessage(failMsg.ToBuffer())
	}

	// Send reconnect response.
	responseMsg := &messages.SessionReconnectResponseMessage{
		ServerReconnectToken:       serverToken,
		LastReceivedSequenceNumber: reconnectSession.protocol.LastIncomingSequence(),
	}
	if err := ss.protocol.sendMessage(responseMsg.ToBuffer()); err != nil {
		ss.ReconnectableSessions.add(reconnectSession)
		return err
	}

	// Transfer protocol from this new session to the old session.
	reconnectSession.mu.Lock()
	reconnectSession.reconnecting = true
	reconnectSession.mu.Unlock()

	// Close the old session's protocol (just the stream, not the session).
	oldProtocol := reconnectSession.protocol

	// Swap protocol: the old session gets the new connection's protocol.
	reconnectSession.protocol = ss.protocol
	reconnectSession.kexService = ss.kexService
	if reconnectSession.kexService != nil {
		reconnectSession.kexService.session = &reconnectSession.Session
	}
	// Transfer the new session's algorithms to the reconnected session.
	// The reconnected session will use these new keys for ongoing operations
	// and any future reconnect token creation/verification.
	ss.mu.Lock()
	ssAlgs := ss.currentAlgorithms
	ss.mu.Unlock()
	if ssAlgs != nil && ssAlgs.Signer != nil {
		reconnectSession.mu.Lock()
		reconnectSession.currentAlgorithms = ssAlgs
		reconnectSession.mu.Unlock()
	}
	// Mark this temporary session as closed BEFORE nilling protocol so that
	// a concurrent enableReconnect goroutine (launched from extension info)
	// sees isClosed=true and bails out before accessing the protocol.
	ss.mu.Lock()
	ss.isClosed = true
	ss.isConnected = false
	ss.protocol = nil
	ss.mu.Unlock()

	// Resend missed messages on the new protocol.
	for _, payload := range messagesToResend {
		if err := reconnectSession.protocol.sendMessage(payload); err != nil {
			return fmt.Errorf("failed to resend message: %w", err)
		}
	}

	// Re-enable reconnection on the old session with the new protocol.
	reconnectSession.enableReconnect()

	// Mark the old session as connected again.
	reconnectSession.mu.Lock()
	reconnectSession.isConnected = true
	reconnectSession.reconnecting = false
	reconnectSession.mu.Unlock()

	// Flush messages that were buffered on the old session while disconnected.
	if err := reconnectSession.flushDisconnectedBuffer(); err != nil {
		return fmt.Errorf("failed to flush disconnected buffer: %w", err)
	}

	// Add session back to reconnectable collection.
	ss.ReconnectableSessions.add(reconnectSession)

	// Restart the dispatch loop on the old session.
	reconnectSession.done = make(chan struct{})
	go reconnectSession.runDispatchLoop()

	// No wait needed here for the client's enable-reconnect: the dispatch loop
	// processes messages sequentially, so it will set IncomingMessagesHaveReconnectInfo
	// (via handleEnableReconnectRequest) before processing any subsequent messages
	// that need caching. This ordering guarantee is inherent to the dispatch loop.

	// Update metrics.
	reconnectSession.sessionMetrics.addReconnection()

	// Fire OnReconnected on the reconnected server session.
	if reconnectServerSession, ok := reconnectSession.serverSession(); ok {
		reconnectServerSession.mu.Lock()
		onReconnected := reconnectServerSession.OnReconnected
		reconnectServerSession.mu.Unlock()
		if onReconnected != nil {
			onReconnected()
		}
	}

	// isClosed and isConnected were already set above (before nilling protocol).

	// Close the old protocol's stream to clean up.
	if oldProtocol != nil {
		_ = oldProtocol.close()
	}

	// Wait for the old dispatch loop to finish (it should have already exited
	// when the stream was closed during disconnect).

	return nil
}

// WaitUntilReconnectEnabled polls until both sides of a session pair have
// reconnect extensions negotiated and enabled, AND both protocols have
// IncomingMessagesHaveReconnectInfo set (meaning each side has received
// the other's enable-reconnect message and message caching is active).
// Used in tests for initial setup with kex:none (where enableReconnect
// is called manually rather than via extension info exchange).
func WaitUntilReconnectEnabled(ctx context.Context, sessions ...*Session) error {
	timeout := time.After(5 * time.Second)
	for {
		allReady := true
		for _, s := range sessions {
			s.mu.Lock()
			enabled := s.reconnectEnabled
			proto := s.protocol
			s.mu.Unlock()
			if !enabled || proto == nil {
				allReady = false
				break
			}
			// Wait for the protocol-level signal: reconnectInfoReady is closed
			// when IncomingMessagesHaveReconnectInfo is set, meaning the remote
			// side's enable-reconnect message has been received and processed.
			select {
			case <-proto.reconnectInfoReady:
			default:
				allReady = false
			}
		}
		if allReady {
			return nil
		}
		select {
		case <-timeout:
			return fmt.Errorf("timed out waiting for reconnect to be enabled")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
