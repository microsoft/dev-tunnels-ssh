// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// Session is the base type for SSH client and server sessions.
// It manages the connection lifecycle, message dispatch, and channel multiplexing.
type Session struct {
	Config *SessionConfig

	// OnAuthenticating is called when authentication credentials need to be verified.
	OnAuthenticating func(*AuthenticatingEventArgs)

	// OnChannelOpening is called when a channel open request is received.
	OnChannelOpening func(*ChannelOpeningEventArgs)

	// OnClosed is called when the session is closed.
	OnClosed func(*SessionClosedEventArgs)

	// OnRequest is called when a session request is received.
	OnRequest func(*RequestEventArgs)

	// OnServiceActivated is called when a service is activated for the first time.
	OnServiceActivated func(Service)

	// OnKeepAliveSucceeded is called when a keep-alive response is received.
	// The argument is the consecutive success count.
	OnKeepAliveSucceeded func(int)

	// OnKeepAliveFailed is called when no keep-alive response is received within the timeout.
	// The argument is the consecutive failure count.
	OnKeepAliveFailed func(int)

	// OnDisconnected is called when the session transitions to a disconnected
	// (but not closed) state while reconnection is enabled. Applications can
	// call Reconnect() with a new stream to resume the session.
	OnDisconnected func()

	// OnReportProgress is called to report connection progress at key handshake stages.
	OnReportProgress func(Progress)

	// Principal holds the authenticated identity after successful authentication.
	// On the server side, this is populated from AuthenticatingEventArgs.AuthenticationResult.
	// It is nil before authentication completes.
	Principal interface{}

	// Trace is called for structured trace events during session operation.
	// Set this before calling Connect to receive all trace events.
	// The function is nil-safe — no overhead when not set.
	Trace TraceFunc

	// RemoteVersion contains parsed version info from the remote side
	// after the version exchange completes.
	RemoteVersion *VersionInfo

	// ProtocolExtensions from remote side (from ExtensionInfoMessage).
	ProtocolExtensions map[string]string

	// SessionID is the exchange hash from the first key exchange.
	// It is set once and never changes, even on re-exchange.
	SessionID []byte

	mu               sync.Mutex
	protocol         *SSHProtocol
	isConnected      bool
	isClosed         bool
	done             chan struct{} // closed when dispatch loop exits
	isClient         bool
	closedEventFired bool


	// Key exchange service.
	kexService *keyExchangeService

	// currentAlgorithms stores the most recently negotiated algorithms.
	// Used for reconnect token creation/verification (HMAC operations).
	currentAlgorithms *sessionAlgorithms

	// Back-reference to ServerSession (set when embedded in ServerSession).
	serverRef *ServerSession

	// kexDone is closed when the initial key exchange completes.
	// Connect() waits on this to ensure the session is ready for use.
	kexDone chan struct{}

	// Channel management
	channels       map[uint32]*Channel          // active channels by local channel ID
	nextChannelID  uint32                        // counter for generating local channel IDs
	pendingOpens   map[uint32]*pendingChannelOpen // pending channel open requests by local channel ID
	acceptQueue     []*Channel     // incoming channels waiting to be accepted
	acceptBroadcast chan struct{}  // closed to broadcast new channel arrival to all waiters

	// Service management
	activatedServices      map[string]Service
	pendingServiceRequests map[string]chan struct{}
	pendingSessionRequests []chan *sessionRequestResponse // pending session request responses (FIFO order)
	requestMu              sync.Mutex // serializes session request queue + send to ensure FIFO consistency

	// Session-level metrics.
	sessionMetrics SessionMetrics

	// Authentication state
	isAuthenticated bool

	// Keep-alive state
	keepAliveResetCh          chan struct{}
	keepAliveResponseReceived bool
	keepAliveFailureCount     int
	keepAliveSuccessCount     int

	// Reconnection state
	reconnectEnabled    bool                   // true after EnableReconnect succeeds
	reconnecting        bool                   // true during an active reconnect attempt
	reconnectResponseCh chan *reconnectResponse // for client to receive reconnect response

	// disconnectedBuffer stores messages sent while the session is disconnected
	// but reconnect-enabled. These are flushed after reconnection completes.
	disconnectedBuffer [][]byte

	// kexBlockedQueue stores non-KEX message payloads received during an active
	// key exchange. Per RFC 4253 §7.1, these are replayed in order after NewKeys
	// activates the new encryption. Only accessed from the dispatch loop goroutine.
	kexBlockedQueue [][]byte
}

// Metrics returns a pointer to the session's metrics counters.
func (s *Session) Metrics() *SessionMetrics {
	return &s.sessionMetrics
}

// IsConnected returns true if the session is currently connected.
func (s *Session) IsConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isConnected
}

// IsClosed returns true if the session has been closed.
func (s *Session) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isClosed
}

// Done returns a channel that is closed when the session's dispatch loop exits.
// This can be used to derive contexts that are scoped to the session's lifetime.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// SetAuthenticatingHandler sets the OnAuthenticating callback in a thread-safe manner.
// Use this method instead of direct field assignment when the session is already connected,
// to avoid data races with the dispatch goroutine.
func (s *Session) SetAuthenticatingHandler(handler func(*AuthenticatingEventArgs)) {
	s.mu.Lock()
	s.OnAuthenticating = handler
	s.mu.Unlock()
}

// SetChannelOpeningHandler sets the OnChannelOpening callback in a thread-safe manner.
// Use this method instead of direct field assignment when the session is already connected,
// to avoid data races with the dispatch goroutine.
func (s *Session) SetChannelOpeningHandler(handler func(*ChannelOpeningEventArgs)) {
	s.mu.Lock()
	s.OnChannelOpening = handler
	s.mu.Unlock()
}

// SetRequestHandler sets the OnRequest callback in a thread-safe manner.
// Use this method instead of direct field assignment when the session is already connected,
// to avoid data races with the dispatch goroutine.
func (s *Session) SetRequestHandler(handler func(*RequestEventArgs)) {
	s.mu.Lock()
	s.OnRequest = handler
	s.mu.Unlock()
}

// SetClosedHandler sets the OnClosed callback in a thread-safe manner.
// Use this method instead of direct field assignment when the session is already connected,
// to avoid data races with the dispatch goroutine.
func (s *Session) SetClosedHandler(handler func(*SessionClosedEventArgs)) {
	s.mu.Lock()
	s.OnClosed = handler
	s.mu.Unlock()
}

// SetReportProgressHandler sets the OnReportProgress callback in a thread-safe manner.
// Use this method instead of direct field assignment when the session is already connected,
// to avoid data races with the dispatch goroutine.
func (s *Session) SetReportProgressHandler(handler func(Progress)) {
	s.mu.Lock()
	s.OnReportProgress = handler
	s.mu.Unlock()
}

// reportProgress fires the OnReportProgress callback if set.
func (s *Session) reportProgress(p Progress) {
	s.mu.Lock()
	handler := s.OnReportProgress
	s.mu.Unlock()
	if handler != nil {
		handler(p)
	}
}

// SetTraceHandler sets the Trace callback in a thread-safe manner.
// Use this method instead of direct field assignment when the session is already connected,
// to avoid data races with the dispatch goroutine.
func (s *Session) SetTraceHandler(handler TraceFunc) {
	s.mu.Lock()
	s.Trace = handler
	s.mu.Unlock()
}

// trace fires the Trace callback if set. Zero overhead when Trace is nil.
func (s *Session) trace(level TraceLevel, eventID int, message string) {
	s.mu.Lock()
	handler := s.Trace
	s.mu.Unlock()
	if handler != nil {
		handler(level, eventID, message)
	}
}

// canAcceptRequests returns true if the session can process session requests.
// Returns true if no key exchange occurred (no-security mode), or if encryption
// is active and the session is authenticated. Must be called with s.mu held.
func (s *Session) canAcceptRequests() bool {
	// No kex service = no encryption = always accept.
	if s.kexService == nil {
		return true
	}
	// Kex service exists but no encryption was negotiated = accept.
	if s.protocol != nil && !s.protocol.hasEncryption() {
		return true
	}
	// Encryption active = require authentication.
	return s.isAuthenticated
}


// Connect connects the session over the given stream.
// Both sides exchange SSH-2.0 version strings and key exchange init messages.
func (s *Session) Connect(ctx context.Context, stream io.ReadWriteCloser) error {
	// Validate config before connecting.
	if s.Config != nil {
		if err := s.Config.Validate(); err != nil {
			return err
		}
	}

	s.mu.Lock()
	if s.isConnected || s.isClosed {
		s.mu.Unlock()
		return fmt.Errorf("session already connected or closed")
	}
	isReconnecting := s.reconnecting
	s.mu.Unlock()

	s.reportProgress(ProgressOpeningSSHSessionConnection)
	s.trace(TraceLevelInfo, TraceEventSessionConnecting, "SSH session connecting.")

	// Create protocol and initialize channels.
	p := newSSHProtocol(stream, &s.sessionMetrics)
	if s.Config != nil {
		p.maxCacheSize = s.Config.MaxReconnectMessageCacheSize
		p.traceChannelData = s.Config.TraceChannelData
	}
	s.mu.Lock()
	p.trace = s.Trace
	s.protocol = p
	s.mu.Unlock()
	s.done = make(chan struct{})
	// Don't reinitialize channels during reconnect — preserve existing channel state.
	if !isReconnecting {
		s.initChannels()
	}

	s.reportProgress(ProgressStartingProtocolVersionExchange)

	localVersion := GetLocalVersion()

	// Initialize key exchange service and prepare KexInit payload before any I/O.
	// Per RFC 4253, KexInit can be sent immediately after the version string.
	s.mu.Lock()
	s.kexService = newKeyExchangeService(s)
	s.mu.Unlock()
	s.kexDone = make(chan struct{})
	kexInitPayload, guessPayload := s.kexService.startKeyExchange(true)

	// Pipeline version string + KexInit in a background goroutine, matching
	// C#/TS behavior. This lets the version write + KexInit write proceed
	// while we read the remote version concurrently — saving one round trip.
	// With io.Pipe streams, the goroutine safely blocks on Write until the
	// other side's Read consumes each message sequentially.
	writeErr := make(chan error, 1)
	go func() {
		if err := s.protocol.writeVersionString(localVersion.String()); err != nil {
			writeErr <- err
			return
		}
		if err := s.protocol.sendMessage(kexInitPayload); err != nil {
			writeErr <- err
			return
		}
		if guessPayload != nil {
			if err := s.protocol.sendMessage(guessPayload); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	remoteVersionStr, err := s.protocol.readVersionString()
	if err != nil {
		<-writeErr
		return fmt.Errorf("failed to read version string: %w", err)
	}

	if err := <-writeErr; err != nil {
		return fmt.Errorf("failed to write version/kex init: %w", err)
	}

	s.RemoteVersion = ParseVersionInfo(remoteVersionStr)
	if s.RemoteVersion == nil {
		return &ConnectionError{
			Reason: messages.DisconnectProtocolVersionNotSupported,
			Msg:    fmt.Sprintf("invalid remote version string: %q", remoteVersionStr),
		}
	}

	s.trace(TraceLevelVerbose, TraceEventProtocolVersion,
		fmt.Sprintf("Protocol version exchange: local=%s remote=%s", localVersion, remoteVersionStr))
	s.reportProgress(ProgressCompletedProtocolVersionExchange)

	// Set connected state.
	s.mu.Lock()
	s.isConnected = true
	s.mu.Unlock()

	s.reportProgress(ProgressStartingKeyExchange)

	// Start dispatch loop after the version string has been consumed from the
	// stream. The dispatch loop reads framed SSH messages (starting with the
	// remote KexInit that was pipelined with the version string).
	go s.runDispatchLoop()

	// Wait for the initial key exchange to complete before returning.
	// This ensures the session is ready for use (encryption activated, etc.).
	select {
	case <-s.kexDone:
		s.reportProgress(ProgressCompletedKeyExchange)
		s.trace(TraceLevelVerbose, TraceEventSessionEncrypted, "Key exchange completed.")
		s.startKeepAliveTimer()
		s.reportProgress(ProgressOpenedSSHSessionConnection)
		return nil
	case <-s.done:
		return fmt.Errorf("session closed during key exchange")
	case <-ctx.Done():
		s.close(messages.DisconnectByApplication, "connect context cancelled", false, false)
		return ctx.Err()
	}
}

// buildKexInitMessage creates a KeyExchangeInitMessage from the session configuration.
func (s *Session) buildKexInitMessage() *messages.KeyExchangeInitMessage {
	config := s.Config
	msg := &messages.KeyExchangeInitMessage{
		KeyExchangeAlgorithms:              config.KeyExchangeAlgorithms,
		ServerHostKeyAlgorithms:            s.getPublicKeyAlgorithms(),
		EncryptionAlgorithmsClientToServer: config.EncryptionAlgorithms,
		EncryptionAlgorithmsServerToClient: config.EncryptionAlgorithms,
		MacAlgorithmsClientToServer:        config.HmacAlgorithms,
		MacAlgorithmsServerToClient:        config.HmacAlgorithms,
		CompressionAlgorithmsClientToServer: config.CompressionAlgorithms,
		CompressionAlgorithmsServerToClient: config.CompressionAlgorithms,
	}

	// Generate random cookie.
	_, _ = rand.Read(msg.Cookie[:])

	return msg
}

// getPublicKeyAlgorithms returns the public key algorithms to advertise in KexInit.
// For a server session with multiple configured algorithms, the list is filtered
// to only include algorithms for which the server has a matching host key.
// This ensures the negotiated algorithm can actually be used during key exchange.
func (s *Session) getPublicKeyAlgorithms() []string {
	algorithms := s.Config.PublicKeyAlgorithms

	serverSession, ok := s.serverSession()
	if !ok || len(algorithms) <= 1 {
		return algorithms
	}

	if serverSession.Credentials == nil || len(serverSession.Credentials.PublicKeys) == 0 {
		return algorithms
	}

	// Build set of key algorithm names from server's available keys.
	availableKeyAlgos := make(map[string]bool)
	for _, key := range serverSession.Credentials.PublicKeys {
		if key != nil {
			algoName := key.KeyAlgorithmName()
			availableKeyAlgos[algoName] = true
			// RSA keys can be used with multiple signing algorithms.
			if algoName == AlgoKeyRsa {
				availableKeyAlgos[AlgoPKRsaSha256] = true
				availableKeyAlgos[AlgoPKRsaSha512] = true
			}
		}
	}

	// Filter to only algorithms with matching keys.
	filtered := make([]string, 0, len(algorithms))
	for _, algo := range algorithms {
		if availableKeyAlgos[algo] {
			filtered = append(filtered, algo)
		}
	}

	if len(filtered) == 0 {
		// No matching keys — return original list and let the key exchange fail gracefully.
		return algorithms
	}

	return filtered
}

// Close closes the session gracefully with DisconnectByApplication reason.
// Implements io.Closer. Returns nil; close errors are reported via OnClosed.
func (s *Session) Close() error {
	s.close(messages.DisconnectByApplication, "Session closed by application.", true, false)
	return nil
}

// Compile-time check that *Session satisfies io.Closer.
var _ io.Closer = (*Session)(nil)

// CloseWithReason closes the session with a specific disconnect reason and message.
func (s *Session) CloseWithReason(ctx context.Context, reason messages.SSHDisconnectReason, msg string) error {
	s.close(reason, msg, true, false)
	return nil
}

// close is the internal close implementation.
// sendDisconnect controls whether a disconnect message is sent to the remote side.
// fromDispatchLoop must be true when called from within the dispatch loop goroutine
// to avoid deadlocking on the done channel.
func (s *Session) close(reason messages.SSHDisconnectReason, msg string, sendDisconnect bool, fromDispatchLoop bool) {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return
	}

	// Check if this is a connection loss that should transition to disconnected
	// (not closed) state for potential reconnection.
	if reason == messages.DisconnectConnectionLost && !sendDisconnect && s.onDisconnected() {
		s.mu.Unlock()
		s.disconnect(reason, msg)
		return
	}

	wasConnected := s.isConnected
	s.isConnected = false
s.isClosed = true

	// Signal keep-alive goroutine to stop (it listens on s.done).
	s.keepAliveResetCh = nil
	traceHandler := s.Trace
	s.mu.Unlock()

	if traceHandler != nil {
		traceHandler(TraceLevelInfo, TraceEventSessionClosing,
			fmt.Sprintf("Session closing: reason=%d %s", reason, msg))
	}

	// Try to send disconnect message (ignore errors, stream may already be closed).
	// Send with a short timeout to avoid blocking if a concurrent goroutine holds
	// the send lock while blocked on a pipe write.
	if sendDisconnect && wasConnected && s.protocol != nil {
		disconnectMsg := &messages.DisconnectMessage{
			ReasonCode:  reason,
			Description: msg,
		}
		sendDone := make(chan struct{})
		go func() {
			_ = s.protocol.sendMessage(disconnectMsg.ToBuffer())
			close(sendDone)
		}()
		select {
		case <-sendDone:
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Close the protocol/stream (unblocks the dispatch loop read and any pending writes).
	if s.protocol != nil {
		_ = s.protocol.close()
	}

	// Notify all channels of session close.
	sessionErr := &ConnectionError{Reason: reason, Msg: msg}
	s.mu.Lock()
	channelsCopy := make([]*Channel, 0, len(s.channels))
	for _, ch := range s.channels {
		channelsCopy = append(channelsCopy, ch)
	}
	// Complete any pending channel opens with an error.
	for id, pending := range s.pendingOpens {
		pending.resultCh <- &channelOpenResult{err: sessionErr}
		delete(s.pendingOpens, id)
	}
	s.mu.Unlock()

	for _, ch := range channelsCopy {
		ch.handleSessionClose(sessionErr)
	}

	// Wait for dispatch loop to finish (unless we're called from within it).
	if !fromDispatchLoop && s.done != nil {
		<-s.done
	}

	// Close all activated services.
	s.closeServices()

	// Close metrics (resets current latency and fires session closed callback).
	s.sessionMetrics.closeMetrics()

	// Fire OnClosed callback exactly once.
	s.mu.Lock()
	if s.closedEventFired {
		s.mu.Unlock()
		return
	}
	s.closedEventFired = true
	onClosed := s.OnClosed
	s.mu.Unlock()

	if onClosed != nil {
		onClosed(&SessionClosedEventArgs{
			Reason:  reason,
			Message: msg,
			Err:     &ConnectionError{Reason: reason, Msg: msg},
		})
	}
}




// CloseWithError closes the session with a specific disconnect reason and a custom error
// that is propagated to channel OnClosed callbacks.
func (s *Session) CloseWithError(reason messages.SSHDisconnectReason, msg string, err error) error {
	s.closeWithError(reason, msg, true, false, err)
	return nil
}

// closeWithError is the internal close implementation that supports passing a custom error.
func (s *Session) closeWithError(reason messages.SSHDisconnectReason, msg string, sendDisconnect bool, fromDispatchLoop bool, customErr error) {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return
	}
	wasConnected := s.isConnected
	s.isConnected = false
s.isClosed = true
	s.mu.Unlock()

	// Try to send disconnect message (ignore errors, stream may already be closed).
	if sendDisconnect && wasConnected && s.protocol != nil {
		disconnectMsg := &messages.DisconnectMessage{
			ReasonCode:  reason,
			Description: msg,
		}
		_ = s.protocol.sendMessage(disconnectMsg.ToBuffer())
	}

	// Use custom error if provided, otherwise create ConnectionError.
	var channelErr error
	if customErr != nil {
		channelErr = customErr
	} else {
		channelErr = &ConnectionError{Reason: reason, Msg: msg}
	}

	s.mu.Lock()
	channelsCopy := make([]*Channel, 0, len(s.channels))
	for _, ch := range s.channels {
		channelsCopy = append(channelsCopy, ch)
	}
	// Complete any pending channel opens with an error.
	sessionErr := &ConnectionError{Reason: reason, Msg: msg}
	for id, pending := range s.pendingOpens {
		pending.resultCh <- &channelOpenResult{err: sessionErr}
		delete(s.pendingOpens, id)
	}
	s.mu.Unlock()

	for _, ch := range channelsCopy {
		ch.handleSessionClose(channelErr)
	}

	// Close the protocol/stream (unblocks the dispatch loop read).
	if s.protocol != nil {
		_ = s.protocol.close()
	}

	// Wait for dispatch loop to finish (unless we're called from within it).
	if !fromDispatchLoop && s.done != nil {
		<-s.done
	}

	// Close all activated services.
	s.closeServices()

	// Fire OnClosed callback exactly once.
	s.mu.Lock()
	if s.closedEventFired {
		s.mu.Unlock()
		return
	}
	s.closedEventFired = true
	onClosed := s.OnClosed
	s.mu.Unlock()

	if onClosed != nil {
		onClosed(&SessionClosedEventArgs{
			Reason:  reason,
			Message: msg,
			Err:     &ConnectionError{Reason: reason, Msg: msg},
		})
	}
}

// SendRawMessage sends a raw byte payload through the protocol layer.
// This is primarily used for testing (e.g., sending unknown message types).
func (s *Session) SendRawMessage(payload []byte) error {
	s.mu.Lock()
	if !s.isConnected {
		s.mu.Unlock()
		return &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "session is not connected",
		}
	}
	p := s.protocol
	s.mu.Unlock()

	return p.sendMessage(payload)
}

// SendMessage sends a message through the protocol layer.
func (s *Session) SendMessage(msg messages.Message) error {
	s.mu.Lock()
	if !s.isConnected {
		// If reconnect is enabled and session is not closed, buffer the message
		// for delivery after reconnection.
		if s.reconnectEnabled && !s.isClosed {
			payload := msg.ToBuffer()
			bufCopy := make([]byte, len(payload))
			copy(bufCopy, payload)
			s.disconnectedBuffer = append(s.disconnectedBuffer, bufCopy)
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		return &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "session is not connected",
		}
	}
	p := s.protocol
	s.mu.Unlock()

	return p.sendMessageDirect(msg)
}

// flushDisconnectedBuffer sends all messages that were buffered while
// the session was disconnected. Called after reconnection completes.
func (s *Session) flushDisconnectedBuffer() error {
	s.mu.Lock()
	buffer := s.disconnectedBuffer
	s.disconnectedBuffer = nil
	s.mu.Unlock()

	for _, payload := range buffer {
		if err := s.protocol.sendMessage(payload); err != nil {
			return err
		}
	}
	return nil
}




