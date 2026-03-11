// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// runDispatchLoop reads and handles messages until the session is closed or
// the stream produces an error.
func (s *Session) runDispatchLoop() {
	defer close(s.done)

	for {
		payload, err := s.protocol.receiveMessage()
		if err != nil {
			// Check if the session was intentionally closed.
			s.mu.Lock()
			closed := s.isClosed
			s.mu.Unlock()

			if !closed {
				s.trace(TraceLevelWarning, TraceEventReceiveMessageFailed,
					fmt.Sprintf("Receive message failed: %v", err))
				s.close(messages.DisconnectConnectionLost, "Connection lost.", false, true)
			}
			return
		}

		if len(payload) == 0 {
			continue
		}

		// Reset keep-alive timer on any received message.
		s.resetKeepAliveTimer()

		msgType := payload[0]

		// During an active key exchange, queue non-KEX messages for replay
		// after encryption is activated (RFC 4253 §7.1). KEX messages (20-31)
		// and transport-layer generic messages (1-4) are always processed
		// immediately.
		if s.isKexBlocking(msgType) {
			s.kexBlockedQueue = append(s.kexBlockedQueue, payload)
			continue
		}

		if err := s.handleMessage(msgType, payload); err != nil {
			s.trace(TraceLevelError, TraceEventHandleMessageFailed,
				fmt.Sprintf("Handle message failed (type %d): %v", msgType, err))
			s.close(messages.DisconnectProtocolError, err.Error(), false, true)
			return
		}

		// After handling a KEX message that may have completed the exchange
		// (NewKeys or KexInit for kex:none), replay any queued messages.
		if err := s.replayKexBlockedQueue(); err != nil {
			s.close(messages.DisconnectProtocolError, err.Error(), false, true)
			return
		}

		// Check if handleMessage or replayed messages triggered a close.
		s.mu.Lock()
		closed := s.isClosed
		s.mu.Unlock()
		if closed {
			return
		}

		// Check if key rotation is needed based on cumulative bytes transferred.
		// Snapshot kexService under lock since tests may modify it concurrently.
		s.mu.Lock()
		kexSvc := s.kexService
		s.mu.Unlock()
		if kexSvc != nil {
			if err := kexSvc.considerReExchange(
				atomic.LoadUint64(&s.protocol.BytesSent),
				atomic.LoadUint64(&s.protocol.BytesReceived),
			); err != nil {
				s.close(messages.DisconnectProtocolError, err.Error(), false, true)
				return
			}
		}
	}
}

// handleMessage dispatches a received message based on its type.
func (s *Session) handleMessage(msgType byte, payload []byte) error {
	switch msgType {
	case messages.MsgNumDisconnect:
		msg := &messages.DisconnectMessage{}
		if err := messages.ReadMessage(msg, payload); err != nil {
			return fmt.Errorf("failed to read disconnect message: %w", err)
		}
		s.trace(TraceLevelInfo, TraceEventSessionDisconnected,
			fmt.Sprintf("Session disconnected by remote: reason=%d %s",
				msg.ReasonCode, msg.Description))
		// Close without sending a disconnect back.
		s.close(msg.ReasonCode, msg.Description, false, true)
		return nil

	case messages.MsgNumIgnore:
		return nil

	case messages.MsgNumUnimplemented:
		// Log/process unimplemented notification from remote side. No action needed.
		return nil

	case messages.MsgNumDebug:
		// Debug messages are informational. Process but take no action.
		return nil

	case messages.MsgNumKeyExchangeInit:
		msg := &messages.KeyExchangeInitMessage{}
		if err := messages.ReadMessage(msg, payload); err != nil {
			return fmt.Errorf("failed to read kex init: %w", err)
		}
		if s.kexService != nil {
			return s.kexService.handleKexInit(msg, payload)
		}
		return nil

	case messages.MsgNumNewKeys:
		// NewKeys activates the negotiated encryption.
		return s.activateNewKeys()

	case messages.MsgNumKeyExchangeDhInit:
		// Server receives client's DH init.
		if !s.isClient && s.kexService != nil {
			msg := &messages.KeyExchangeDhInitMessage{}
			if err := messages.ReadMessage(msg, payload); err != nil {
				return fmt.Errorf("failed to read dh init: %w", err)
			}
			return s.kexService.handleDhInit(msg)
		}
		return nil

	case messages.MsgNumKeyExchangeDhReply:
		// Client receives server's DH reply.
		if s.isClient && s.kexService != nil {
			msg := &messages.KeyExchangeDhReplyMessage{}
			if err := messages.ReadMessage(msg, payload); err != nil {
				return fmt.Errorf("failed to read dh reply: %w", err)
			}
			return s.kexService.handleDhReply(msg)
		}
		return nil

	case messages.MsgNumExtensionInfo:
		msg := &messages.ExtensionInfoMessage{}
		if err := messages.ReadMessage(msg, payload); err != nil {
			return fmt.Errorf("failed to read extension info: %w", err)
		}
		s.mu.Lock()
		s.ProtocolExtensions = msg.Extensions
		s.mu.Unlock()

		// If both sides support reconnect, enable it inline.
		// Sending inline (matching C#/TS) avoids goroutine sendMu contention
		// that would delay Authenticate() by ~100ms per latency round-trip.
		if _, ok := msg.Extensions[ExtensionSessionReconnect]; ok {
			if s.hasProtocolExtension(ExtensionSessionReconnect) {
				if err := s.enableReconnect(); err != nil {
					return fmt.Errorf("failed to enable reconnect: %w", err)
				}
			}
		}
		return nil

	case messages.MsgNumServiceRequest:
		return s.handleServiceRequest(payload)

	case messages.MsgNumServiceAccept:
		return s.handleServiceAccept(payload)

	case messages.MsgNumSessionRequest:
		return s.handleSessionRequest(payload)

	case messages.MsgNumSessionRequestSuccess:
		return s.handleSessionRequestResponse(true, payload)

	case messages.MsgNumSessionRequestFailure:
		return s.handleSessionRequestResponse(false, payload)

	case messages.MsgNumAuthenticationRequest, messages.MsgNumAuthenticationFailure,
		messages.MsgNumAuthenticationSuccess:
		return s.handleAuthenticationMessage(msgType, payload)

	case messages.MsgNumPublicKeyOk: // type 60: PublicKeyOk or AuthInfoRequest
		return s.handleAuthenticationMessage(msgType, payload)

	case messages.MsgNumAuthInfoResponse: // type 61
		return s.handleAuthenticationMessage(msgType, payload)

	case messages.MsgNumChannelOpen:
		return s.handleChannelOpen(payload)

	case messages.MsgNumChannelOpenConfirmation:
		return s.handleChannelOpenConfirmation(payload)

	case messages.MsgNumChannelOpenFailure:
		return s.handleChannelOpenFailure(payload)

	case messages.MsgNumChannelWindowAdjust:
		return s.handleChannelWindowAdjust(payload)

	case messages.MsgNumChannelData:
		return s.handleChannelData(payload)

	case messages.MsgNumChannelExtendedData:
		// Extended data handled same as regular data for now.
		return s.handleChannelExtendedData(payload)

	case messages.MsgNumChannelEof:
		return s.handleChannelEof(payload)

	case messages.MsgNumChannelClose:
		return s.handleChannelClose(payload)

	case messages.MsgNumChannelRequest:
		return s.handleChannelRequest(payload)

	case messages.MsgNumChannelSuccess:
		return s.handleChannelRequestResponse(payload, true)

	case messages.MsgNumChannelFailure:
		return s.handleChannelRequestResponse(payload, false)

	default:
		// Check for a registered custom message handler.
		if handler, ok := s.Config.MessageHandlers[msgType]; ok {
			return handler(payload)
		}

		// Unknown message type - send unimplemented response.
		unimpl := &messages.UnimplementedMessage{
			SequenceNumber: uint32(atomic.LoadUint64(&s.protocol.ReceiveSequence) - 1),
		}
		return s.protocol.sendMessage(unimpl.ToBuffer())
	}
}

// handleServiceRequest processes an incoming service request (SSH_MSG_SERVICE_REQUEST).
// Only the server side handles these; the server tries to activate the named service
// and sends ServiceAccept or disconnects.
func (s *Session) handleServiceRequest(payload []byte) error {
	msg := &messages.ServiceRequestMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read service request: %w", err)
	}

	svc := s.activateServiceByServiceRequest(msg.ServiceName)
	if svc != nil {
		acceptMsg := &messages.ServiceAcceptMessage{
			ServiceName: msg.ServiceName,
		}
		return s.protocol.sendMessage(acceptMsg.ToBuffer())
	}

	// No service found — disconnect per SSH spec.
	s.close(messages.DisconnectServiceNotAvailable,
		fmt.Sprintf("Service %q not available", msg.ServiceName), true, true)
	return nil
}

// handleServiceAccept processes an incoming service accept (SSH_MSG_SERVICE_ACCEPT).
// The client side uses this to complete pending RequestService() calls.
func (s *Session) handleServiceAccept(payload []byte) error {
	msg := &messages.ServiceAcceptMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read service accept: %w", err)
	}

	s.mu.Lock()
	ch, ok := s.pendingServiceRequests[msg.ServiceName]
	if ok {
		delete(s.pendingServiceRequests, msg.ServiceName)
	}
	s.mu.Unlock()

	if ok {
		ch <- struct{}{}
	}

	return nil
}

// handleSessionRequest processes an incoming session request (SSH_MSG_GLOBAL_REQUEST).
func (s *Session) handleSessionRequest(payload []byte) error {
	msg := &messages.SessionRequestMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read session request: %w", err)
	}

	// Handle keep-alive requests. Always respond immediately with failure (per SSH convention).
	if msg.RequestType == ExtensionRequestKeepAlive {
		if msg.WantReply {
			reply := &messages.SessionRequestFailureMessage{}
			return s.protocol.sendMessage(reply.ToBuffer())
		}
		return nil
	}

	// Handle enable-session-reconnect request (enables reconnect info on incoming messages).
	if msg.RequestType == ExtensionRequestEnableSessionReconnect {
		s.handleEnableReconnectRequest()
		return nil
	}

	// Handle reconnect request (server-side only).
	if msg.RequestType == ExtensionSessionReconnect && !s.isClient {
		if ss, ok := s.serverSession(); ok {
			return ss.handleReconnectRequest(payload)
		}
		return nil
	}

	// Handle initial-channel-request extension (always allowed, even before auth).
	if msg.RequestType == ExtensionRequestInitialChannelRequest &&
		s.hasProtocolExtension(ExtensionOpenChannelRequest) {
		return s.handleInitialChannelRequest(payload)
	}

	// Authentication gate: reject requests if the session is not yet authenticated.
	s.mu.Lock()
	canAccept := s.canAcceptRequests()
	s.mu.Unlock()

	if !canAccept {
		if msg.WantReply {
			reply := &messages.SessionRequestFailureMessage{}
			return s.protocol.sendMessage(reply.ToBuffer())
		}
		return nil
	}

	// sendRequestReply sends the appropriate reply for a request based on the args.
	sendRequestReply := func(args *RequestEventArgs) error {
		if !msg.WantReply || args.ResponseHandled {
			return nil
		}
		var reply messages.Message
		if args.IsAuthorized {
			if args.ResponseMessage != nil {
				reply = args.ResponseMessage
			} else {
				reply = &messages.SessionRequestSuccessMessage{}
			}
		} else {
			reply = &messages.SessionRequestFailureMessage{}
		}
		return s.protocol.sendMessage(reply.ToBuffer())
	}

	// Snapshot principal under lock for use in request args.
	s.mu.Lock()
	principal := s.Principal
	s.mu.Unlock()

	// Try to activate a service that handles this session request type.
	svc := s.activateServiceBySessionRequest(msg.RequestType)
	if svc != nil {
		args := &RequestEventArgs{
			RequestType:  msg.RequestType,
			Request:      msg,
			IsAuthorized: false,
			Principal:    principal,
			Payload:      payload,
		}
		svc.OnSessionRequest(args)
		return sendRequestReply(args)
	}

	// No service found. Try the session-level OnRequest callback.
	// Snapshot callback under lock to avoid data race with concurrent setter.
	s.mu.Lock()
	onRequest := s.OnRequest
	s.mu.Unlock()

	if onRequest != nil {
		args := &RequestEventArgs{
			RequestType:  msg.RequestType,
			Request:      msg,
			IsAuthorized: false,
			Principal:    principal,
			Payload:      payload,
		}
		onRequest(args)
		return sendRequestReply(args)
	}

	// No handler — send failure response.
	if msg.WantReply {
		reply := &messages.SessionRequestFailureMessage{}
		return s.protocol.sendMessage(reply.ToBuffer())
	}
	return nil
}

// hasProtocolExtension checks if the given protocol extension is enabled in the local config.
func (s *Session) hasProtocolExtension(ext string) bool {
	for _, e := range s.Config.ProtocolExtensions {
		if e == ext {
			return true
		}
	}
	return false
}

// handleInitialChannelRequest processes an initial-channel-request extension message.
// It finds the channel by remote channel ID and dispatches the embedded channel request.
func (s *Session) handleInitialChannelRequest(payload []byte) error {
	// Re-read the payload as a SessionChannelRequestMessage.
	scrMsg := &messages.SessionChannelRequestMessage{}
	if err := messages.ReadMessage(scrMsg, payload); err != nil {
		return fmt.Errorf("failed to read initial channel request: %w", err)
	}

	var success bool

	if scrMsg.Request != nil {
		// Find the channel by remote channel ID (the sender's channel ID).
		s.mu.Lock()
		var targetChannel *Channel
		for _, ch := range s.channels {
			if ch.RemoteChannelID == scrMsg.SenderChannel {
				targetChannel = ch
				break
			}
		}
		s.mu.Unlock()

		if targetChannel != nil {
			// Force WantReply=false on the embedded request to avoid redundant replies.
			// The session request carries the response.
			scrMsg.Request.WantReply = false
			success = targetChannel.handleRequest(scrMsg.Request)
		}
	}

	if scrMsg.WantReply {
		var reply messages.Message
		if success {
			reply = &messages.SessionRequestSuccessMessage{}
		} else {
			reply = &messages.SessionRequestFailureMessage{}
		}
		return s.protocol.sendMessage(reply.ToBuffer())
	}

	return nil
}

// handleSessionRequestResponse processes a session request success or failure response.
func (s *Session) handleSessionRequestResponse(success bool, payload []byte) error {
	// Check if this is a reconnect response.
	s.mu.Lock()
	reconnectCh := s.reconnectResponseCh
	s.mu.Unlock()

	if reconnectCh != nil {
		resp := &reconnectResponse{}
		if success {
			msg := &messages.SessionReconnectResponseMessage{}
			if err := messages.ReadMessage(msg, payload); err == nil {
				resp.success = msg
			} else {
				// Parsing the success response failed — treat as a server failure
				// to prevent a nil-pointer panic when accessing ServerReconnectToken.
				resp.failure = &messages.SessionReconnectFailureMessage{
					ReasonCode:  messages.ReconnectFailureUnknownServerFailure,
					Description: fmt.Sprintf("failed to parse reconnect response: %v", err),
				}
			}
		} else {
			msg := &messages.SessionReconnectFailureMessage{}
			if err := messages.ReadMessage(msg, payload); err == nil {
				resp.failure = msg
			} else {
				resp.failure = &messages.SessionReconnectFailureMessage{
					ReasonCode:  messages.ReconnectFailureUnknownServerFailure,
					Description: "Failed to parse reconnect failure response.",
				}
			}
		}
		reconnectCh <- resp
		return nil
	}

	s.mu.Lock()
	if len(s.pendingSessionRequests) > 0 {
		ch := s.pendingSessionRequests[0]
		s.pendingSessionRequests = s.pendingSessionRequests[1:]
		s.mu.Unlock()
		ch <- &sessionRequestResponse{success: success, payload: payload}
		return nil
	}
	s.mu.Unlock()
	return nil
}

// Request sends a session request and waits for the response.
// Returns true if the request was accepted, false otherwise.
func (s *Session) Request(ctx context.Context, msg *messages.SessionRequestMessage) (bool, error) {
	return s.requestMessage(ctx, msg, msg.WantReply)
}

// requestMessage sends a session-level request message and waits for the response.
// The msg must serialize as a valid SSH_MSG_GLOBAL_REQUEST (type 80).
func (s *Session) requestMessage(ctx context.Context, msg messages.Message, wantReply bool) (bool, error) {
	resp, err := s.requestMessageWithPayload(ctx, msg, wantReply)
	if err != nil {
		return false, err
	}
	return resp.success, nil
}

// RequestWithPayload sends a session request and returns both success and the raw
// response payload. This is useful for requests like tcpip-forward where the success
// response contains additional data (e.g., allocated port).
func (s *Session) RequestWithPayload(ctx context.Context, msg messages.Message, wantReply bool) (bool, []byte, error) {
	resp, err := s.requestMessageWithPayload(ctx, msg, wantReply)
	if err != nil {
		return false, nil, err
	}
	return resp.success, resp.payload, nil
}

// requestMessageWithPayload is the internal implementation that returns the full response.
func (s *Session) requestMessageWithPayload(ctx context.Context, msg messages.Message, wantReply bool) (*sessionRequestResponse, error) {
	s.mu.Lock()
	if !s.isConnected {
		s.mu.Unlock()
		return nil, &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "session is not connected",
		}
	}

	if !wantReply {
		s.mu.Unlock()
		if err := s.SendMessage(msg); err != nil {
			return nil, err
		}
		return &sessionRequestResponse{success: true}, nil
	}

	resultCh := make(chan *sessionRequestResponse, 1)
	s.mu.Unlock()

	// Hold requestMu across append + send to ensure FIFO queue order
	// matches wire send order when multiple goroutines call Request concurrently.
	// Must not hold s.mu here — the dispatch loop needs s.mu to deliver responses,
	// and the synchronous pipe writes would deadlock if s.mu blocks the dispatch loop.
	s.requestMu.Lock()
	s.mu.Lock()
	s.pendingSessionRequests = append(s.pendingSessionRequests, resultCh)
	s.mu.Unlock()

	err := s.SendMessage(msg)
	s.requestMu.Unlock()
	if err != nil {
		return nil, err
	}

	select {
	case resp := <-resultCh:
		return resp, nil
	case <-s.done:
		return nil, &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "session closed while waiting for session request response",
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}


// serverSession returns the session cast to *ServerSession if it is one.
func (s *Session) serverSession() (*ServerSession, bool) {
	// Walk up to find the containing ServerSession.
	// Since Session is embedded in ServerSession, we can't directly cast.
	// Instead, we store a back-reference.
	if s.serverRef != nil {
		return s.serverRef, true
	}
	return nil, false
}

// handleAuthenticationMessage routes auth messages to the authentication service.
func (s *Session) handleAuthenticationMessage(msgType byte, payload []byte) error {
	svc := s.GetService(AuthServiceName)
	if svc == nil {
		// No auth service activated, ignore.
		return nil
	}
	authSvc, ok := svc.(*authenticationService)
	if !ok {
		return nil
	}
	return authSvc.handleMessage(msgType, payload)
}

