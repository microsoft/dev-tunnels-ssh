// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"log"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// channelOpenResult contains the result of a channel open request.
type channelOpenResult struct {
	channel *Channel
	err     error
}

const (
	// maxAcceptQueueSize is the maximum number of unaccepted channels that can
	// be queued before new channel opens are rejected. This prevents unbounded
	// growth when a server selectively accepts certain channel types.
	maxAcceptQueueSize = 64
)

// pendingChannelOpen tracks a pending channel open request, storing both the
// original Channel created during OpenChannel and the result channel used to
// deliver the confirmation/failure back to the caller.
type pendingChannelOpen struct {
	channel  *Channel
	resultCh chan *channelOpenResult
}

// sessionRequestResponse carries the result of a session request.
type sessionRequestResponse struct {
	success bool
	payload []byte
}


// initChannels initializes channel management state.
func (s *Session) initChannels() {
	s.channels = make(map[uint32]*Channel)
	s.pendingOpens = make(map[uint32]*pendingChannelOpen)
	s.acceptQueue = nil
	s.acceptBroadcast = make(chan struct{})
}

// OpenChannel opens a new channel with the default "session" type.
func (s *Session) OpenChannel(ctx context.Context) (*Channel, error) {
	return s.OpenChannelWithType(ctx, "session")
}

// OpenChannelWithType opens a new channel with the given channel type.
func (s *Session) OpenChannelWithType(ctx context.Context, channelType string) (*Channel, error) {
	// Check for cancellation before doing anything.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if channelType == "" {
		channelType = "session"
	}

	s.mu.Lock()
	if !s.isConnected {
		s.mu.Unlock()
		return nil, &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "session is not connected",
		}
	}

	// Allocate local channel ID.
	localID := s.nextChannelID
	s.nextChannelID++

	// Create the channel.
	ch := newChannel(s, channelType, localID)

	// Create a result channel for the confirmation/failure response.
	resultCh := make(chan *channelOpenResult, 1)
	s.pendingOpens[localID] = &pendingChannelOpen{channel: ch, resultCh: resultCh}
	s.mu.Unlock()

	// Send channel open message.
	openMsg := &messages.ChannelOpenMessage{
		ChannelType:   channelType,
		SenderChannel: localID,
		MaxWindowSize: ch.MaxWindowSize,
		MaxPacketSize: ch.MaxPacketSize,
	}
	ch.openMessage = openMsg
	if err := s.SendMessage(openMsg); err != nil {
		s.mu.Lock()
		delete(s.pendingOpens, localID)
		s.mu.Unlock()
		return nil, err
	}

	// Wait for confirmation or failure.
	select {
	case result := <-resultCh:
		return result.channel, result.err
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pendingOpens, localID)
		s.mu.Unlock()
		return nil, ctx.Err()
	}
}

// OpenChannelWithMessage opens a new channel by sending a custom channel open message.
// The buildMsg callback receives the allocated local channel ID, window size, and
// packet size, and returns the message to send. The message must serialize as a valid
// SSH_MSG_CHANNEL_OPEN (type 90) with matching SenderChannel, MaxWindowSize, and MaxPacketSize.
// This is used by services like port forwarding that need extended channel open data.
func (s *Session) OpenChannelWithMessage(
	ctx context.Context,
	channelType string,
	buildMsg func(senderChannel, maxWindowSize, maxPacketSize uint32) messages.Message,
) (*Channel, error) {
	// Check for cancellation before doing anything.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if channelType == "" {
		channelType = "session"
	}

	s.mu.Lock()
	if !s.isConnected {
		s.mu.Unlock()
		return nil, &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "session is not connected",
		}
	}

	localID := s.nextChannelID
	s.nextChannelID++

	ch := newChannel(s, channelType, localID)
	ch.openMessage = &messages.ChannelOpenMessage{
		ChannelType:   channelType,
		SenderChannel: localID,
		MaxWindowSize: ch.MaxWindowSize,
		MaxPacketSize: ch.MaxPacketSize,
	}

	resultCh := make(chan *channelOpenResult, 1)
	s.pendingOpens[localID] = &pendingChannelOpen{channel: ch, resultCh: resultCh}
	s.mu.Unlock()

	msg := buildMsg(localID, ch.MaxWindowSize, ch.MaxPacketSize)
	if err := s.SendMessage(msg); err != nil {
		s.mu.Lock()
		delete(s.pendingOpens, localID)
		s.mu.Unlock()
		return nil, err
	}

	select {
	case result := <-resultCh:
		return result.channel, result.err
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pendingOpens, localID)
		s.mu.Unlock()
		return nil, ctx.Err()
	}
}

// OpenChannelWithRequest opens a channel and sends an initial channel request.
// If the open-channel-request protocol extension is negotiated, the request is
// bundled with the channel open to avoid an extra round-trip. Otherwise, the
// request is sent as a standard channel request after the channel is opened.
// Returns the opened channel. Returns an error if the channel open or the
// initial request fails.
func (s *Session) OpenChannelWithRequest(
	ctx context.Context,
	openMsg *messages.ChannelOpenMessage,
	initialRequest *messages.ChannelRequestMessage,
) (*Channel, error) {
	// Check for cancellation before doing anything.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	channelType := openMsg.ChannelType
	if channelType == "" {
		channelType = "session"
	}

	s.mu.Lock()
	if !s.isConnected {
		s.mu.Unlock()
		return nil, &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "session is not connected",
		}
	}

	// Allocate local channel ID.
	localID := s.nextChannelID
	s.nextChannelID++

	// Create the channel.
	ch := newChannel(s, channelType, localID)

	// Create a result channel for the confirmation/failure response.
	resultCh := make(chan *channelOpenResult, 1)
	s.pendingOpens[localID] = &pendingChannelOpen{channel: ch, resultCh: resultCh}
	s.mu.Unlock()

	// Send channel open message.
	openMsg.SenderChannel = localID
	openMsg.MaxWindowSize = ch.MaxWindowSize
	openMsg.MaxPacketSize = ch.MaxPacketSize
	if err := s.SendMessage(openMsg); err != nil {
		s.mu.Lock()
		delete(s.pendingOpens, localID)
		s.mu.Unlock()
		return nil, err
	}

	// Check if the open-channel-request extension is supported.
	// Three states:
	//   true  = both sides support it
	//   false = explicitly not supported (extension not in our config)
	//   nil   = unknown (in our config but not yet confirmed by remote)
	isExtensionSupported := s.getExtensionSupport(ExtensionOpenChannelRequest)

	if isExtensionSupported != nil && !*isExtensionSupported {
		// Extension definitely not supported: use standard protocol.
		// Wait for channel open confirmation first.
		var channel *Channel
		select {
		case result := <-resultCh:
			if result.err != nil {
				return nil, result.err
			}
			channel = result.channel
		case <-ctx.Done():
			s.mu.Lock()
			delete(s.pendingOpens, localID)
			s.mu.Unlock()
			return nil, ctx.Err()
		}

		// Send the request as a standard channel request.
		initialRequest.RecipientChannel = channel.RemoteChannelID
		success, err := channel.Request(ctx, initialRequest)
		if err != nil {
			_ = channel.Close()
			return nil, err
		}
		if !success {
			_ = channel.Close()
			return nil, &ChannelError{
				Reason: messages.ChannelOpenFailureAdministrativelyProhibited,
				Msg:    "The initial channel request was denied.",
			}
		}
		return channel, nil
	}

	// Extension is supported or unknown: send request immediately via session request.
	wantReply := initialRequest.WantReply || (isExtensionSupported == nil)

	sessionRequest := &messages.SessionChannelRequestMessage{}
	sessionRequest.RequestType = ExtensionRequestInitialChannelRequest
	sessionRequest.SenderChannel = localID
	sessionRequest.Request = initialRequest
	sessionRequest.WantReply = wantReply

	requestTask := make(chan bool, 1)
	requestErr := make(chan error, 1)
	go func() {
		result, err := s.requestMessage(ctx, sessionRequest, wantReply)
		if err != nil {
			requestErr <- err
			return
		}
		requestTask <- result
	}()

	// Wait for channel open confirmation.
	var channel *Channel
	select {
	case result := <-resultCh:
		if result.err != nil {
			return nil, result.err
		}
		channel = result.channel
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pendingOpens, localID)
		s.mu.Unlock()
		return nil, ctx.Err()
	}

	if !wantReply {
		return channel, nil
	}

	// Wait for response to the initial request.
	var requestResult bool
	select {
	case result := <-requestTask:
		requestResult = result
	case err := <-requestErr:
		_ = channel.Close()
		return nil, err
	case <-ctx.Done():
		_ = channel.Close()
		return nil, ctx.Err()
	}

	// If extension support was unknown and request failed, fall back to standard protocol.
	if !requestResult && isExtensionSupported == nil {
		initialRequest.RecipientChannel = channel.RemoteChannelID
		success, err := channel.Request(ctx, initialRequest)
		if err != nil {
			_ = channel.Close()
			return nil, err
		}
		requestResult = success
	}

	if !requestResult {
		_ = channel.Close()
		return nil, &ChannelError{
			Reason: messages.ChannelOpenFailureAdministrativelyProhibited,
			Msg:    "The initial channel request was denied.",
		}
	}

	return channel, nil
}

// getExtensionSupport checks if a protocol extension is supported.
// Returns:
//   - pointer to true: both sides support it (in our config and confirmed by remote)
//   - pointer to false: not supported (not in our config)
//   - nil: unknown (in our config but not yet confirmed by remote)
func (s *Session) getExtensionSupport(ext string) *bool {
	// Check if extension is in our local config.
	localSupport := false
	for _, e := range s.Config.ProtocolExtensions {
		if e == ext {
			localSupport = true
			break
		}
	}
	if !localSupport {
		f := false
		return &f
	}

	// Check if remote side supports it (snapshot under lock to avoid race
	// with dispatch loop writing ProtocolExtensions).
	s.mu.Lock()
	extensions := s.ProtocolExtensions
	s.mu.Unlock()

	if extensions != nil {
		if _, ok := extensions[ext]; ok {
			t := true
			return &t
		}
	}

	// In our config but not confirmed by remote — unknown.
	return nil
}

// AcceptChannel waits for and accepts an incoming channel of any type.
func (s *Session) AcceptChannel(ctx context.Context) (*Channel, error) {
	return s.AcceptChannelWithType(ctx, "")
}

// AcceptChannelWithType waits for and accepts an incoming channel of the specified type.
// If channelType is empty, any channel type is accepted.
//
// Uses a broadcast notification pattern so that multiple goroutines waiting for
// different channel types are all woken when a new channel arrives. Each waiter
// checks the queue for its specific type, avoiding the livelock that would occur
// with a single-consumer notification channel.
func (s *Session) AcceptChannelWithType(ctx context.Context, channelType string) (*Channel, error) {
	for {
		// Check for a matching channel in the queue and capture the current
		// broadcast channel for waiting. Both must happen under the same lock
		// to avoid missing a notification between the check and the select.
		s.mu.Lock()
		for i, ch := range s.acceptQueue {
			if channelType == "" || ch.ChannelType == channelType {
				s.acceptQueue = append(s.acceptQueue[:i], s.acceptQueue[i+1:]...)
				s.mu.Unlock()
				return ch, nil
			}
		}
		broadcast := s.acceptBroadcast
		s.mu.Unlock()

		// Wait for a new channel (broadcast), session close, or context cancellation.
		select {
		case <-broadcast:
			// A new channel was enqueued; loop around to check.
		case <-s.done:
			return nil, &ConnectionError{
				Reason: messages.DisconnectByApplication,
				Msg:    "session closed while waiting for channel",
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// getChannel returns the channel with the given local ID, or nil if not found.
func (s *Session) getChannel(localID uint32) *Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.channels[localID]
}

// handleChannelOpen processes an incoming channel open request.
func (s *Session) handleChannelOpen(payload []byte) error {
	msg := &messages.ChannelOpenMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read channel open: %w", err)
	}

	s.mu.Lock()
	localID := s.nextChannelID
	s.nextChannelID++
	s.mu.Unlock()

	ch := newChannel(s, msg.ChannelType, localID)
	ch.RemoteChannelID = msg.SenderChannel
	ch.openMessage = msg

	// Try to activate a service for this channel type.
	svc := s.activateServiceByChannelType(msg.ChannelType)

	args := &ChannelOpeningEventArgs{
		Request:         msg,
		Channel:         ch,
		IsRemoteRequest: true,
		Ctx:             context.Background(),
		Payload:         payload,
	}

	// Snapshot callback under lock to avoid data race with concurrent setter.
	s.mu.Lock()
	onChannelOpening := s.OnChannelOpening
	s.mu.Unlock()

	if svc != nil {
		svc.OnChannelOpening(args)
	} else if onChannelOpening != nil {
		onChannelOpening(args)
	}

	if args.FailureReason != messages.ChannelOpenFailureNone {
		s.trace(TraceLevelWarning, TraceEventChannelOpenFailed,
			fmt.Sprintf("Channel open failed: type=%s reason=%d %s",
				msg.ChannelType, args.FailureReason, args.FailureDescription))
		failMsg := &messages.ChannelOpenFailureMessage{
			RecipientChannel: msg.SenderChannel,
			ReasonCode:       args.FailureReason,
			Description:      args.FailureDescription,
		}
		return s.protocol.sendMessage(failMsg.ToBuffer())
	}

	// Add channel to active channels and start request handler.
	s.mu.Lock()
	acceptQueueLen := len(s.acceptQueue)
	s.mu.Unlock()

	if acceptQueueLen >= maxAcceptQueueSize {
		s.trace(TraceLevelWarning, TraceEventChannelOpenFailed,
			fmt.Sprintf("Channel open rejected: accept queue full (%d), type=%s",
				acceptQueueLen, msg.ChannelType))
		failMsg := &messages.ChannelOpenFailureMessage{
			RecipientChannel: msg.SenderChannel,
			ReasonCode:       messages.ChannelOpenFailureResourceShortage,
			Description:      "accept queue full",
		}
		return s.protocol.sendMessage(failMsg.ToBuffer())
	}

	s.mu.Lock()
	s.channels[localID] = ch
	s.mu.Unlock()
	ch.startRequestHandler()

	// Send confirmation.
	confirmMsg := &messages.ChannelOpenConfirmationMessage{
		RecipientChannel: msg.SenderChannel,
		SenderChannel:    localID,
		MaxWindowSize:    ch.MaxWindowSize,
		MaxPacketSize:    ch.MaxPacketSize,
	}
	ch.openConfirmationMessage = confirmMsg
	if err := s.protocol.sendMessage(confirmMsg.ToBuffer()); err != nil {
		return err
	}

	// Enable sending on this channel.
	ch.enableSending(msg.MaxWindowSize, msg.MaxPacketSize)

	s.trace(TraceLevelInfo, TraceEventChannelOpened,
		fmt.Sprintf("Channel opened: type=%s id=%d remoteId=%d",
			msg.ChannelType, localID, msg.SenderChannel))

	// Queue channel for acceptance (non-blocking, never stalls the dispatch loop).
	// Close the old broadcast channel to wake ALL waiting goroutines, then create
	// a new one for subsequent waits. This ensures typed acceptors are all notified.
	s.mu.Lock()
	s.acceptQueue = append(s.acceptQueue, ch)
	old := s.acceptBroadcast
	s.acceptBroadcast = make(chan struct{})
	s.mu.Unlock()
	close(old)

	return nil
}

// handleChannelOpenConfirmation processes a channel open confirmation response.
func (s *Session) handleChannelOpenConfirmation(payload []byte) error {
	msg := &messages.ChannelOpenConfirmationMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read channel open confirmation: %w", err)
	}

	s.mu.Lock()
	pending, ok := s.pendingOpens[msg.RecipientChannel]
	if ok {
		delete(s.pendingOpens, msg.RecipientChannel)
	}
	s.mu.Unlock()

	if !ok {
		// No pending open for this channel ID, ignore.
		return nil
	}

	// Reuse the original Channel created during OpenChannel, preserving its
	// ChannelType and internal signaling channels (sendEnabled, windowAvailable,
	// closeDone) so that nothing is leaked.
	ch := pending.channel
	ch.RemoteChannelID = msg.SenderChannel
	ch.openConfirmationMessage = msg

	// Add channel to active channels and start request handler.
	s.mu.Lock()
	s.channels[msg.RecipientChannel] = ch
	s.mu.Unlock()
	ch.startRequestHandler()

	// Enable sending.
	ch.enableSending(msg.MaxWindowSize, msg.MaxPacketSize)

	s.trace(TraceLevelInfo, TraceEventChannelOpened,
		fmt.Sprintf("Channel opened: type=%s id=%d remoteId=%d",
			ch.ChannelType, ch.ChannelID, msg.SenderChannel))

	// Complete the pending open request.
	pending.resultCh <- &channelOpenResult{channel: ch}

	return nil
}

// handleChannelOpenFailure processes a channel open failure response.
func (s *Session) handleChannelOpenFailure(payload []byte) error {
	msg := &messages.ChannelOpenFailureMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read channel open failure: %w", err)
	}

	s.mu.Lock()
	pending, ok := s.pendingOpens[msg.RecipientChannel]
	if ok {
		delete(s.pendingOpens, msg.RecipientChannel)
	}
	s.mu.Unlock()

	if !ok {
		return nil
	}

	s.trace(TraceLevelWarning, TraceEventChannelOpenFailed,
		fmt.Sprintf("Channel open failed: reason=%d %s",
			msg.ReasonCode, msg.Description))

	pending.resultCh <- &channelOpenResult{
		err: &ChannelError{
			Reason: msg.ReasonCode,
			Msg:    msg.Description,
		},
	}

	return nil
}

// handleChannelWindowAdjust processes a window adjust message.
func (s *Session) handleChannelWindowAdjust(payload []byte) error {
	msg := &messages.ChannelWindowAdjustMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read channel window adjust: %w", err)
	}

	ch := s.getChannel(msg.RecipientChannel)
	if ch == nil {
		// Unknown channel, ignore (per acceptance criteria).
		return nil
	}

	if err := ch.adjustRemoteWindow(msg.BytesToAdd); err != nil {
		return err
	}
	return nil
}

// handleChannelData processes incoming channel data.
func (s *Session) handleChannelData(payload []byte) error {
	msg := &messages.ChannelDataMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read channel data: %w", err)
	}

	ch := s.getChannel(msg.RecipientChannel)
	if ch == nil {
		// Unknown channel, ignore.
		return nil
	}

	ch.handleDataReceived(msg.Data)
	return nil
}

// handleChannelExtendedData processes incoming channel extended data.
func (s *Session) handleChannelExtendedData(payload []byte) error {
	msg := &messages.ChannelExtendedDataMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read channel extended data: %w", err)
	}

	ch := s.getChannel(msg.RecipientChannel)
	if ch == nil {
		return nil
	}

	ch.handleExtendedDataReceived(SSHExtendedDataType(msg.DataTypeCode), msg.Data)
	return nil
}

// handleChannelEof processes an incoming EOF message.
func (s *Session) handleChannelEof(payload []byte) error {
	msg := &messages.ChannelEofMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read channel eof: %w", err)
	}

	ch := s.getChannel(msg.RecipientChannel)
	if ch == nil {
		// Unknown channel, ignore.
		return nil
	}

	ch.handleEof()
	return nil
}

// handleChannelClose processes an incoming close message.
func (s *Session) handleChannelClose(payload []byte) error {
	msg := &messages.ChannelCloseMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read channel close: %w", err)
	}

	ch := s.getChannel(msg.RecipientChannel)
	if ch == nil {
		return nil
	}

	ch.handleClose()

	s.trace(TraceLevelInfo, TraceEventChannelClosed,
		fmt.Sprintf("Channel closed: type=%s id=%d", ch.ChannelType, ch.ChannelID))

	// Remove channel from active channels.
	s.mu.Lock()
	delete(s.channels, ch.ChannelID)
	s.mu.Unlock()

	return nil
}

// handleChannelRequest processes an incoming channel request.
// Exit-status and exit-signal are handled inline (internal state changes).
// All other requests are enqueued to the per-channel request goroutine,
// decoupling handler execution from the dispatch loop.
func (s *Session) handleChannelRequest(payload []byte) error {
	basicMsg := &messages.ChannelRequestMessage{}
	if err := messages.ReadMessage(basicMsg, payload); err != nil {
		return fmt.Errorf("failed to read channel request: %w", err)
	}

	ch := s.getChannel(basicMsg.RecipientChannel)
	if ch == nil {
		return nil
	}

	// Exit-status and exit-signal are internal state changes, handled inline.
	switch basicMsg.RequestType {
	case "exit-status", "exit-signal":
		signalMsg := &messages.ChannelSignalMessage{}
		if err := messages.ReadMessage(signalMsg, payload); err != nil {
			return fmt.Errorf("failed to read channel signal: %w", err)
		}
		ch.handleSignal(signalMsg)
		return nil
	}

	// All other requests (including "signal") are enqueued to the per-channel
	// request goroutine. Replies are sent from the handler goroutine, not here.
	req := &pendingRequest{
		payload:  payload,
		basicMsg: basicMsg,
	}

	if !ch.enqueueRequest(req) {
		// Queue is full — reject with channel-failure if want_reply.
		ch.metrics.addDroppedRequest()
		if basicMsg.WantReply {
			reply := &messages.ChannelFailureMessage{
				RecipientChannel: ch.RemoteChannelID,
			}
			_ = s.SendMessage(reply)
		} else {
			log.Printf("ssh: dropped fire-and-forget channel request %q on channel %d (queue full)",
				basicMsg.RequestType, ch.ChannelID)
		}
	}

	return nil
}

// handleChannelRequestResponse processes a channel success or failure message.
func (s *Session) handleChannelRequestResponse(payload []byte, success bool) error {
	// Both ChannelSuccess and ChannelFailure have the same format: just a RecipientChannel.
	// Parse it manually since both message types share the format.
	var recipientChannel uint32
	if success {
		msg := &messages.ChannelSuccessMessage{}
		if err := messages.ReadMessage(msg, payload); err != nil {
			return fmt.Errorf("failed to read channel success: %w", err)
		}
		recipientChannel = msg.RecipientChannel
	} else {
		msg := &messages.ChannelFailureMessage{}
		if err := messages.ReadMessage(msg, payload); err != nil {
			return fmt.Errorf("failed to read channel failure: %w", err)
		}
		recipientChannel = msg.RecipientChannel
	}

	ch := s.getChannel(recipientChannel)
	if ch == nil {
		return nil
	}

	ch.handleRequestResponse(success)
	return nil
}

// Channels returns a snapshot (copy) of the active channels map.
// The returned map is safe to iterate without holding any lock.
func (s *Session) Channels() map[uint32]*Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := make(map[uint32]*Channel, len(s.channels))
	for id, ch := range s.channels {
		snapshot[id] = ch
	}
	return snapshot
}


