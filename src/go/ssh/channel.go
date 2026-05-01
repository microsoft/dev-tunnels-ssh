// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"log"
	"math"
	"runtime/debug"
	"sync"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

const (
	// requestQueueCapacity is the buffer size for the per-channel request queue.
	requestQueueCapacity = 16
)

// pendingRequest pairs a channel request message with its raw payload
// for processing by the per-channel request goroutine.
type pendingRequest struct {
	payload  []byte
	basicMsg *messages.ChannelRequestMessage
}

// SSHExtendedDataType represents the type code for SSH extended data.
type SSHExtendedDataType uint32

const (
	// ExtendedDataStderr is the standard type code for stderr data.
	ExtendedDataStderr SSHExtendedDataType = 1
)

const (
	// DefaultMaxPacketSize is the default maximum packet size for channel data (32 KB).
	DefaultMaxPacketSize uint32 = 32 * 1024

	// DefaultMaxWindowSize is the default maximum window size for channel flow control (1 MB).
	DefaultMaxWindowSize uint32 = DefaultMaxPacketSize * 32
)

// pendingExtended stores a buffered extended data message.
type pendingExtended struct {
	dataType SSHExtendedDataType
	data     []byte
}

// Channel represents a single SSH channel within a session.
// Channels are multiplexed over a single SSH connection and support
// bidirectional data transfer with flow control.
type Channel struct {
	// ChannelType is the type string for this channel (e.g., "session").
	ChannelType string

	// ChannelID is the local channel ID.
	ChannelID uint32

	// RemoteChannelID is the remote side's channel ID.
	RemoteChannelID uint32

	// MaxWindowSize is the local maximum receive window size.
	MaxWindowSize uint32

	// MaxPacketSize is the local maximum packet size.
	MaxPacketSize uint32

	// OnDataReceived is called when data is received on this channel.
	// The handler must call AdjustWindow(len(data)) when done processing.
	OnDataReceived func(data []byte)

	// OnExtendedDataReceived is called when extended data (e.g. stderr) is received.
	// If nil, extended data falls through to OnDataReceived for backward compatibility.
	// The handler must call AdjustWindow(len(data)) when done processing.
	OnExtendedDataReceived func(dataType SSHExtendedDataType, data []byte)

	// OnClosed is called when the channel is closed.
	OnClosed func(*ChannelClosedEventArgs)

	// OnEof is called when an EOF message is received from the remote side.
	OnEof func()

	// OnRequest is called when a channel request is received.
	OnRequest func(*RequestEventArgs)

	// openMessage is the message that requested opening the channel.
	openMessage *messages.ChannelOpenMessage

	// openConfirmationMessage is the message that confirmed opening the channel.
	openConfirmationMessage *messages.ChannelOpenConfirmationMessage

	session          *Session
	mu               sync.Mutex
	sendMu           sync.Mutex // serializes Send calls to prevent data interleaving
	remoteWindowSize uint32
	remotePacketSize uint32
	windowSize       uint32
	sentEof          bool
	receivedEof      bool
	localClosed      bool
	remoteClosed     bool
	disposed         bool
	exitStatus       *uint32
	exitSignal       string
	errorMessage     string
	pendingData         [][]byte          // buffers received data when no OnDataReceived handler is set
	pendingExtendedData []pendingExtended // buffers received extended data when no handler is set

	// pendingRequests tracks pending channel request responses in FIFO order.
	// SSH requires responses to arrive in the same order as requests.
	pendingRequests []chan bool

	// sendEnabled is closed when the channel is fully opened and ready for data.
	sendEnabled chan struct{}

	// windowAvailable is signaled when remote window opens up.
	windowAvailable chan struct{}

	// closeDone is closed when the remote close message is received (bilateral close complete).
	closeDone chan struct{}

	// requestsCh is a buffered channel for queuing incoming channel requests.
	// Requests are processed sequentially by a per-channel goroutine, decoupling
	// handler execution from the dispatch loop.
	requestsCh chan *pendingRequest

	// requestDone is closed when the per-channel request goroutine exits.
	requestDone chan struct{}

	// requestsChClosed tracks whether requestsCh has been closed to prevent double-close.
	requestsChClosed bool

	// requestHandlerStarted tracks whether the request handler goroutine has been launched.
	requestHandlerStarted bool

	// metrics tracks channel-level byte counters.
	metrics ChannelMetrics
}

// newChannel creates a new channel associated with the given session.
func newChannel(session *Session, channelType string, channelID uint32) *Channel {
	maxWindowSize := DefaultMaxWindowSize
	if session != nil && session.Config != nil && session.Config.MaxChannelWindowSize > 0 {
		maxWindowSize = session.Config.MaxChannelWindowSize
	}
	return &Channel{
		ChannelType:     channelType,
		ChannelID:       channelID,
		MaxWindowSize:   maxWindowSize,
		MaxPacketSize:   DefaultMaxPacketSize,
		windowSize:      maxWindowSize,
		session:         session,
		sendEnabled:     make(chan struct{}),
		windowAvailable: make(chan struct{}),
		closeDone:       make(chan struct{}),
		requestsCh:      make(chan *pendingRequest, requestQueueCapacity),
		requestDone:     make(chan struct{}),
	}
}

// Metrics returns a pointer to the channel's metrics counters.
func (c *Channel) Metrics() *ChannelMetrics {
	return &c.metrics
}

// newSessionContext returns a context that is cancelled when the session's
// dispatch loop exits (session.Done() is closed). Callers must call the
// returned cancel function when done (typically via defer).
func (c *Channel) newSessionContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	done := c.session.Done()
	if done == nil {
		return ctx, cancel
	}
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// OpenMessage returns the message that requested opening the channel.
// It is non-nil after the channel is opened.
func (c *Channel) OpenMessage() *messages.ChannelOpenMessage {
	return c.openMessage
}

// OpenConfirmationMessage returns the message that confirmed opening the channel.
// It is non-nil after the channel open is confirmed.
func (c *Channel) OpenConfirmationMessage() *messages.ChannelOpenConfirmationMessage {
	return c.openConfirmationMessage
}

// IsClosed returns true if the channel has been closed.
func (c *Channel) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.disposed || (c.localClosed && c.remoteClosed)
}

// Request sends a channel request and waits for a success/failure response.
// Returns true if the request was accepted, false otherwise.
func (c *Channel) Request(ctx context.Context, msg *messages.ChannelRequestMessage) (bool, error) {
	// Check for cancellation before doing anything.
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	c.mu.Lock()
	if c.localClosed || c.disposed {
		c.mu.Unlock()
		return false, ErrClosed
	}

	// Set the recipient channel ID.
	msg.RecipientChannel = c.RemoteChannelID

	if !msg.WantReply {
		c.mu.Unlock()
		// Fire-and-forget: no response expected.
		if err := c.session.SendMessage(msg); err != nil {
			return false, err
		}
		return true, nil
	}

	// Append a response channel to the FIFO queue.
	resultCh := make(chan bool, 1)
	c.pendingRequests = append(c.pendingRequests, resultCh)
	c.mu.Unlock()

	// Send the request.
	if err := c.session.SendMessage(msg); err != nil {
		c.mu.Lock()
		c.removePendingRequest(resultCh)
		c.mu.Unlock()
		return false, err
	}

	// Wait for response.
	select {
	case success := <-resultCh:
		return success, nil
	case <-c.closeDone:
		c.mu.Lock()
		c.removePendingRequest(resultCh)
		c.mu.Unlock()
		return false, nil
	case <-ctx.Done():
		c.mu.Lock()
		c.removePendingRequest(resultCh)
		c.mu.Unlock()
		return false, ctx.Err()
	}
}

// removePendingRequest removes a specific result channel from the FIFO queue.
// Must be called with c.mu held.
func (c *Channel) removePendingRequest(ch chan bool) {
	for i, pending := range c.pendingRequests {
		if pending == ch {
			c.pendingRequests = append(c.pendingRequests[:i], c.pendingRequests[i+1:]...)
			return
		}
	}
}

// handleRequestResponse is called when a ChannelSuccess or ChannelFailure is received.
func (c *Channel) handleRequestResponse(success bool) {
	c.mu.Lock()
	var ch chan bool
	if len(c.pendingRequests) > 0 {
		ch = c.pendingRequests[0]
		c.pendingRequests = c.pendingRequests[1:]
	}
	c.mu.Unlock()

	if ch != nil {
		ch <- success
	}
}

// enableSending marks the channel as fully opened and ready for data transfer.
// Called after the channel open confirmation exchange completes.
func (c *Channel) enableSending(remoteWindowSize, remotePacketSize uint32) {
	c.mu.Lock()
	c.remoteWindowSize = remoteWindowSize
	c.remotePacketSize = remotePacketSize
	c.mu.Unlock()

	select {
	case <-c.sendEnabled:
		// Already enabled
	default:
		close(c.sendEnabled)
	}
}

// Send sends data on the channel. It blocks if the remote window is exhausted
// and resumes when a WindowAdjust message is received.
// Sending empty/nil data sends an EOF message.
// Send is safe for concurrent use; multiple sends are serialized to prevent
// data interleaving across multi-packet messages.
func (c *Channel) Send(ctx context.Context, data []byte) error {
	if len(data) == 0 {
		return c.sendEof(ctx)
	}

	// Serialize sends to prevent interleaving of multi-packet messages.
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	c.mu.Lock()
	if c.sentEof {
		c.mu.Unlock()
		return fmt.Errorf("cannot send data after EOF")
	}
	if c.localClosed || c.disposed {
		c.mu.Unlock()
		return ErrClosed
	}
	c.mu.Unlock()

	// Wait for channel to be fully opened.
	select {
	case <-c.sendEnabled:
	case <-ctx.Done():
		return ctx.Err()
	}

	offset := 0
	for offset < len(data) {
		c.mu.Lock()
		if c.localClosed || c.disposed {
			c.mu.Unlock()
			return ErrClosed
		}

		packetSize := c.calculatePacketSize(len(data) - offset)
		if packetSize > 0 {
			// Reserve window space before sending to prevent concurrent
			// goroutines from seeing stale window sizes.
			c.remoteWindowSize -= packetSize
		}
		c.mu.Unlock()

		if packetSize == 0 {
			c.mu.Lock()
			ch := c.windowAvailable
			if c.remoteWindowSize > 0 {
				packetSize = c.calculatePacketSize(len(data) - offset)
				c.remoteWindowSize -= packetSize
				c.mu.Unlock()
			} else {
				c.mu.Unlock()
				select {
				case <-ch:
					continue
				case <-c.closeDone:
					return ErrClosed
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		// Use a sub-slice of the data buffer for the chunk.
		chunk := data[offset : offset+int(packetSize)]

		msg := &messages.ChannelDataMessage{
			RecipientChannel: c.RemoteChannelID,
			Data:             chunk,
		}
		if err := c.session.SendMessage(msg); err != nil {
			return err
		}

		c.metrics.addBytesSent(int64(packetSize))
		offset += int(packetSize)
	}

	return nil
}

// sendEof sends an EOF message on the channel.
func (c *Channel) sendEof(ctx context.Context) error {
	c.mu.Lock()
	if c.sentEof {
		c.mu.Unlock()
		return nil
	}
	c.sentEof = true
	c.mu.Unlock()

	msg := &messages.ChannelEofMessage{
		RecipientChannel: c.RemoteChannelID,
	}
	return c.session.SendMessage(msg)
}

// calculatePacketSize returns the size of the next data chunk to send,
// bounded by remote window size, remote max packet size, and available data.
// Must be called with c.mu held.
func (c *Channel) calculatePacketSize(remaining int) uint32 {
	size := c.remoteWindowSize
	if size > c.remotePacketSize {
		size = c.remotePacketSize
	}
	if size > uint32(remaining) {
		size = uint32(remaining)
	}
	return size
}

// AdjustWindow is called by the data receiver after processing received data.
// It sends a WindowAdjust message to the remote side when more than 50% of
// the window has been consumed.
func (c *Channel) AdjustWindow(messageLength uint32) {
	c.mu.Lock()
	if c.windowSize < messageLength {
		c.windowSize = 0
	} else {
		c.windowSize -= messageLength
	}

	if c.windowSize <= c.MaxWindowSize/2 {
		bytesToAdd := c.MaxWindowSize - c.windowSize
		c.windowSize = c.MaxWindowSize
		c.mu.Unlock()

		msg := &messages.ChannelWindowAdjustMessage{
			RecipientChannel: c.RemoteChannelID,
			BytesToAdd:       bytesToAdd,
		}
		if err := c.session.SendMessage(msg); err != nil {
			log.Printf("ssh: failed to send window adjust for channel %d: %v", c.ChannelID, err)
		}
	} else {
		c.mu.Unlock()
	}
}

// adjustRemoteWindow is called when a WindowAdjust message is received from remote.
// Returns an error if the adjustment would cause the window size to overflow uint32.
func (c *Channel) adjustRemoteWindow(bytesToAdd uint32) error {
	c.mu.Lock()
	if c.remoteWindowSize > math.MaxUint32-bytesToAdd {
		c.mu.Unlock()
		return fmt.Errorf("channel window adjust would overflow: current=%d, add=%d",
			c.remoteWindowSize, bytesToAdd)
	}
	c.remoteWindowSize += bytesToAdd

	// Close-based signaling: close the current channel and replace it.
	old := c.windowAvailable
	c.windowAvailable = make(chan struct{})
	c.mu.Unlock()

	close(old)
	return nil
}

// handleDataReceived is called when channel data is received from the remote side.
// If no OnDataReceived handler is set, data is buffered but the window is NOT
// adjusted. This back-pressures the remote side so that it stops sending when the
// window is exhausted. Use SetDataReceivedHandler to attach a handler; the handler
// is responsible for calling AdjustWindow after processing each message.
func (c *Channel) handleDataReceived(data []byte) {
	c.metrics.addBytesReceived(int64(len(data)))

	c.mu.Lock()
	handler := c.OnDataReceived
	if handler == nil {
		// Buffer data when no listener is attached.
		// Do NOT call AdjustWindow — the remote side is back-pressured
		// so that unbounded data does not accumulate.
		buf := make([]byte, len(data))
		copy(buf, data)
		c.pendingData = append(c.pendingData, buf)
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	handler(data)
}

// SetClosedHandler sets the OnClosed callback in a thread-safe manner.
func (c *Channel) SetClosedHandler(handler func(*ChannelClosedEventArgs)) {
	c.mu.Lock()
	c.OnClosed = handler
	c.mu.Unlock()
}

// SetDataReceivedHandler sets the OnDataReceived callback and flushes any
// data that was buffered while no handler was attached.
func (c *Channel) SetDataReceivedHandler(handler func([]byte)) {
	c.mu.Lock()
	c.OnDataReceived = handler
	pending := c.pendingData
	c.pendingData = nil
	c.mu.Unlock()

	if handler != nil {
		for _, data := range pending {
			handler(data)
		}
	}
}

// handleExtendedDataReceived is called when extended channel data is received.
// If OnExtendedDataReceived is set, it is called with the type code and data.
// If only OnDataReceived is set, data falls through to it (backward compatibility).
// If neither is set, data is buffered in pendingExtendedData (preserving type codes)
// until SetExtendedDataReceivedHandler is called.
func (c *Channel) handleExtendedDataReceived(dataType SSHExtendedDataType, data []byte) {
	c.metrics.addBytesReceived(int64(len(data)))

	c.mu.Lock()
	handler := c.OnExtendedDataReceived
	if handler != nil {
		c.mu.Unlock()
		handler(dataType, data)
		return
	}

	// No extended data handler — check regular handler for backward compat.
	regularHandler := c.OnDataReceived
	if regularHandler != nil {
		c.mu.Unlock()
		regularHandler(data)
		return
	}

	// Neither handler set — buffer with type code preserved.
	buf := make([]byte, len(data))
	copy(buf, data)
	c.pendingExtendedData = append(c.pendingExtendedData, pendingExtended{dataType: dataType, data: buf})
	c.mu.Unlock()
}

// SetExtendedDataReceivedHandler sets the OnExtendedDataReceived callback and
// flushes any extended data that was buffered while no handler was attached.
func (c *Channel) SetExtendedDataReceivedHandler(handler func(SSHExtendedDataType, []byte)) {
	c.mu.Lock()
	c.OnExtendedDataReceived = handler
	pending := c.pendingExtendedData
	c.pendingExtendedData = nil
	c.mu.Unlock()

	if handler != nil {
		for _, item := range pending {
			handler(item.dataType, item.data)
		}
	}
}

// SendExtendedData sends extended data (e.g. stderr) on the channel.
// It respects flow control the same way as Send.
func (c *Channel) SendExtendedData(ctx context.Context, dataType SSHExtendedDataType, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// Serialize sends to prevent interleaving of multi-packet messages.
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	c.mu.Lock()
	if c.sentEof {
		c.mu.Unlock()
		return fmt.Errorf("cannot send data after EOF")
	}
	if c.localClosed || c.disposed {
		c.mu.Unlock()
		return ErrClosed
	}
	c.mu.Unlock()

	// Wait for channel to be fully opened.
	select {
	case <-c.sendEnabled:
	case <-ctx.Done():
		return ctx.Err()
	}

	offset := 0
	for offset < len(data) {
		c.mu.Lock()
		if c.localClosed || c.disposed {
			c.mu.Unlock()
			return ErrClosed
		}

		packetSize := c.calculatePacketSize(len(data) - offset)
		if packetSize > 0 {
			c.remoteWindowSize -= packetSize
		}
		c.mu.Unlock()

		if packetSize == 0 {
			c.mu.Lock()
			ch := c.windowAvailable
			if c.remoteWindowSize > 0 {
				packetSize = c.calculatePacketSize(len(data) - offset)
				c.remoteWindowSize -= packetSize
				c.mu.Unlock()
			} else {
				c.mu.Unlock()
				select {
				case <-ch:
					continue
				case <-c.closeDone:
					return ErrClosed
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		chunk := data[offset : offset+int(packetSize)]

		msg := &messages.ChannelExtendedDataMessage{
			RecipientChannel: c.RemoteChannelID,
			DataTypeCode:     uint32(dataType),
			Data:             chunk,
		}
		if err := c.session.SendMessage(msg); err != nil {
			return err
		}

		c.metrics.addBytesSent(int64(packetSize))
		offset += int(packetSize)
	}

	return nil
}

// SetRequestHandler sets the OnRequest callback in a thread-safe manner.
// Use this method instead of direct field assignment when the channel is already
// active, to avoid data races with the request handler goroutine.
func (c *Channel) SetRequestHandler(handler func(*RequestEventArgs)) {
	c.mu.Lock()
	c.OnRequest = handler
	c.mu.Unlock()
}

// SetEofHandler sets the OnEof callback in a thread-safe manner.
func (c *Channel) SetEofHandler(handler func()) {
	c.mu.Lock()
	c.OnEof = handler
	c.mu.Unlock()
}

// handleEof is called when an EOF message is received from the remote side.
func (c *Channel) handleEof() {
	c.mu.Lock()
	c.receivedEof = true
	handler := c.OnEof
	c.mu.Unlock()

	if handler != nil {
		handler()
	}
}

// handleRequest is called when a channel request is received.
// It recovers from panics in the handler and returns false if one occurs.
func (c *Channel) handleRequest(msg *messages.ChannelRequestMessage) (success bool) {
	c.mu.Lock()
	handler := c.OnRequest
	c.mu.Unlock()

	if handler != nil {
		// Recover from panics in the handler to prevent crashing the dispatch loop.
		defer func() {
			if r := recover(); r != nil {
				success = false
			}
		}()

		c.session.mu.Lock()
		principal := c.session.Principal
		c.session.mu.Unlock()

		ctx, cancel := c.newSessionContext()
		defer cancel()

		args := &RequestEventArgs{
			RequestType:  msg.RequestType,
			Request:      msg,
			IsAuthorized: false,
			Principal:    principal,
			Ctx:          ctx,
		}
		handler(args)
		return args.IsAuthorized
	}
	return false
}

// startRequestHandler launches the per-channel request goroutine.
// Must be called once when the channel becomes active (added to session's channels map).
func (c *Channel) startRequestHandler() {
	c.mu.Lock()
	c.requestHandlerStarted = true
	c.mu.Unlock()
	go c.runRequestHandler()
}

// runRequestHandler is the per-channel goroutine that drains requestsCh
// and invokes OnRequest sequentially for this channel.
func (c *Channel) runRequestHandler() {
	defer close(c.requestDone)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ssh: panic in request handler goroutine for channel %d: %v\n%s",
				c.ChannelID, r, debug.Stack())
			// Do NOT call c.Close() here — Close() waits for requestDone,
			// which is closed by our sibling defer, causing a deadlock.
			// Instead, just close the request channel so no more requests
			// are enqueued. The deferred close(c.requestDone) will signal
			// any future Close() call that we're done.
			c.closeRequestsCh()
		}
	}()

	for req := range c.requestsCh {
		c.processRequest(req)
	}
}

// processRequest handles a single channel request in the per-channel goroutine.
// It invokes the OnRequest handler (or service handler) and sends the reply.
func (c *Channel) processRequest(req *pendingRequest) {
	var success bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("ssh: panic in channel request handler for channel %d, request %q: %v\n%s",
					c.ChannelID, req.basicMsg.RequestType, r, debug.Stack())
				success = false
			}
		}()

		switch req.basicMsg.RequestType {
		case "signal":
			signalMsg := &messages.ChannelSignalMessage{}
			if err := messages.ReadMessage(signalMsg, req.payload); err != nil {
				return
			}
			success = c.handleSignalRequest(signalMsg)
		default:
			svc := c.session.activateServiceByChannelRequest(c.ChannelType, req.basicMsg.RequestType)
			if svc != nil {
				c.session.mu.Lock()
				principal := c.session.Principal
				c.session.mu.Unlock()

				ctx, cancel := c.newSessionContext()
				defer cancel()

				args := &RequestEventArgs{
					RequestType:  req.basicMsg.RequestType,
					Request:      req.basicMsg,
					IsAuthorized: false,
					Principal:    principal,
					Ctx:          ctx,
				}
				svc.OnChannelRequest(c, args)
				success = args.IsAuthorized
			} else {
				success = c.handleRequest(req.basicMsg)
			}
		}
	}()

	if req.basicMsg.WantReply {
		var reply messages.Message
		if success {
			reply = &messages.ChannelSuccessMessage{
				RecipientChannel: c.RemoteChannelID,
			}
		} else {
			reply = &messages.ChannelFailureMessage{
				RecipientChannel: c.RemoteChannelID,
			}
		}
		_ = c.session.SendMessage(reply)
	}
}

// enqueueRequest enqueues a channel request for processing by the per-channel
// request goroutine. Returns true if enqueued, false if the queue is full.
func (c *Channel) enqueueRequest(req *pendingRequest) bool {
	select {
	case c.requestsCh <- req:
		return true
	default:
		return false
	}
}

// closeRequestsCh closes the request channel to signal the request goroutine to exit.
// Safe to call multiple times.
func (c *Channel) closeRequestsCh() {
	c.mu.Lock()
	if !c.requestsChClosed {
		c.requestsChClosed = true
		if !c.requestHandlerStarted {
			// No goroutine was started, close requestDone ourselves.
			close(c.requestDone)
		}
		close(c.requestsCh)
	}
	c.mu.Unlock()
}

// handleSignal is called when an exit-status or exit-signal message is received.
// These are consumed internally and stored on the channel.
func (c *Channel) handleSignal(msg *messages.ChannelSignalMessage) {
	c.mu.Lock()
	switch msg.RequestType {
	case "exit-status":
		status := msg.ExitStatus
		c.exitStatus = &status
	case "exit-signal":
		c.exitSignal = msg.ExitSignal
		c.errorMessage = msg.ErrorMessage
	}
	c.mu.Unlock()
}

// handleSignalRequest is called when a standalone "signal" channel request is received.
// Unlike exit-status/exit-signal, standalone signals are delivered to the application
// via OnRequest, matching C#/TS behavior.
func (c *Channel) handleSignalRequest(msg *messages.ChannelSignalMessage) (success bool) {
	c.mu.Lock()
	handler := c.OnRequest
	c.mu.Unlock()

	if handler != nil {
		defer func() {
			if r := recover(); r != nil {
				success = false
			}
		}()

		c.session.mu.Lock()
		principal := c.session.Principal
		c.session.mu.Unlock()

		ctx, cancel := c.newSessionContext()
		defer cancel()

		args := &RequestEventArgs{
			RequestType:  msg.RequestType,
			Request:      msg,
			IsAuthorized: false,
			Principal:    principal,
			Ctx:          ctx,
		}
		handler(args)
		return args.IsAuthorized
	}
	return false
}

// SendSignal sends a standalone signal channel request to the remote side.
// The signalName should be a signal name like "TERM", "HUP", "INT", etc.
func (c *Channel) SendSignal(ctx context.Context, signalName string) error {
	msg := &messages.ChannelSignalMessage{
		RecipientChannel: c.RemoteChannelID,
		RequestType:      "signal",
		WantReply:        false,
		Signal:           signalName,
	}
	return c.session.SendMessage(msg)
}

// Close closes the channel by sending EOF (if not already sent) and Close messages.
// It waits for the remote side to acknowledge the close.
func (c *Channel) Close() error {
	return c.CloseWithContext(context.Background())
}

// CloseWithContext closes the channel with context support.
func (c *Channel) CloseWithContext(ctx context.Context) error {
	return c.closeInternal(ctx, nil, "", "")
}

// CloseWithStatus closes the channel with an exit status code.
// The exit status is propagated to the remote side via OnClosed callback.
func (c *Channel) CloseWithStatus(ctx context.Context, exitStatus uint32) error {
	return c.closeInternal(ctx, &exitStatus, "", "")
}

// CloseWithSignal closes the channel with a signal name and error message.
// The signal info is propagated to the remote side via OnClosed callback.
func (c *Channel) CloseWithSignal(ctx context.Context, signal string, errorMessage string) error {
	return c.closeInternal(ctx, nil, signal, errorMessage)
}

// closeInternal is the common close implementation that optionally sends exit status or signal.
func (c *Channel) closeInternal(ctx context.Context, exitStatus *uint32, signal string, errorMessage string) error {
	c.mu.Lock()
	if c.localClosed || c.disposed {
		c.mu.Unlock()
		return nil
	}
	c.localClosed = true
	c.mu.Unlock()

	// Send exit status or signal if specified.
	if exitStatus != nil {
		signalMsg := &messages.ChannelSignalMessage{
			RecipientChannel: c.RemoteChannelID,
			RequestType:      "exit-status",
			WantReply:        false,
			ExitStatus:       *exitStatus,
		}
		_ = c.session.SendMessage(signalMsg)
	} else if signal != "" {
		signalMsg := &messages.ChannelSignalMessage{
			RecipientChannel: c.RemoteChannelID,
			RequestType:      "exit-signal",
			WantReply:        false,
			ExitSignal:       signal,
			ErrorMessage:     errorMessage,
		}
		_ = c.session.SendMessage(signalMsg)
	}

	// Send EOF if not already sent.
	_ = c.sendEof(ctx)

	// Send close message.
	closeMsg := &messages.ChannelCloseMessage{
		RecipientChannel: c.RemoteChannelID,
	}
	if err := c.session.SendMessage(closeMsg); err != nil {
		// If send fails, fire closed event immediately.
		c.fireClosedEvent(nil)
		return nil
	}

	// Wait for remote close acknowledgment (or context cancellation).
	select {
	case <-c.closeDone:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Wait for the request goroutine to finish processing remaining requests.
	select {
	case <-c.requestDone:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

// handleClose is called when a Close message is received from the remote side.
func (c *Channel) handleClose() {
	c.mu.Lock()
	c.remoteClosed = true
	wasLocallyClosed := c.localClosed

	// Cancel all pending requests.
	// These are buffered channels with capacity 1. The writes are safe because
	// both handleRequestResponse (which sends true/false) and handleClose (here)
	// are called exclusively from the single-threaded dispatch loop, so at most
	// one value is ever sent to each channel.
	for _, ch := range c.pendingRequests {
		ch <- false
	}
	c.pendingRequests = nil
	c.mu.Unlock()

	// Close the request channel so the request goroutine drains and exits.
	c.closeRequestsCh()

	if !wasLocallyClosed {
		// Remote initiated close. Send EOF + Close back.
		c.mu.Lock()
		c.localClosed = true
		c.mu.Unlock()

		_ = c.sendEof(context.Background())

		closeMsg := &messages.ChannelCloseMessage{
			RecipientChannel: c.RemoteChannelID,
		}
		_ = c.session.SendMessage(closeMsg)
	}

	// Signal close completion.
	select {
	case <-c.closeDone:
	default:
		close(c.closeDone)
	}

	c.fireClosedEvent(nil)
}

// handleSessionClose is called when the parent session closes.
func (c *Channel) handleSessionClose(err error) {
	c.mu.Lock()
	if c.disposed {
		c.mu.Unlock()
		return
	}
	c.localClosed = true
	c.remoteClosed = true

	// Cancel all pending requests.
	for _, ch := range c.pendingRequests {
		ch <- false
	}
	c.pendingRequests = nil
	c.mu.Unlock()

	// Close the request channel so the request goroutine drains and exits.
	c.closeRequestsCh()

	// Unblock any waiting goroutines.
	select {
	case <-c.closeDone:
	default:
		close(c.closeDone)
	}
	select {
	case <-c.sendEnabled:
	default:
		close(c.sendEnabled)
	}

	c.fireClosedEvent(err)
}

// fireClosedEvent fires the OnClosed callback exactly once.
func (c *Channel) fireClosedEvent(err error) {
	c.mu.Lock()
	if c.disposed {
		c.mu.Unlock()
		return
	}
	c.disposed = true
	onClosed := c.OnClosed
	exitStatus := c.exitStatus
	exitSignal := c.exitSignal
	errorMessage := c.errorMessage
	c.mu.Unlock()

	if onClosed != nil {
		onClosed(&ChannelClosedEventArgs{
			ExitStatus:   exitStatus,
			ExitSignal:   exitSignal,
			ErrorMessage: errorMessage,
			Err:          err,
		})
	}
}
