// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"io"
	"sync"
)

// MultiChannelStream provides lightweight channel multiplexing over a single
// transport stream without encryption. It is suitable for scenarios where the
// transport is already secure (e.g., TLS).
//
// MultiChannelStream uses an underlying SSH session configured with "none"
// algorithms (no encryption, no HMAC, no key exchange) to provide channel
// multiplexing, flow control, and message framing without cryptographic overhead.
type MultiChannelStream struct {
	// OnChannelOpening is called when a channel open request is received.
	OnChannelOpening func(*ChannelOpeningEventArgs)

	// OnClosed is called when the stream is closed.
	OnClosed func(*SessionClosedEventArgs)

	// ChannelMaxWindowSize is the maximum window size for channels.
	// Zero uses the default (1 MB).
	ChannelMaxWindowSize uint32

	transportStream io.ReadWriteCloser
	session         *Session
	isClient        bool

	mu        sync.Mutex
	connected bool
	closed    bool
	connectMu sync.Mutex // serializes connect calls
}

// NewMultiChannelStream creates a new MultiChannelStream wrapping the given transport stream.
// The isClient parameter indicates whether this end acts as the SSH client (true) or server (false).
func NewMultiChannelStream(transportStream io.ReadWriteCloser, isClient bool) *MultiChannelStream {
	config := NewNoSecurityConfig()

	var session *Session
	if isClient {
		cs := NewClientSession(config)
		session = &cs.Session
	} else {
		ss := NewServerSession(config)
		session = &ss.Session
	}

	mcs := &MultiChannelStream{
		transportStream: transportStream,
		session:         session,
		isClient:        isClient,
	}

	// Forward session events.
	session.OnChannelOpening = func(args *ChannelOpeningEventArgs) {
		if mcs.OnChannelOpening != nil {
			mcs.OnChannelOpening(args)
		}
	}

	session.OnClosed = func(args *SessionClosedEventArgs) {
		mcs.mu.Lock()
		mcs.closed = true
		mcs.mu.Unlock()

		if mcs.OnClosed != nil {
			mcs.OnClosed(args)
		}
	}

	return mcs
}

// Session returns the underlying SSH session.
func (mcs *MultiChannelStream) Session() *Session {
	return mcs.session
}

// IsClosed returns true if the stream has been closed.
func (mcs *MultiChannelStream) IsClosed() bool {
	mcs.mu.Lock()
	defer mcs.mu.Unlock()
	return mcs.closed
}

// Connect establishes the multiplexed connection by performing SSH version
// exchange and key exchange (with "none" algorithms). This method is
// idempotent — calling it multiple times returns immediately after the first
// successful connection.
func (mcs *MultiChannelStream) Connect(ctx context.Context) error {
	mcs.connectMu.Lock()
	defer mcs.connectMu.Unlock()

	mcs.mu.Lock()
	if mcs.connected {
		mcs.mu.Unlock()
		return nil
	}
	if mcs.closed {
		mcs.mu.Unlock()
		return ErrSessionClosed
	}
	mcs.mu.Unlock()

	// Apply channel window size to session config before connecting.
	if mcs.ChannelMaxWindowSize > 0 {
		mcs.session.Config.MaxChannelWindowSize = mcs.ChannelMaxWindowSize
	}

	if err := mcs.session.Connect(ctx, mcs.transportStream); err != nil {
		return err
	}

	mcs.mu.Lock()
	mcs.connected = true
	mcs.mu.Unlock()

	return nil
}

// ConnectAndRunUntilClosed connects and then blocks until the session is
// closed or the context is cancelled. This is useful for server-side code
// that needs to process channels until the connection ends.
func (mcs *MultiChannelStream) ConnectAndRunUntilClosed(ctx context.Context) error {
	if err := mcs.Connect(ctx); err != nil {
		return err
	}

	// Wait for session closure or context cancellation.
	select {
	case <-mcs.session.done:
		return nil
	case <-ctx.Done():
		mcs.Close()
		return ctx.Err()
	}
}

// OpenChannel opens a new channel with the given channel type.
// If channelType is empty, "session" is used as the default.
func (mcs *MultiChannelStream) OpenChannel(ctx context.Context, channelType string) (*Channel, error) {
	if err := mcs.Connect(ctx); err != nil {
		return nil, err
	}

	if channelType == "" {
		channelType = "session"
	}

	return mcs.session.OpenChannelWithType(ctx, channelType)
}

// AcceptChannel waits for and accepts an incoming channel with the given type.
// If channelType is empty, any channel type is accepted.
func (mcs *MultiChannelStream) AcceptChannel(ctx context.Context, channelType string) (*Channel, error) {
	if err := mcs.Connect(ctx); err != nil {
		return nil, err
	}

	if channelType == "" {
		return mcs.session.AcceptChannel(ctx)
	}
	return mcs.session.AcceptChannelWithType(ctx, channelType)
}

// OpenStream opens a new channel and wraps it as an io.ReadWriteCloser.
func (mcs *MultiChannelStream) OpenStream(ctx context.Context, channelType string) (*Stream, error) {
	ch, err := mcs.OpenChannel(ctx, channelType)
	if err != nil {
		return nil, err
	}
	return NewStream(ch), nil
}

// AcceptStream waits for an incoming channel and wraps it as an io.ReadWriteCloser.
func (mcs *MultiChannelStream) AcceptStream(ctx context.Context, channelType string) (*Stream, error) {
	ch, err := mcs.AcceptChannel(ctx, channelType)
	if err != nil {
		return nil, err
	}
	return NewStream(ch), nil
}

// Close closes the underlying session and transport stream.
func (mcs *MultiChannelStream) Close() error {
	mcs.mu.Lock()
	if mcs.closed {
		mcs.mu.Unlock()
		return nil
	}
	mcs.closed = true
	mcs.mu.Unlock()

	// Close the session (sends disconnect, closes channels).
	mcs.session.Close()

	// Close the transport stream explicitly.
	return mcs.transportStream.Close()
}
