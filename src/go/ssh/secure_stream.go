// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// Compile-time check that SecureStream implements io.ReadWriteCloser.
var _ io.ReadWriteCloser = (*SecureStream)(nil)

// SecureStream establishes an end-to-end encrypted, two-way authenticated data
// stream over an underlying transport stream, using the SSH protocol but
// providing a simplified interface that is limited to a single duplex stream
// (channel).
//
// This type is a complement to MultiChannelStream, which provides only the
// channel-multiplexing functions of SSH without encryption.
//
// To establish a secure connection, the two sides first establish an insecure
// transport stream over a pipe, socket, or anything else. Then they encrypt and
// authenticate the connection before beginning to send and receive data.
type SecureStream struct {
	// OnAuthenticating is called when authentication credentials need to be
	// verified. For a client, it is called to verify the server host key. For
	// a server, it is called to verify the client's credentials.
	//
	// The handler must set AuthenticationResult to a non-nil value to accept.
	OnAuthenticating func(*AuthenticatingEventArgs)

	// OnDisconnected is called when the session disconnects while reconnection
	// is enabled. After this fires, the client application should call
	// Reconnect() with a new transport stream. The server handles reconnections
	// automatically during the session handshake.
	OnDisconnected func()

	// OnClosed is called when the underlying SSH session is closed.
	OnClosed func(*SessionClosedEventArgs)

	transportStream   io.ReadWriteCloser
	clientSession     *ClientSession
	serverSession     *ServerSession
	session           *Session
	clientCredentials *ClientCredentials
	serverCredentials *ServerCredentials
	stream            *Stream

	mu     sync.Mutex
	closed bool
}

// NewSecureStreamClient creates a SecureStream over an underlying transport
// stream using client credentials. Set enableReconnect to true to enable
// SSH session reconnection.
func NewSecureStreamClient(
	transportStream io.ReadWriteCloser,
	clientCredentials *ClientCredentials,
	enableReconnect bool,
) *SecureStream {
	var config *SessionConfig
	if enableReconnect {
		config = NewDefaultConfigWithReconnect()
	} else {
		config = NewDefaultConfig()
	}

	cs := NewClientSession(config)

	ss := &SecureStream{
		transportStream:   transportStream,
		clientSession:     cs,
		session:           &cs.Session,
		clientCredentials: clientCredentials,
	}

	cs.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		if ss.OnAuthenticating != nil {
			ss.OnAuthenticating(args)
		}
	}

	cs.OnDisconnected = func() {
		if ss.OnDisconnected != nil {
			ss.OnDisconnected()
		}
	}

	cs.OnClosed = func(args *SessionClosedEventArgs) {
		ss.mu.Lock()
		ss.closed = true
		ss.mu.Unlock()

		if ss.OnClosed != nil {
			ss.OnClosed(args)
		}
	}

	return ss
}

// NewSecureStreamServer creates a SecureStream over an underlying transport
// stream using server credentials. Pass a non-nil reconnectableSessions
// collection to enable reconnection support.
func NewSecureStreamServer(
	transportStream io.ReadWriteCloser,
	serverCredentials *ServerCredentials,
	reconnectableSessions *ReconnectableSessions,
) *SecureStream {
	var config *SessionConfig
	if reconnectableSessions != nil {
		config = NewDefaultConfigWithReconnect()
	} else {
		config = NewDefaultConfig()
	}

	svr := NewServerSession(config)
	svr.Credentials = serverCredentials
	if reconnectableSessions != nil {
		svr.ReconnectableSessions = reconnectableSessions
	}

	ss := &SecureStream{
		transportStream:   transportStream,
		serverSession:     svr,
		session:           &svr.Session,
		serverCredentials: serverCredentials,
	}

	svr.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		if ss.OnAuthenticating != nil {
			ss.OnAuthenticating(args)
		}
	}

	svr.OnDisconnected = func() {
		if ss.OnDisconnected != nil {
			ss.OnDisconnected()
		}
	}

	svr.OnClosed = func(args *SessionClosedEventArgs) {
		ss.mu.Lock()
		ss.closed = true
		ss.mu.Unlock()

		if ss.OnClosed != nil {
			ss.OnClosed(args)
		}
	}

	return ss
}

// Session returns the underlying SSH session.
func (ss *SecureStream) Session() *Session {
	return ss.session
}

// IsClosed returns true if the secure stream has been closed.
func (ss *SecureStream) IsClosed() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.closed || ss.session.IsClosed()
}

// Connect initiates the SSH session over the transport stream. It performs
// version exchange, key exchange, authentication, and opens a channel.
// On success, Read and Write can be used to exchange data.
func (ss *SecureStream) Connect(ctx context.Context) error {
	if ss.OnAuthenticating == nil {
		return fmt.Errorf("an OnAuthenticating handler must be registered before connecting")
	}

	if err := ss.session.Connect(ctx, ss.transportStream); err != nil {
		return err
	}

	var channel *Channel

	if ss.clientSession != nil {
		// Client: authenticate (server host key + client credentials), then open channel.
		ok, err := ss.clientSession.Authenticate(ctx, ss.clientCredentials)
		if err != nil {
			ss.session.CloseWithReason(ctx, messages.DisconnectProtocolError, err.Error())
			return &ConnectionError{
				Reason: messages.DisconnectProtocolError,
				Msg:    "authentication failed: " + err.Error(),
				Err:    err,
			}
		}
		if !ok {
			if ss.session.IsClosed() {
				// Server host key verification failed — Authenticate already closed
				// the session with DisconnectHostKeyNotVerifiable.
				return &ConnectionError{
					Reason: messages.DisconnectHostKeyNotVerifiable,
					Msg:    "authentication failed: server host key not verified",
				}
			}
			// Client credentials were rejected by the server.
			ss.session.CloseWithReason(
				ctx, messages.DisconnectNoMoreAuthMethodsAvailable, "authentication failed")
			return &ConnectionError{
				Reason: messages.DisconnectNoMoreAuthMethodsAvailable,
				Msg:    "authentication failed",
			}
		}

		ch, err := ss.session.OpenChannel(ctx)
		if err != nil {
			return err
		}
		channel = ch
	} else {
		// Server: accept channel (auth is handled automatically by dispatch loop).
		ch, err := ss.session.AcceptChannel(ctx)
		if err != nil {
			return err
		}
		channel = ch
	}

	ss.stream = NewStream(channel)

	// When the channel closes, close the secure stream.
	channel.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		ss.Close()
	})

	return nil
}

// Reconnect reconnects a disconnected client session over a new transport
// stream. The new stream must connect to the same server (same host key).
// This method applies only to client-side secure streams.
func (ss *SecureStream) Reconnect(ctx context.Context, newTransportStream io.ReadWriteCloser) error {
	if ss.clientSession == nil {
		return fmt.Errorf("cannot reconnect SecureStream server")
	}

	ss.mu.Lock()
	ss.transportStream = newTransportStream
	ss.mu.Unlock()

	return ss.clientSession.Reconnect(ctx, newTransportStream)
}

// Read reads data from the secure stream. It blocks until data is available,
// the stream is closed, or an error occurs.
// Read implements io.Reader.
func (ss *SecureStream) Read(p []byte) (int, error) {
	if ss.stream == nil {
		return 0, fmt.Errorf("stream is not connected")
	}
	return ss.stream.Read(p)
}

// Write sends data on the secure stream.
// Write implements io.Writer.
func (ss *SecureStream) Write(p []byte) (int, error) {
	if ss.stream == nil {
		return 0, fmt.Errorf("stream is not connected")
	}
	return ss.stream.Write(p)
}

// Close closes the underlying SSH session and transport stream.
// Close implements io.Closer.
func (ss *SecureStream) Close() error {
	ss.mu.Lock()
	if ss.closed {
		ss.mu.Unlock()
		return nil
	}
	ss.closed = true
	ss.mu.Unlock()

	// Close the session (sends disconnect, closes channels).
	ss.session.Close()

	// Close the transport stream.
	return ss.transportStream.Close()
}
