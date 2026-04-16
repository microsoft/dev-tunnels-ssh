// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// Server is a convenience wrapper that listens for incoming TCP connections and
// creates SSH server sessions for each one.
type Server struct {
	config *ssh.SessionConfig

	// Credentials sets the host keys for the server.
	// Must be set before calling AcceptSessions.
	Credentials *ssh.ServerCredentials

	// OnSessionOpened is called when a new session is created from an incoming
	// TCP connection. The session is connected but not yet authenticated.
	OnSessionOpened func(*ssh.ServerSession)

	// OnSessionAuthenticating is called when a client sends authentication credentials.
	// Set this to define authentication policy for all sessions.
	OnSessionAuthenticating func(*ssh.AuthenticatingEventArgs)

	// OnSessionChannelOpening is called when a channel open request is received.
	OnSessionChannelOpening func(*ssh.ChannelOpeningEventArgs)

	// OnSessionRequest is called when a session request is received.
	OnSessionRequest func(*ssh.RequestEventArgs)

	// reconnectableSessions is the shared collection of disconnected sessions
	// awaiting reconnection. It is non-nil when the config includes reconnect extensions.
	reconnectableSessions *ssh.ReconnectableSessions

	mu       sync.Mutex
	sessions []*ssh.ServerSession
	listener net.Listener
	closed   bool
}

// NewServer creates a new TCP SSH server with the given session configuration.
// If config is nil, a default configuration is used.
func NewServer(config *ssh.SessionConfig) *Server {
	if config == nil {
		config = ssh.NewDefaultConfig()
	}

	s := &Server{
		config: config,
	}

	// If reconnect extension is enabled, create a shared reconnectable sessions collection.
	for _, ext := range config.ProtocolExtensions {
		if ext == ssh.ExtensionSessionReconnect {
			s.reconnectableSessions = ssh.NewReconnectableSessions()
			break
		}
	}

	return s
}

// AcceptSessions starts listening on the given port and address, creating a new
// SSH server session for each incoming TCP connection. This method blocks until
// the context is cancelled or Close() is called.
//
// If address is empty, it listens on all interfaces.
func (s *Server) AcceptSessions(ctx context.Context, port int, address string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("server is closed")
	}
	s.mu.Unlock()

	listenAddr := fmt.Sprintf("%s:%d", address, port)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	// Close the listener when context is cancelled.
	// The acceptDone channel ensures this goroutine exits when the accept loop
	// finishes (e.g., Close() called without context cancellation).
	acceptDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
		case <-acceptDone:
		}
	}()
	defer close(acceptDone)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Check if we were closed intentionally.
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			// Check if context was cancelled.
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			// Transient accept error — continue.
			continue
		}

		go s.acceptSession(ctx, conn)
	}
}

// ListenPort returns the port the server is actually listening on.
// This is useful when port 0 was specified (dynamic allocation).
// Returns 0 if the server is not listening.
func (s *Server) ListenPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return 0
	}
	if addr, ok := s.listener.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}

// Sessions returns a snapshot of the currently active sessions.
func (s *Server) Sessions() []*ssh.ServerSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*ssh.ServerSession, len(s.sessions))
	copy(result, s.sessions)
	return result
}

// Close stops the listener and closes all active sessions.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.listener
	sessions := make([]*ssh.ServerSession, len(s.sessions))
	copy(sessions, s.sessions)
	s.sessions = nil
	s.mu.Unlock()

	if ln != nil {
		ln.Close()
	}

	for _, ss := range sessions {
		ss.Close()
	}
	return nil
}

// acceptSession handles a new incoming TCP connection by creating and connecting
// a server session.
func (s *Server) acceptSession(ctx context.Context, conn net.Conn) {
	configureSocketForSSH(conn)

	session := ssh.NewServerSession(s.config)
	session.Credentials = s.Credentials

	// Wire up server-level event handlers.
	if s.OnSessionAuthenticating != nil {
		session.OnAuthenticating = s.OnSessionAuthenticating
	}
	if s.OnSessionChannelOpening != nil {
		session.OnChannelOpening = s.OnSessionChannelOpening
	}
	if s.OnSessionRequest != nil {
		session.OnRequest = s.OnSessionRequest
	}

	// Set up reconnectable sessions if enabled.
	if s.reconnectableSessions != nil {
		session.ReconnectableSessions = s.reconnectableSessions
	}

	// Track the session.
	s.mu.Lock()
	s.sessions = append(s.sessions, session)
	s.mu.Unlock()

	// Remove session when closed.
	session.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		s.removeSession(session)
	}

	// Fire the session opened callback before connecting.
	if s.OnSessionOpened != nil {
		s.OnSessionOpened(session)
	}

	// Connect the session (version exchange + key exchange).
	if err := session.Connect(ctx, conn); err != nil {
		s.removeSession(session)
		conn.Close()
	} else if s.reconnectableSessions != nil {
		// Add the connected session to the reconnectable collection so it can
		// be found when a reconnect request arrives on a subsequent connection.
		s.reconnectableSessions.Add(session)
	}
}

// removeSession removes a session from the tracked sessions list.
func (s *Server) removeSession(session *ssh.ServerSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ss := range s.sessions {
		if ss == session {
			s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
			return
		}
	}
}
