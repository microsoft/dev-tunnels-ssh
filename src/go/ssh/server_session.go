// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

// ServerSession is an SSH server session that accepts client connections.
type ServerSession struct {
	Session
	Credentials *ServerCredentials

	// OnClientAuthenticated is called when a client successfully authenticates.
	OnClientAuthenticated func()

	// OnReconnected is called after a client successfully reconnects to this session.
	OnReconnected func()

	// ReconnectableSessions is a shared collection of disconnected sessions
	// awaiting reconnection. Must be set before connecting if reconnection
	// support is desired. Multiple ServerSession instances can share the same
	// collection to enable reconnection across sessions.
	ReconnectableSessions *ReconnectableSessions
}

// SetClientAuthenticatedHandler sets the OnClientAuthenticated callback in a thread-safe manner.
// Use this method instead of direct field assignment when the session is already connected,
// to avoid data races with the dispatch goroutine.
func (ss *ServerSession) SetClientAuthenticatedHandler(handler func()) {
	ss.mu.Lock()
	ss.OnClientAuthenticated = handler
	ss.mu.Unlock()
}

// SetReconnectedHandler sets the OnReconnected callback in a thread-safe manner.
// Use this method instead of direct field assignment when the session is already connected,
// to avoid data races with the dispatch goroutine.
func (ss *ServerSession) SetReconnectedHandler(handler func()) {
	ss.mu.Lock()
	ss.OnReconnected = handler
	ss.mu.Unlock()
}

// NewServerSession creates a new SSH server session with the given configuration.
// If config is nil, a no-security configuration is used.
func NewServerSession(config *SessionConfig) *ServerSession {
	if config == nil {
		config = NewNoSecurityConfig()
	}
	ss := &ServerSession{
		Session: Session{
			Config:   config,
			isClient: false,
		},
	}
	ss.Session.serverRef = ss
	ss.sessionMetrics.initMetrics()
	return ss
}
