// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// Client is a convenience wrapper that manages SSH client sessions over TCP connections.
// It dials TCP connections, configures sockets for SSH, and tracks active sessions.
type Client struct {
	config *ssh.SessionConfig

	mu       sync.Mutex
	sessions []*ssh.ClientSession
	closed   bool
}

// NewClient creates a new TCP SSH client with the given session configuration.
// If config is nil, a default configuration is used.
func NewClient(config *ssh.SessionConfig) *Client {
	if config == nil {
		config = ssh.NewDefaultConfig()
	}
	return &Client{
		config: config,
	}
}

// OpenSession dials a TCP connection to the given host and port, then establishes
// an SSH client session over it. The returned session is connected and ready for
// authentication.
func (c *Client) OpenSession(ctx context.Context, host string, port int) (*ssh.ClientSession, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	conn, err := c.openConnection(ctx, host, port)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s:%d: %w", host, port, err)
	}

	session := ssh.NewClientSession(c.config)

	// Track session and remove it when closed.
	c.mu.Lock()
	c.sessions = append(c.sessions, session)
	c.mu.Unlock()

	session.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		c.removeSession(session)
	}

	if err := session.Connect(ctx, conn); err != nil {
		c.removeSession(session)
		conn.Close()
		return nil, fmt.Errorf("failed to establish SSH session: %w", err)
	}

	return session, nil
}

// ReconnectSession reconnects a previously disconnected client session over a new
// TCP connection to the given host and port.
func (c *Client) ReconnectSession(ctx context.Context, session *ssh.ClientSession, host string, port int) error {
	if session == nil {
		return fmt.Errorf("session is nil")
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	conn, err := c.openConnection(ctx, host, port)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", host, port, err)
	}

	if err := session.Reconnect(ctx, conn); err != nil {
		conn.Close()
		return err
	}

	return nil
}

// Sessions returns a snapshot of the currently active sessions.
func (c *Client) Sessions() []*ssh.ClientSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]*ssh.ClientSession, len(c.sessions))
	copy(result, c.sessions)
	return result
}

// Close closes all active sessions and marks the client as closed.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	sessions := make([]*ssh.ClientSession, len(c.sessions))
	copy(sessions, c.sessions)
	c.sessions = nil
	c.mu.Unlock()

	for _, s := range sessions {
		s.Close()
	}
	return nil
}

// openConnection dials a TCP connection and configures socket options for SSH.
func (c *Client) openConnection(ctx context.Context, host string, port int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	configureSocketForSSH(conn)
	return conn, nil
}

// removeSession removes a session from the tracked sessions list.
func (c *Client) removeSession(session *ssh.ClientSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, s := range c.sessions {
		if s == session {
			c.sessions = append(c.sessions[:i], c.sessions[i+1:]...)
			return
		}
	}
}
