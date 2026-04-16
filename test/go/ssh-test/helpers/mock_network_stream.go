// Copyright (c) Microsoft Corporation. All rights reserved.

package helpers

import (
	"errors"
	"io"
	"sync"
)

// ErrMockDisconnect is the default error used for mock disconnections.
var ErrMockDisconnect = errors.New("mock network disconnection")

// MockNetworkStream wraps an io.ReadWriteCloser and simulates network failures.
// It intercepts Read and Write calls, allowing tests to inject disconnection
// errors and optionally drop a specified number of bytes before disconnecting.
type MockNetworkStream struct {
	underlying io.ReadWriteCloser

	mu            sync.Mutex
	disconnected  chan struct{}
	disconnectErr error
	dropBytes     int
	bytesSent     int
	closed        bool
}

// NewMockNetworkStream creates a MockNetworkStream wrapping the given stream.
func NewMockNetworkStream(underlying io.ReadWriteCloser) *MockNetworkStream {
	return &MockNetworkStream{
		underlying:   underlying,
		disconnected: make(chan struct{}),
	}
}

// Read reads from the underlying stream. Returns the disconnect error if
// MockDisconnect has been called.
func (m *MockNetworkStream) Read(p []byte) (int, error) {
	// Check if already disconnected.
	select {
	case <-m.disconnected:
		return 0, m.getDisconnectErr()
	default:
	}

	// Read from underlying, but race against disconnect.
	type readResult struct {
		n   int
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		n, err := m.underlying.Read(p)
		ch <- readResult{n, err}
	}()

	select {
	case result := <-ch:
		return result.n, result.err
	case <-m.disconnected:
		return 0, m.getDisconnectErr()
	}
}

// Write writes to the underlying stream. If MockDisconnectWithDrop was called,
// drops the specified number of bytes before returning the disconnect error.
// Returns the disconnect error immediately if MockDisconnect was called.
func (m *MockNetworkStream) Write(p []byte) (int, error) {
	select {
	case <-m.disconnected:
		m.mu.Lock()
		drop := m.dropBytes
		sent := m.bytesSent
		m.mu.Unlock()
		if drop > 0 && sent < drop {
			// Still need to drop some bytes before returning error.
			remaining := drop - sent
			if len(p) <= remaining {
				m.mu.Lock()
				m.bytesSent += len(p)
				m.mu.Unlock()
				return len(p), nil
			}
			m.mu.Lock()
			m.bytesSent += remaining
			m.mu.Unlock()
			return remaining, m.getDisconnectErr()
		}
		return 0, m.getDisconnectErr()
	default:
	}

	n, err := m.underlying.Write(p)
	return n, err
}

// Close closes the mock stream and the underlying stream.
func (m *MockNetworkStream) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	// Signal disconnection if not already done.
	select {
	case <-m.disconnected:
	default:
		m.disconnectErr = io.ErrClosedPipe
		close(m.disconnected)
	}

	return m.underlying.Close()
}

// MockDisconnect simulates a network disconnection with the given error.
// All pending and future Read/Write calls will return the error.
func (m *MockNetworkStream) MockDisconnect(err error) {
	if err == nil {
		err = ErrMockDisconnect
	}
	m.mu.Lock()
	m.disconnectErr = err
	m.mu.Unlock()

	select {
	case <-m.disconnected:
	default:
		close(m.disconnected)
	}

	// Close the underlying stream to unblock any pending reads.
	m.underlying.Close()
}

// MockDisconnectWithDrop simulates a network disconnection that drops a specified
// number of bytes before the error manifests. This is used to test reconnection
// scenarios where some bytes were sent but not received by the remote end.
func (m *MockNetworkStream) MockDisconnectWithDrop(err error, dropBytes int) {
	if err == nil {
		err = ErrMockDisconnect
	}
	m.mu.Lock()
	m.disconnectErr = err
	m.dropBytes = dropBytes
	m.bytesSent = 0
	m.mu.Unlock()

	select {
	case <-m.disconnected:
	default:
		close(m.disconnected)
	}

	// Close the underlying stream to unblock any pending reads.
	m.underlying.Close()
}

// IsClosed returns true if the stream has been closed or disconnected.
func (m *MockNetworkStream) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// IsDisconnected returns true if MockDisconnect or MockDisconnectWithDrop has been called.
func (m *MockNetworkStream) IsDisconnected() bool {
	select {
	case <-m.disconnected:
		return true
	default:
		return false
	}
}

func (m *MockNetworkStream) getDisconnectErr() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.disconnectErr != nil {
		return m.disconnectErr
	}
	return ErrMockDisconnect
}

