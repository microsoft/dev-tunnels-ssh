// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"io"
	"sync"
)

// Compile-time check that Stream implements io.ReadWriteCloser.
var _ io.ReadWriteCloser = (*Stream)(nil)

// Stream wraps an SSH Channel as an io.ReadWriteCloser.
// This allows using SSH channels with any Go library that expects a stream.
//
// Stream does not support more than one concurrent reader or more than
// one concurrent writer.
type Stream struct {
	channel *Channel

	mu         sync.Mutex
	readQueue  [][]byte // incoming data buffers
	readReady  chan struct{} // signaled when data or close arrives
	readBuf    []byte   // current buffer being consumed
	readOffset int      // offset into current read buffer
	closed     bool
	closeErr   error // error from channel closure (nil for normal close)
}

// NewStream creates a new Stream wrapping the given channel.
// The stream implements io.ReadWriteCloser.
func NewStream(channel *Channel) *Stream {
	s := &Stream{
		channel:   channel,
		readReady: make(chan struct{}),
	}

	// Set up data received handler on the channel.
	channel.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)

		s.mu.Lock()
		s.readQueue = append(s.readQueue, buf)
		old := s.readReady
		s.readReady = make(chan struct{})
		s.mu.Unlock()

		// Close-based signaling: closing the old channel wakes any
		// goroutine blocked on it. This avoids the signal-loss race
		// inherent in buffered(1) channels where multiple dispatches
		// can coalesce into a single notification.
		close(old)
	})

	// Set up close handler to unblock readers (thread-safe).
	channel.mu.Lock()
	prevOnClosed := channel.OnClosed
	channel.mu.Unlock()
	channel.SetClosedHandler(func(args *ChannelClosedEventArgs) {
		s.mu.Lock()
		s.closed = true
		if args != nil && args.Err != nil {
			s.closeErr = args.Err
		}
		old := s.readReady
		s.readReady = make(chan struct{})
		s.mu.Unlock()

		close(old)

		// Call previous handler if any.
		if prevOnClosed != nil {
			prevOnClosed(args)
		}
	})

	return s
}

// Read reads data from the channel into p. It blocks until data is available,
// the channel is closed, or an error occurs.
// Read implements io.Reader.
func (s *Stream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()

		// Check if we have data in the current buffer.
		if len(s.readBuf) > s.readOffset {
			n := copy(p, s.readBuf[s.readOffset:])
			s.readOffset += n

			// If we've consumed the entire buffer, clear it.
			if s.readOffset >= len(s.readBuf) {
				s.readBuf = nil
				s.readOffset = 0
			}

			s.mu.Unlock()
			// Adjust window incrementally after each read. The channel's
			// AdjustWindow uses a 50% threshold to batch actual window
			// adjust messages, so calling it per-read is efficient.
			s.channel.AdjustWindow(uint32(n))
			return n, nil
		}

		// Try to dequeue from the read queue.
		if len(s.readQueue) > 0 {
			s.readBuf = s.readQueue[0]
			s.readQueue = s.readQueue[1:]
			s.readOffset = 0
			s.mu.Unlock()
			continue // loop back to consume from readBuf
		}

		// No data available. Check if closed.
		if s.closed {
			err := s.closeErr
			s.mu.Unlock()
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		}

		// Capture the current readReady channel while holding the lock.
		// The close-and-replace pattern guarantees that when new data
		// arrives (or the channel closes), the old channel is closed,
		// waking any goroutine blocked on it.
		ch := s.readReady
		s.mu.Unlock()

		// Wait for data or close.
		<-ch
	}
}

// Write sends data on the channel.
// Write implements io.Writer.
func (s *Stream) Write(p []byte) (int, error) {
	return s.WriteContext(context.Background(), p)
}

// WriteContext sends data on the channel, respecting the provided context for
// cancellation and timeouts.
func (s *Stream) WriteContext(ctx context.Context, p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	s.mu.Unlock()

	if err := s.channel.Send(ctx, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the underlying channel.
// Close implements io.Closer.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	return s.channel.Close()
}

// Channel returns the underlying SSH channel.
func (s *Stream) Channel() *Channel {
	return s.channel
}
