// Copyright (c) Microsoft Corporation. All rights reserved.

// Package helpers provides test infrastructure for SSH session testing.
package helpers

import (
	"io"
	"sync"
)

// DuplexStream implements io.ReadWriteCloser over a pair of io.Pipe connections.
// Writing to one end of a duplex pair can be read from the other.
type DuplexStream struct {
	reader   *io.PipeReader
	writer   *io.PipeWriter
	mu       sync.Mutex
	closed   bool
	onClose  func()
}

// Read reads from the stream. Blocks until data is available or the stream is closed.
func (d *DuplexStream) Read(p []byte) (int, error) {
	return d.reader.Read(p)
}

// Write writes to the stream. The data will be readable from the paired stream.
func (d *DuplexStream) Write(p []byte) (int, error) {
	return d.writer.Write(p)
}

// Close closes both the read and write ends of the stream.
func (d *DuplexStream) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	onClose := d.onClose
	d.mu.Unlock()

	rErr := d.reader.Close()
	wErr := d.writer.Close()
	if onClose != nil {
		onClose()
	}
	if rErr != nil {
		return rErr
	}
	return wErr
}

// IsClosed returns true if the stream has been closed.
func (d *DuplexStream) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

// CreateDuplexStreams creates a pair of connected io.ReadWriteCloser streams.
// Writing to stream1 can be read from stream2 and vice versa.
// Closing one stream will cause reads on the other to return io.EOF.
func CreateDuplexStreams() (stream1 *DuplexStream, stream2 *DuplexStream) {
	// Pipe A: stream1 writes -> stream2 reads
	r1, w1 := io.Pipe()
	// Pipe B: stream2 writes -> stream1 reads
	r2, w2 := io.Pipe()

	stream1 = &DuplexStream{
		reader: r2, // reads from pipe B
		writer: w1, // writes to pipe A
	}
	stream2 = &DuplexStream{
		reader: r1, // reads from pipe A
		writer: w2, // writes to pipe B
	}

	// When one stream closes, close the other side's pipes to unblock reads.
	stream1.onClose = func() {
		r1.Close()
		w2.Close()
	}
	stream2.onClose = func() {
		r2.Close()
		w1.Close()
	}

	return stream1, stream2
}
