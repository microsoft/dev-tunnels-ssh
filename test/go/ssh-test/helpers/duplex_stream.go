// Copyright (c) Microsoft Corporation. All rights reserved.

// Package helpers provides test infrastructure for SSH session testing.
package helpers

import (
	"io"
	"sync"
)

// DuplexStream implements io.ReadWriteCloser over a pair of io.Pipe connections
// with buffered async writes. Writing to one end of a duplex pair can be read
// from the other. Writes are buffered via a channel and goroutine pump to
// emulate the OS kernel write buffer that real transports (TCP, Unix sockets)
// provide, preventing deadlocks when both sides send on zero-buffered io.Pipe.
type DuplexStream struct {
	reader    *io.PipeReader
	writer    *io.PipeWriter
	wch       chan []byte
	wdone     chan struct{}
	closeCh   chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	onClose   func()
}

func newDuplexStream(r *io.PipeReader, w *io.PipeWriter) *DuplexStream {
	d := &DuplexStream{
		reader:  r,
		writer:  w,
		wch:     make(chan []byte, 256),
		wdone:   make(chan struct{}),
		closeCh: make(chan struct{}),
	}
	go d.writePump()
	return d
}

func (d *DuplexStream) writePump() {
	defer close(d.wdone)
	for {
		select {
		case data := <-d.wch:
			if _, err := d.writer.Write(data); err != nil {
				d.closeOnce.Do(func() { close(d.closeCh) })
				return
			}
		case <-d.closeCh:
			return
		}
	}
}

// Read reads from the stream. Blocks until data is available or the stream is closed.
func (d *DuplexStream) Read(p []byte) (int, error) {
	return d.reader.Read(p)
}

// Write writes to the stream. The data is buffered and will be readable from
// the paired stream. Returns immediately unless the buffer is full.
func (d *DuplexStream) Write(p []byte) (int, error) {
	select {
	case <-d.closeCh:
		return 0, io.ErrClosedPipe
	default:
	}
	data := make([]byte, len(p))
	copy(data, p)
	select {
	case d.wch <- data:
		return len(p), nil
	case <-d.closeCh:
		return 0, io.ErrClosedPipe
	}
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

	d.closeOnce.Do(func() { close(d.closeCh) })
	<-d.wdone

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

	stream1 = newDuplexStream(r2, w1) // reads from pipe B, writes to pipe A
	stream2 = newDuplexStream(r1, w2) // reads from pipe A, writes to pipe B

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
