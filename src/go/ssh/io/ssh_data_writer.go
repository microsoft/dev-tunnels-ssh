// Copyright (c) Microsoft Corporation. All rights reserved.

package sshio

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// SSHDataWriter writes SSH-encoded data types to an in-memory buffer.
//
// All multi-byte integers are written in big-endian (network) byte order
// per the SSH protocol specification (RFC 4251).
type SSHDataWriter struct {
	buffer   []byte
	Position int
}

// NewSSHDataWriter creates a new SSHDataWriter with the given initial buffer.
func NewSSHDataWriter(buffer []byte) *SSHDataWriter {
	return &SSHDataWriter{buffer: buffer}
}

func (w *SSHDataWriter) ensureCapacity(capacity int) {
	if capacity <= len(w.buffer) {
		return
	}
	newLen := len(w.buffer) * 2
	if newLen < capacity {
		newLen = capacity
	}
	newBuf := make([]byte, newLen)
	copy(newBuf, w.buffer)
	w.buffer = newBuf
}

// WriteByte writes a single byte.
// Returns nil always; the error return satisfies the io.ByteWriter interface.
func (w *SSHDataWriter) WriteByte(c byte) error {
	w.ensureCapacity(w.Position + 1)
	w.buffer[w.Position] = c
	w.Position++
	return nil
}

// WriteBoolean writes a boolean as a single byte (0x00 for false, 0x01 for true).
func (w *SSHDataWriter) WriteBoolean(value bool) {
	w.ensureCapacity(w.Position + 1)
	if value {
		w.buffer[w.Position] = 1
	} else {
		w.buffer[w.Position] = 0
	}
	w.Position++
}

// WriteUInt32 writes a 32-bit unsigned integer in big-endian byte order.
func (w *SSHDataWriter) WriteUInt32(value uint32) {
	w.ensureCapacity(w.Position + 4)
	w.buffer[w.Position] = byte(value >> 24)
	w.buffer[w.Position+1] = byte(value >> 16)
	w.buffer[w.Position+2] = byte(value >> 8)
	w.buffer[w.Position+3] = byte(value)
	w.Position += 4
}

// WriteUInt64 writes a 64-bit unsigned integer in big-endian byte order.
func (w *SSHDataWriter) WriteUInt64(value uint64) {
	w.ensureCapacity(w.Position + 8)
	w.buffer[w.Position] = byte(value >> 56)
	w.buffer[w.Position+1] = byte(value >> 48)
	w.buffer[w.Position+2] = byte(value >> 40)
	w.buffer[w.Position+3] = byte(value >> 32)
	w.buffer[w.Position+4] = byte(value >> 24)
	w.buffer[w.Position+5] = byte(value >> 16)
	w.buffer[w.Position+6] = byte(value >> 8)
	w.buffer[w.Position+7] = byte(value)
	w.Position += 8
}

// WriteString writes a UTF-8 string with a uint32 length prefix.
func (w *SSHDataWriter) WriteString(value string) {
	w.WriteBinary([]byte(value))
}

// WriteBinary writes a byte slice with a uint32 length prefix.
func (w *SSHDataWriter) WriteBinary(data []byte) {
	w.ensureCapacity(w.Position + 4 + len(data))
	w.WriteUInt32(uint32(len(data)))
	copy(w.buffer[w.Position:], data)
	w.Position += len(data)
}

// Write writes raw bytes without a length prefix.
func (w *SSHDataWriter) Write(data []byte) {
	w.ensureCapacity(w.Position + len(data))
	copy(w.buffer[w.Position:], data)
	w.Position += len(data)
}

// WriteList writes a name-list as comma-separated strings with a uint32 length prefix.
// Per RFC 4251, a name-list is a comma-separated list of names encoded as a string.
func (w *SSHDataWriter) WriteList(list []string) {
	if len(list) == 0 {
		w.WriteString("")
	} else {
		w.WriteString(strings.Join(list, ","))
	}
}

// WriteBigInt writes a multi-precision integer in SSH mpint format (RFC 4251).
// The value is stored as a signed two's complement big-endian integer
// with a uint32 length prefix. Positive numbers with the high bit set
// are padded with a leading zero byte.
func (w *SSHDataWriter) WriteBigInt(value *big.Int) {
	data := BigIntToSSHBytes(value)
	if len(data) == 1 && data[0] == 0 {
		w.WriteUInt32(0)
	} else {
		w.WriteBinary(data)
	}
}

// WriteRandom writes count bytes of cryptographically random data.
func (w *SSHDataWriter) WriteRandom(count int) {
	w.ensureCapacity(w.Position + count)
	_, _ = rand.Read(w.buffer[w.Position : w.Position+count])
	w.Position += count
}

// ToBuffer returns a copy of the written data from position 0 to the current position.
func (w *SSHDataWriter) ToBuffer() []byte {
	result := make([]byte, w.Position)
	copy(result, w.buffer[:w.Position])
	return result
}

// Slice returns the written data as a sub-slice of the internal buffer.
// Unlike ToBuffer, this does not allocate. The returned slice aliases internal
// state and is valid only until the next write or position change.
func (w *SSHDataWriter) Slice() []byte {
	return w.buffer[:w.Position]
}

// WriteUInt32At writes a uint32 at a specific offset in the given buffer.
func WriteUInt32At(buffer []byte, offset int, value uint32) {
	buffer[offset] = byte(value >> 24)
	buffer[offset+1] = byte(value >> 16)
	buffer[offset+2] = byte(value >> 8)
	buffer[offset+3] = byte(value)
}
