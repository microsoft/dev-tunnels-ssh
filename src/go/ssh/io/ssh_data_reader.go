// Copyright (c) Microsoft Corporation. All rights reserved.

package sshio

import (
	"fmt"
	"math/big"
	"strings"
)

// SSHDataReader reads SSH-encoded data types from an in-memory buffer.
//
// All multi-byte integers are read in big-endian (network) byte order
// per the SSH protocol specification (RFC 4251).
type SSHDataReader struct {
	buffer   []byte
	Position int
}

// NewSSHDataReader creates a new SSHDataReader over the given buffer.
func NewSSHDataReader(buffer []byte) *SSHDataReader {
	return &SSHDataReader{buffer: buffer}
}

// Buffer returns the underlying byte buffer.
func (r *SSHDataReader) Buffer() []byte {
	return r.buffer
}

// Available returns the number of unread bytes remaining in the buffer.
func (r *SSHDataReader) Available() int {
	avail := len(r.buffer) - r.Position
	if avail < 0 {
		return 0
	}
	return avail
}

// ReadByte reads a single byte.
func (r *SSHDataReader) ReadByte() (byte, error) {
	if r.Available() < 1 {
		return 0, fmt.Errorf("attempted to read past end of buffer")
	}
	v := r.buffer[r.Position]
	r.Position++
	return v, nil
}

// ReadBoolean reads a boolean from a single byte (any non-zero value is true).
func (r *SSHDataReader) ReadBoolean() (bool, error) {
	b, err := r.ReadByte()
	if err != nil {
		return false, err
	}
	return b != 0, nil
}

// ReadUInt32 reads a 32-bit unsigned integer in big-endian byte order.
func (r *SSHDataReader) ReadUInt32() (uint32, error) {
	if r.Available() < 4 {
		return 0, fmt.Errorf("attempted to read past end of buffer")
	}
	v := uint32(r.buffer[r.Position])<<24 |
		uint32(r.buffer[r.Position+1])<<16 |
		uint32(r.buffer[r.Position+2])<<8 |
		uint32(r.buffer[r.Position+3])
	r.Position += 4
	return v, nil
}

// ReadUInt64 reads a 64-bit unsigned integer in big-endian byte order.
func (r *SSHDataReader) ReadUInt64() (uint64, error) {
	if r.Available() < 8 {
		return 0, fmt.Errorf("attempted to read past end of buffer")
	}
	v := uint64(r.buffer[r.Position])<<56 |
		uint64(r.buffer[r.Position+1])<<48 |
		uint64(r.buffer[r.Position+2])<<40 |
		uint64(r.buffer[r.Position+3])<<32 |
		uint64(r.buffer[r.Position+4])<<24 |
		uint64(r.buffer[r.Position+5])<<16 |
		uint64(r.buffer[r.Position+6])<<8 |
		uint64(r.buffer[r.Position+7])
	r.Position += 8
	return v, nil
}

// ReadString reads a UTF-8 string with a uint32 length prefix.
func (r *SSHDataReader) ReadString() (string, error) {
	data, err := r.ReadBinary()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ReadBinary reads a byte slice with a uint32 length prefix.
func (r *SSHDataReader) ReadBinary() ([]byte, error) {
	length, err := r.ReadUInt32()
	if err != nil {
		return nil, err
	}
	return r.ReadBytes(int(length))
}

// ReadBytes reads exactly length bytes from the buffer.
func (r *SSHDataReader) ReadBytes(length int) ([]byte, error) {
	if r.Available() < length {
		return nil, fmt.Errorf("attempted to read past end of buffer")
	}
	data := r.buffer[r.Position : r.Position+length]
	r.Position += length
	return data, nil
}

// ReadList reads a name-list: a comma-separated string with a uint32 length prefix.
// Returns an empty slice for an empty name-list.
func (r *SSHDataReader) ReadList() ([]string, error) {
	s, err := r.ReadString()
	if err != nil {
		return nil, err
	}
	if s == "" {
		return []string{}, nil
	}
	return strings.Split(s, ","), nil
}

// ReadBigInt reads a multi-precision integer in SSH mpint format (RFC 4251).
// The value is stored as a signed two's complement big-endian integer
// with a uint32 length prefix.
func (r *SSHDataReader) ReadBigInt() (*big.Int, error) {
	data, err := r.ReadBinary()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return new(big.Int), nil
	}
	return SSHBytesToBigInt(data), nil
}
