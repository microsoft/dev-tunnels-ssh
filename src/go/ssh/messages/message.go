// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// SSH message type constants (RFC 4253, 4252, 4254).
const (
	MsgNumDisconnect              byte = 1
	MsgNumIgnore                  byte = 2
	MsgNumUnimplemented           byte = 3
	MsgNumDebug                   byte = 4
	MsgNumServiceRequest          byte = 5
	MsgNumServiceAccept           byte = 6
	MsgNumExtensionInfo           byte = 7
	MsgNumKeyExchangeInit         byte = 20
	MsgNumNewKeys                 byte = 21
	MsgNumKeyExchangeDhInit       byte = 30
	MsgNumKeyExchangeDhReply      byte = 31
	MsgNumAuthenticationRequest   byte = 50
	MsgNumAuthenticationFailure   byte = 51
	MsgNumAuthenticationSuccess   byte = 52
	MsgNumPublicKeyOk             byte = 60
	MsgNumAuthInfoRequest         byte = 60
	MsgNumAuthInfoResponse        byte = 61
	MsgNumSessionRequest          byte = 80
	MsgNumSessionRequestSuccess   byte = 81
	MsgNumSessionRequestFailure   byte = 82
	MsgNumChannelOpen             byte = 90
	MsgNumChannelOpenConfirmation byte = 91
	MsgNumChannelOpenFailure      byte = 92
	MsgNumChannelWindowAdjust     byte = 93
	MsgNumChannelData             byte = 94
	MsgNumChannelExtendedData     byte = 95
	MsgNumChannelEof              byte = 96
	MsgNumChannelClose            byte = 97
	MsgNumChannelRequest          byte = 98
	MsgNumChannelSuccess          byte = 99
	MsgNumChannelFailure          byte = 100
)

// Message is the interface for all SSH protocol messages.
type Message interface {
	// MessageType returns the SSH message type number.
	MessageType() byte

	// Read deserializes the message from the reader.
	// The reader should be positioned after the message type byte.
	Read(reader *sshio.SSHDataReader) error

	// Write serializes the message to the writer,
	// including the message type byte.
	Write(writer *sshio.SSHDataWriter) error

	// ToBuffer serializes the message to a byte slice.
	ToBuffer() []byte
}

// toBuffer is a helper to serialize any Message to a byte slice.
func toBuffer(m Message) []byte {
	w := sshio.NewSSHDataWriter(make([]byte, 0))
	_ = m.Write(w)
	return w.ToBuffer()
}

// ReadMessage reads a message from a byte buffer, consuming the
// message type byte and deserializing the fields.
func ReadMessage(m Message, data []byte) error {
	r := sshio.NewSSHDataReader(data)
	msgType, err := r.ReadByte()
	if err != nil {
		return err
	}
	if msgType != m.MessageType() {
		return &InvalidMessageTypeError{Expected: m.MessageType(), Actual: msgType}
	}
	return m.Read(r)
}

// InvalidMessageTypeError indicates a message type mismatch during deserialization.
type InvalidMessageTypeError struct {
	Expected byte
	Actual   byte
}

func (e *InvalidMessageTypeError) Error() string {
	return "invalid message type: expected " + byteToStr(e.Expected) +
		", got " + byteToStr(e.Actual)
}

func byteToStr(b byte) string {
	// Simple int-to-string without importing strconv
	if b == 0 {
		return "0"
	}
	digits := [3]byte{}
	i := 2
	for b > 0 {
		digits[i] = '0' + b%10
		b /= 10
		i--
	}
	return string(digits[i+1:])
}
