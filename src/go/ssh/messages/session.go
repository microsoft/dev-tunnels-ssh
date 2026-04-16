// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// SessionRequestMessage represents SSH_MSG_GLOBAL_REQUEST (type 80).
type SessionRequestMessage struct {
	RequestType string
	WantReply   bool
}

func (m *SessionRequestMessage) MessageType() byte { return MsgNumSessionRequest }

func (m *SessionRequestMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RequestType, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.WantReply, err = reader.ReadBoolean()
	return err
}

func (m *SessionRequestMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.RequestType)
	writer.WriteBoolean(m.WantReply)
	return nil
}

func (m *SessionRequestMessage) ToBuffer() []byte { return toBuffer(m) }

// SessionRequestSuccessMessage represents SSH_MSG_REQUEST_SUCCESS (type 81).
type SessionRequestSuccessMessage struct{}

func (m *SessionRequestSuccessMessage) MessageType() byte { return MsgNumSessionRequestSuccess }

func (m *SessionRequestSuccessMessage) Read(reader *sshio.SSHDataReader) error {
	return nil
}

func (m *SessionRequestSuccessMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	return nil
}

func (m *SessionRequestSuccessMessage) ToBuffer() []byte { return toBuffer(m) }

// SessionRequestFailureMessage represents SSH_MSG_REQUEST_FAILURE (type 82).
type SessionRequestFailureMessage struct{}

func (m *SessionRequestFailureMessage) MessageType() byte { return MsgNumSessionRequestFailure }

func (m *SessionRequestFailureMessage) Read(reader *sshio.SSHDataReader) error {
	return nil
}

func (m *SessionRequestFailureMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	return nil
}

func (m *SessionRequestFailureMessage) ToBuffer() []byte { return toBuffer(m) }

// SessionChannelRequestMessage extends SessionRequestMessage to bundle
// a channel request with a session request. Used by the open-channel-request
// protocol extension to avoid an extra round-trip when opening a channel.
type SessionChannelRequestMessage struct {
	SessionRequestMessage
	SenderChannel uint32
	Request       *ChannelRequestMessage
}

func (m *SessionChannelRequestMessage) Read(reader *sshio.SSHDataReader) error {
	if err := m.SessionRequestMessage.Read(reader); err != nil {
		return err
	}
	var err error
	m.SenderChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	// Read the embedded message type byte (matching C#/TS wire format).
	_, err = reader.ReadByte()
	if err != nil {
		return err
	}
	m.Request = &ChannelRequestMessage{}
	return m.Request.ReadFields(reader)
}

func (m *SessionChannelRequestMessage) Write(writer *sshio.SSHDataWriter) error {
	if err := m.SessionRequestMessage.Write(writer); err != nil {
		return err
	}
	writer.WriteUInt32(m.SenderChannel)
	if m.Request != nil {
		// Write the full embedded message including its type byte,
		// matching the C#/TS wire format.
		m.Request.Write(writer)
	}
	return nil
}

func (m *SessionChannelRequestMessage) ToBuffer() []byte { return toBuffer(m) }
