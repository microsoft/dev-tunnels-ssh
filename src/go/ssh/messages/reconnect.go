// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// SSHReconnectFailureReason defines the reason codes for reconnection failure.
type SSHReconnectFailureReason uint32

const (
	ReconnectFailureNone                       SSHReconnectFailureReason = 0
	ReconnectFailureUnknownServerFailure       SSHReconnectFailureReason = 1
	ReconnectFailureSessionNotFound            SSHReconnectFailureReason = 2
	ReconnectFailureInvalidClientReconnectToken SSHReconnectFailureReason = 3
	ReconnectFailureServerDroppedMessages      SSHReconnectFailureReason = 4
	ReconnectFailureUnknownClientFailure       SSHReconnectFailureReason = 101
	ReconnectFailureDifferentServerHostKey     SSHReconnectFailureReason = 102
	ReconnectFailureInvalidServerReconnectToken SSHReconnectFailureReason = 103
	ReconnectFailureClientDroppedMessages      SSHReconnectFailureReason = 104
)

// SessionReconnectRequestMessage extends SessionRequestMessage with reconnect-specific fields.
// Sent by the client to request session reconnection.
type SessionReconnectRequestMessage struct {
	RequestType                string
	WantReply                  bool
	ClientReconnectToken       []byte
	LastReceivedSequenceNumber uint64
}

func (m *SessionReconnectRequestMessage) MessageType() byte { return MsgNumSessionRequest }

func (m *SessionReconnectRequestMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RequestType, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.WantReply, err = reader.ReadBoolean()
	if err != nil {
		return err
	}
	m.ClientReconnectToken, err = reader.ReadBinary()
	if err != nil {
		return err
	}
	m.LastReceivedSequenceNumber, err = reader.ReadUInt64()
	return err
}

func (m *SessionReconnectRequestMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.RequestType)
	writer.WriteBoolean(m.WantReply)
	writer.WriteBinary(m.ClientReconnectToken)
	writer.WriteUInt64(m.LastReceivedSequenceNumber)
	return nil
}

func (m *SessionReconnectRequestMessage) ToBuffer() []byte { return toBuffer(m) }

// SessionReconnectResponseMessage extends SessionRequestSuccessMessage with reconnect-specific fields.
// Sent by the server to confirm session reconnection.
type SessionReconnectResponseMessage struct {
	ServerReconnectToken       []byte
	LastReceivedSequenceNumber uint64
}

func (m *SessionReconnectResponseMessage) MessageType() byte { return MsgNumSessionRequestSuccess }

func (m *SessionReconnectResponseMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.ServerReconnectToken, err = reader.ReadBinary()
	if err != nil {
		return err
	}
	m.LastReceivedSequenceNumber, err = reader.ReadUInt64()
	return err
}

func (m *SessionReconnectResponseMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteBinary(m.ServerReconnectToken)
	writer.WriteUInt64(m.LastReceivedSequenceNumber)
	return nil
}

func (m *SessionReconnectResponseMessage) ToBuffer() []byte { return toBuffer(m) }

// SessionReconnectFailureMessage extends SessionRequestFailureMessage with reconnect-specific fields.
// Sent by the server when session reconnection is refused.
type SessionReconnectFailureMessage struct {
	ReasonCode  SSHReconnectFailureReason
	Description string
	Language    string
}

func (m *SessionReconnectFailureMessage) MessageType() byte { return MsgNumSessionRequestFailure }

func (m *SessionReconnectFailureMessage) Read(reader *sshio.SSHDataReader) error {
	// Reconnect failure fields are optional (plain SessionRequestFailure has no payload)
	if reader.Available() == 0 {
		m.ReasonCode = ReconnectFailureUnknownClientFailure
		return nil
	}

	rc, err := reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.ReasonCode = SSHReconnectFailureReason(rc)
	m.Description, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.Language, err = reader.ReadString()
	return err
}

func (m *SessionReconnectFailureMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(uint32(m.ReasonCode))
	writer.WriteString(m.Description)
	writer.WriteString(m.Language)
	return nil
}

func (m *SessionReconnectFailureMessage) ToBuffer() []byte { return toBuffer(m) }
