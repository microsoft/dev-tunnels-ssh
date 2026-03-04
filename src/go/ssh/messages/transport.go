// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// SSHDisconnectReason defines the reason codes for SSH disconnect messages (RFC 4253 section 11.1).
type SSHDisconnectReason uint32

const (
	DisconnectHostNotAllowedToConnect    SSHDisconnectReason = 1
	DisconnectProtocolError              SSHDisconnectReason = 2
	DisconnectKeyExchangeFailed          SSHDisconnectReason = 3
	DisconnectReserved                   SSHDisconnectReason = 4
	DisconnectMACError                   SSHDisconnectReason = 5
	DisconnectCompressionError           SSHDisconnectReason = 6
	DisconnectServiceNotAvailable        SSHDisconnectReason = 7
	DisconnectProtocolVersionNotSupported SSHDisconnectReason = 8
	DisconnectHostKeyNotVerifiable       SSHDisconnectReason = 9
	DisconnectConnectionLost             SSHDisconnectReason = 10
	DisconnectByApplication              SSHDisconnectReason = 11
	DisconnectTooManyConnections         SSHDisconnectReason = 12
	DisconnectAuthCancelledByUser        SSHDisconnectReason = 13
	DisconnectNoMoreAuthMethodsAvailable SSHDisconnectReason = 14
	DisconnectIllegalUserName            SSHDisconnectReason = 15
)

// DisconnectMessage represents SSH_MSG_DISCONNECT (type 1).
type DisconnectMessage struct {
	ReasonCode  SSHDisconnectReason
	Description string
	Language    string
}

func (m *DisconnectMessage) MessageType() byte { return MsgNumDisconnect }

func (m *DisconnectMessage) Read(reader *sshio.SSHDataReader) error {
	rc, err := reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.ReasonCode = SSHDisconnectReason(rc)

	m.Description, err = reader.ReadString()
	if err != nil {
		return err
	}

	// Language is optional per spec
	if reader.Available() >= 4 {
		m.Language, err = reader.ReadString()
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *DisconnectMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(uint32(m.ReasonCode))
	writer.WriteString(m.Description)
	writer.WriteString(m.Language)
	return nil
}

func (m *DisconnectMessage) ToBuffer() []byte { return toBuffer(m) }

// IgnoreMessage represents SSH_MSG_IGNORE (type 2).
type IgnoreMessage struct{}

func (m *IgnoreMessage) MessageType() byte { return MsgNumIgnore }

func (m *IgnoreMessage) Read(reader *sshio.SSHDataReader) error {
	return nil
}

func (m *IgnoreMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	return nil
}

func (m *IgnoreMessage) ToBuffer() []byte { return toBuffer(m) }

// UnimplementedMessage represents SSH_MSG_UNIMPLEMENTED (type 3).
type UnimplementedMessage struct {
	SequenceNumber uint32
}

func (m *UnimplementedMessage) MessageType() byte { return MsgNumUnimplemented }

func (m *UnimplementedMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.SequenceNumber, err = reader.ReadUInt32()
	return err
}

func (m *UnimplementedMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.SequenceNumber)
	return nil
}

func (m *UnimplementedMessage) ToBuffer() []byte { return toBuffer(m) }

// DebugMessage represents SSH_MSG_DEBUG (type 4).
type DebugMessage struct {
	AlwaysDisplay bool
	Message       string
	Language      string
}

func (m *DebugMessage) MessageType() byte { return MsgNumDebug }

func (m *DebugMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.AlwaysDisplay, err = reader.ReadBoolean()
	if err != nil {
		return err
	}
	m.Message, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.Language, err = reader.ReadString()
	return err
}

func (m *DebugMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteBoolean(m.AlwaysDisplay)
	writer.WriteString(m.Message)
	writer.WriteString(m.Language)
	return nil
}

func (m *DebugMessage) ToBuffer() []byte { return toBuffer(m) }

// ServiceRequestMessage represents SSH_MSG_SERVICE_REQUEST (type 5).
type ServiceRequestMessage struct {
	ServiceName string
}

func (m *ServiceRequestMessage) MessageType() byte { return MsgNumServiceRequest }

func (m *ServiceRequestMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.ServiceName, err = reader.ReadString()
	return err
}

func (m *ServiceRequestMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.ServiceName)
	return nil
}

func (m *ServiceRequestMessage) ToBuffer() []byte { return toBuffer(m) }

// ServiceAcceptMessage represents SSH_MSG_SERVICE_ACCEPT (type 6).
type ServiceAcceptMessage struct {
	ServiceName string
}

func (m *ServiceAcceptMessage) MessageType() byte { return MsgNumServiceAccept }

func (m *ServiceAcceptMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.ServiceName, err = reader.ReadString()
	return err
}

func (m *ServiceAcceptMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.ServiceName)
	return nil
}

func (m *ServiceAcceptMessage) ToBuffer() []byte { return toBuffer(m) }

// ExtensionInfoMessage represents SSH_MSG_EXT_INFO (type 7).
// Extensions are key-value pairs negotiated via RFC 8308.
type ExtensionInfoMessage struct {
	Extensions map[string]string
}

func (m *ExtensionInfoMessage) MessageType() byte { return MsgNumExtensionInfo }

func (m *ExtensionInfoMessage) Read(reader *sshio.SSHDataReader) error {
	count, err := reader.ReadUInt32()
	if err != nil {
		return err
	}

	m.Extensions = make(map[string]string, count)
	for i := uint32(0); i < count; i++ {
		key, err := reader.ReadString()
		if err != nil {
			return err
		}
		value, err := reader.ReadString()
		if err != nil {
			return err
		}
		m.Extensions[key] = value
	}
	return nil
}

func (m *ExtensionInfoMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())

	exts := m.Extensions
	if exts == nil {
		writer.WriteUInt32(0)
		return nil
	}

	writer.WriteUInt32(uint32(len(exts)))
	for key, value := range exts {
		writer.WriteString(key)
		writer.WriteString(value)
	}
	return nil
}

func (m *ExtensionInfoMessage) ToBuffer() []byte { return toBuffer(m) }
