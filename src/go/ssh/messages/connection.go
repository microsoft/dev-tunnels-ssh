// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// SSHChannelOpenFailureReason defines the reason codes for channel open failure (RFC 4254 section 5.1).
type SSHChannelOpenFailureReason uint32

const (
	ChannelOpenFailureNone                       SSHChannelOpenFailureReason = 0
	ChannelOpenFailureAdministrativelyProhibited SSHChannelOpenFailureReason = 1
	ChannelOpenFailureConnectFailed              SSHChannelOpenFailureReason = 2
	ChannelOpenFailureUnknownChannelType         SSHChannelOpenFailureReason = 3
	ChannelOpenFailureResourceShortage           SSHChannelOpenFailureReason = 4
)

// ChannelOpenMessage represents SSH_MSG_CHANNEL_OPEN (type 90).
type ChannelOpenMessage struct {
	ChannelType   string
	SenderChannel uint32
	MaxWindowSize uint32
	MaxPacketSize uint32
}

func (m *ChannelOpenMessage) MessageType() byte { return MsgNumChannelOpen }

func (m *ChannelOpenMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.ChannelType, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.SenderChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.MaxWindowSize, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.MaxPacketSize, err = reader.ReadUInt32()
	return err
}

func (m *ChannelOpenMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.ChannelType)
	writer.WriteUInt32(m.SenderChannel)
	writer.WriteUInt32(m.MaxWindowSize)
	writer.WriteUInt32(m.MaxPacketSize)
	return nil
}

func (m *ChannelOpenMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelOpenConfirmationMessage represents SSH_MSG_CHANNEL_OPEN_CONFIRMATION (type 91).
type ChannelOpenConfirmationMessage struct {
	RecipientChannel uint32
	SenderChannel    uint32
	MaxWindowSize    uint32
	MaxPacketSize    uint32
}

func (m *ChannelOpenConfirmationMessage) MessageType() byte { return MsgNumChannelOpenConfirmation }

func (m *ChannelOpenConfirmationMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.SenderChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.MaxWindowSize, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.MaxPacketSize, err = reader.ReadUInt32()
	return err
}

func (m *ChannelOpenConfirmationMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	writer.WriteUInt32(m.SenderChannel)
	writer.WriteUInt32(m.MaxWindowSize)
	writer.WriteUInt32(m.MaxPacketSize)
	return nil
}

func (m *ChannelOpenConfirmationMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelOpenFailureMessage represents SSH_MSG_CHANNEL_OPEN_FAILURE (type 92).
type ChannelOpenFailureMessage struct {
	RecipientChannel uint32
	ReasonCode       SSHChannelOpenFailureReason
	Description      string
	Language         string
}

func (m *ChannelOpenFailureMessage) MessageType() byte { return MsgNumChannelOpenFailure }

func (m *ChannelOpenFailureMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	rc, err := reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.ReasonCode = SSHChannelOpenFailureReason(rc)
	m.Description, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.Language, err = reader.ReadString()
	return err
}

func (m *ChannelOpenFailureMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	writer.WriteUInt32(uint32(m.ReasonCode))
	writer.WriteString(m.Description)
	writer.WriteString(m.Language)
	return nil
}

func (m *ChannelOpenFailureMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelWindowAdjustMessage represents SSH_MSG_CHANNEL_WINDOW_ADJUST (type 93).
type ChannelWindowAdjustMessage struct {
	RecipientChannel uint32
	BytesToAdd       uint32
}

func (m *ChannelWindowAdjustMessage) MessageType() byte { return MsgNumChannelWindowAdjust }

func (m *ChannelWindowAdjustMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.BytesToAdd, err = reader.ReadUInt32()
	return err
}

func (m *ChannelWindowAdjustMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	writer.WriteUInt32(m.BytesToAdd)
	return nil
}

func (m *ChannelWindowAdjustMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelDataMessage represents SSH_MSG_CHANNEL_DATA (type 94).
type ChannelDataMessage struct {
	RecipientChannel uint32
	Data             []byte
}

func (m *ChannelDataMessage) MessageType() byte { return MsgNumChannelData }

func (m *ChannelDataMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.Data, err = reader.ReadBinary()
	return err
}

func (m *ChannelDataMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	writer.WriteBinary(m.Data)
	return nil
}

func (m *ChannelDataMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelExtendedDataMessage represents SSH_MSG_CHANNEL_EXTENDED_DATA (type 95).
type ChannelExtendedDataMessage struct {
	RecipientChannel uint32
	DataTypeCode     uint32
	Data             []byte
}

func (m *ChannelExtendedDataMessage) MessageType() byte { return MsgNumChannelExtendedData }

func (m *ChannelExtendedDataMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.DataTypeCode, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.Data, err = reader.ReadBinary()
	return err
}

func (m *ChannelExtendedDataMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	writer.WriteUInt32(m.DataTypeCode)
	writer.WriteBinary(m.Data)
	return nil
}

func (m *ChannelExtendedDataMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelEofMessage represents SSH_MSG_CHANNEL_EOF (type 96).
type ChannelEofMessage struct {
	RecipientChannel uint32
}

func (m *ChannelEofMessage) MessageType() byte { return MsgNumChannelEof }

func (m *ChannelEofMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	return err
}

func (m *ChannelEofMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	return nil
}

func (m *ChannelEofMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelCloseMessage represents SSH_MSG_CHANNEL_CLOSE (type 97).
type ChannelCloseMessage struct {
	RecipientChannel uint32
}

func (m *ChannelCloseMessage) MessageType() byte { return MsgNumChannelClose }

func (m *ChannelCloseMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	return err
}

func (m *ChannelCloseMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	return nil
}

func (m *ChannelCloseMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelRequestMessage represents SSH_MSG_CHANNEL_REQUEST (type 98).
type ChannelRequestMessage struct {
	RecipientChannel uint32
	RequestType      string
	WantReply        bool

	// Payload contains the type-specific data bytes that follow the standard
	// channel request header fields (recipient, type, want_reply).
	// This is preserved during Read so that pipe forwarding can relay the
	// complete message including type-specific fields.
	Payload []byte
}

func (m *ChannelRequestMessage) MessageType() byte { return MsgNumChannelRequest }

func (m *ChannelRequestMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.RequestType, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.WantReply, err = reader.ReadBoolean()
	if err != nil {
		return err
	}

	// Capture any remaining type-specific data as opaque payload.
	if remaining := reader.Available(); remaining > 0 {
		m.Payload, err = reader.ReadBytes(remaining)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *ChannelRequestMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	writer.WriteString(m.RequestType)
	writer.WriteBoolean(m.WantReply)
	if len(m.Payload) > 0 {
		writer.Write(m.Payload)
	}
	return nil
}

func (m *ChannelRequestMessage) ToBuffer() []byte { return toBuffer(m) }

// ReadFields reads the channel request fields from the reader (without type byte).
// Used by SessionChannelRequestMessage to read the embedded request.
func (m *ChannelRequestMessage) ReadFields(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.RequestType, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.WantReply, err = reader.ReadBoolean()
	return err
}

// WriteFields writes the channel request fields to the writer (without type byte).
// Used by SessionChannelRequestMessage to write the embedded request.
func (m *ChannelRequestMessage) WriteFields(writer *sshio.SSHDataWriter) {
	writer.WriteUInt32(m.RecipientChannel)
	writer.WriteString(m.RequestType)
	writer.WriteBoolean(m.WantReply)
}

// CommandRequestMessage extends ChannelRequestMessage with a command string.
// It represents an "exec" channel request (RFC 4254 section 6.5).
type CommandRequestMessage struct {
	RecipientChannel uint32
	RequestType      string
	WantReply        bool
	Command          string
}

func NewCommandRequestMessage(command string) *CommandRequestMessage {
	return &CommandRequestMessage{
		RequestType: "exec",
		WantReply:   true,
		Command:     command,
	}
}

func (m *CommandRequestMessage) MessageType() byte { return MsgNumChannelRequest }

func (m *CommandRequestMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.RequestType, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.WantReply, err = reader.ReadBoolean()
	if err != nil {
		return err
	}
	m.Command, err = reader.ReadString()
	return err
}

func (m *CommandRequestMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	writer.WriteString(m.RequestType)
	writer.WriteBoolean(m.WantReply)
	writer.WriteString(m.Command)
	return nil
}

func (m *CommandRequestMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelSignalMessage extends ChannelRequestMessage with exit status and signal info.
// It handles three request types: "exit-status", "signal", and "exit-signal".
type ChannelSignalMessage struct {
	RecipientChannel uint32
	RequestType      string
	WantReply        bool
	ExitStatus       uint32
	Signal           string
	ExitSignal       string
	ErrorMessage     string
}

func (m *ChannelSignalMessage) MessageType() byte { return MsgNumChannelRequest }

func (m *ChannelSignalMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.RequestType, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.WantReply, err = reader.ReadBoolean()
	if err != nil {
		return err
	}

	switch m.RequestType {
	case "exit-status":
		m.ExitStatus, err = reader.ReadUInt32()
	case "signal":
		m.Signal, err = reader.ReadString()
	case "exit-signal":
		m.ExitSignal, err = reader.ReadString()
		if err != nil {
			return err
		}
		// Core dumped flag (read and discard)
		_, err = reader.ReadBoolean()
		if err != nil {
			return err
		}
		m.ErrorMessage, err = reader.ReadString()
		if err != nil {
			return err
		}
		// Language tag (read and discard)
		_, err = reader.ReadString()
	}
	return err
}

func (m *ChannelSignalMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	writer.WriteString(m.RequestType)
	writer.WriteBoolean(m.WantReply)

	switch m.RequestType {
	case "exit-status":
		writer.WriteUInt32(m.ExitStatus)
	case "signal":
		writer.WriteString(m.Signal)
	case "exit-signal":
		writer.WriteString(m.ExitSignal)
		writer.WriteBoolean(false) // Core dumped
		writer.WriteString(m.ErrorMessage)
		writer.WriteString("") // Language tag
	}
	return nil
}

func (m *ChannelSignalMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelSuccessMessage represents SSH_MSG_CHANNEL_SUCCESS (type 99).
type ChannelSuccessMessage struct {
	RecipientChannel uint32
}

func (m *ChannelSuccessMessage) MessageType() byte { return MsgNumChannelSuccess }

func (m *ChannelSuccessMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	return err
}

func (m *ChannelSuccessMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	return nil
}

func (m *ChannelSuccessMessage) ToBuffer() []byte { return toBuffer(m) }

// ChannelFailureMessage represents SSH_MSG_CHANNEL_FAILURE (type 100).
type ChannelFailureMessage struct {
	RecipientChannel uint32
}

func (m *ChannelFailureMessage) MessageType() byte { return MsgNumChannelFailure }

func (m *ChannelFailureMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RecipientChannel, err = reader.ReadUInt32()
	return err
}

func (m *ChannelFailureMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.RecipientChannel)
	return nil
}

func (m *ChannelFailureMessage) ToBuffer() []byte { return toBuffer(m) }
