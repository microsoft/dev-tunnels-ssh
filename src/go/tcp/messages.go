// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import (
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// Port forwarding request types.
const (
	PortForwardRequestType       = "tcpip-forward"
	CancelPortForwardRequestType = "cancel-tcpip-forward"
)

// Port forwarding channel types.
const (
	ForwardedTCPIPChannelType = "forwarded-tcpip"
	DirectTCPIPChannelType    = "direct-tcpip"
)

// PortForwardRequestMessage extends SessionRequestMessage with address and port
// fields for tcpip-forward and cancel-tcpip-forward requests.
type PortForwardRequestMessage struct {
	RequestType    string
	WantReply      bool
	AddressToBind  string
	Port           uint32
}

func (m *PortForwardRequestMessage) MessageType() byte {
	return messages.MsgNumSessionRequest
}

func (m *PortForwardRequestMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.RequestType, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.WantReply, err = reader.ReadBoolean()
	if err != nil {
		return err
	}
	m.AddressToBind, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.Port, err = reader.ReadUInt32()
	return err
}

func (m *PortForwardRequestMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.RequestType)
	writer.WriteBoolean(m.WantReply)
	writer.WriteString(m.AddressToBind)
	writer.WriteUInt32(m.Port)
	return nil
}

func (m *PortForwardRequestMessage) ToBuffer() []byte {
	writer := sshio.NewSSHDataWriter(make([]byte, 0))
	_ = m.Write(writer)
	return writer.ToBuffer()
}

// PortForwardSuccessMessage extends SessionRequestSuccessMessage with the allocated port.
type PortForwardSuccessMessage struct {
	Port uint32
}

func (m *PortForwardSuccessMessage) MessageType() byte {
	return messages.MsgNumSessionRequestSuccess
}

func (m *PortForwardSuccessMessage) Read(reader *sshio.SSHDataReader) error {
	// Port field is optional — may be omitted if same as requested.
	if reader.Available() >= 4 {
		var err error
		m.Port, err = reader.ReadUInt32()
		return err
	}
	return nil
}

func (m *PortForwardSuccessMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(m.Port)
	return nil
}

func (m *PortForwardSuccessMessage) ToBuffer() []byte {
	writer := sshio.NewSSHDataWriter(make([]byte, 0))
	_ = m.Write(writer)
	return writer.ToBuffer()
}

// PortForwardChannelOpenMessage extends ChannelOpenMessage with host, port, and
// originator fields used by both forwarded-tcpip and direct-tcpip channel types.
type PortForwardChannelOpenMessage struct {
	ChannelType         string
	SenderChannel       uint32
	MaxWindowSize       uint32
	MaxPacketSize       uint32
	Host                string
	Port                uint32
	OriginatorIPAddress string
	OriginatorPort      uint32
}

func (m *PortForwardChannelOpenMessage) MessageType() byte {
	return messages.MsgNumChannelOpen
}

func (m *PortForwardChannelOpenMessage) Read(reader *sshio.SSHDataReader) error {
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
	if err != nil {
		return err
	}
	m.Host, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.Port, err = reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.OriginatorIPAddress, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.OriginatorPort, err = reader.ReadUInt32()
	return err
}

func (m *PortForwardChannelOpenMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.ChannelType)
	writer.WriteUInt32(m.SenderChannel)
	writer.WriteUInt32(m.MaxWindowSize)
	writer.WriteUInt32(m.MaxPacketSize)
	writer.WriteString(m.Host)
	writer.WriteUInt32(m.Port)
	writer.WriteString(m.OriginatorIPAddress)
	writer.WriteUInt32(m.OriginatorPort)
	return nil
}

func (m *PortForwardChannelOpenMessage) ToBuffer() []byte {
	writer := sshio.NewSSHDataWriter(make([]byte, 0))
	_ = m.Write(writer)
	return writer.ToBuffer()
}

// ParsePortForwardChannelOpenMessage parses the port-forwarding-specific fields
// from a channel open message payload.
func ParsePortForwardChannelOpenMessage(payload []byte) (*PortForwardChannelOpenMessage, error) {
	msg := &PortForwardChannelOpenMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return nil, err
	}
	return msg, nil
}

// ParsePortForwardRequestMessage parses the port-forwarding-specific fields
// from a session request payload.
func ParsePortForwardRequestMessage(payload []byte) (*PortForwardRequestMessage, error) {
	msg := &PortForwardRequestMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return nil, err
	}
	return msg, nil
}
