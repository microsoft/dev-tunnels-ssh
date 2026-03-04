// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	"math/big"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// KeyExchangeInitMessage represents SSH_MSG_KEXINIT (type 20).
// Sent by both client and server to begin key exchange negotiation.
type KeyExchangeInitMessage struct {
	Cookie                                [16]byte
	KeyExchangeAlgorithms                 []string
	ServerHostKeyAlgorithms               []string
	EncryptionAlgorithmsClientToServer    []string
	EncryptionAlgorithmsServerToClient    []string
	MacAlgorithmsClientToServer           []string
	MacAlgorithmsServerToClient           []string
	CompressionAlgorithmsClientToServer   []string
	CompressionAlgorithmsServerToClient   []string
	LanguagesClientToServer               []string
	LanguagesServerToClient               []string
	FirstKexPacketFollows                 bool
	Reserved                              uint32
}

func (m *KeyExchangeInitMessage) MessageType() byte { return MsgNumKeyExchangeInit }

func (m *KeyExchangeInitMessage) Read(reader *sshio.SSHDataReader) error {
	cookie, err := reader.ReadBytes(16)
	if err != nil {
		return err
	}
	copy(m.Cookie[:], cookie)

	m.KeyExchangeAlgorithms, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.ServerHostKeyAlgorithms, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.EncryptionAlgorithmsClientToServer, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.EncryptionAlgorithmsServerToClient, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.MacAlgorithmsClientToServer, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.MacAlgorithmsServerToClient, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.CompressionAlgorithmsClientToServer, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.CompressionAlgorithmsServerToClient, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.LanguagesClientToServer, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.LanguagesServerToClient, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.FirstKexPacketFollows, err = reader.ReadBoolean()
	if err != nil {
		return err
	}
	m.Reserved, err = reader.ReadUInt32()
	return err
}

func (m *KeyExchangeInitMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.Write(m.Cookie[:])
	writer.WriteList(m.KeyExchangeAlgorithms)
	writer.WriteList(m.ServerHostKeyAlgorithms)
	writer.WriteList(m.EncryptionAlgorithmsClientToServer)
	writer.WriteList(m.EncryptionAlgorithmsServerToClient)
	writer.WriteList(m.MacAlgorithmsClientToServer)
	writer.WriteList(m.MacAlgorithmsServerToClient)
	writer.WriteList(m.CompressionAlgorithmsClientToServer)
	writer.WriteList(m.CompressionAlgorithmsServerToClient)
	writer.WriteList(m.LanguagesClientToServer)
	writer.WriteList(m.LanguagesServerToClient)
	writer.WriteBoolean(m.FirstKexPacketFollows)
	writer.WriteUInt32(m.Reserved)
	return nil
}

func (m *KeyExchangeInitMessage) ToBuffer() []byte { return toBuffer(m) }

// NewKeysMessage represents SSH_MSG_NEWKEYS (type 21).
// Sent by both sides to indicate that subsequent messages will use
// the newly negotiated keys and algorithms.
type NewKeysMessage struct{}

func (m *NewKeysMessage) MessageType() byte { return MsgNumNewKeys }

func (m *NewKeysMessage) Read(reader *sshio.SSHDataReader) error {
	return nil
}

func (m *NewKeysMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	return nil
}

func (m *NewKeysMessage) ToBuffer() []byte { return toBuffer(m) }

// KeyExchangeDhInitMessage represents SSH_MSG_KEXDH_INIT (type 30).
// Sent by the client with its DH/ECDH public value.
type KeyExchangeDhInitMessage struct {
	E *big.Int
}

func (m *KeyExchangeDhInitMessage) MessageType() byte { return MsgNumKeyExchangeDhInit }

func (m *KeyExchangeDhInitMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.E, err = reader.ReadBigInt()
	return err
}

func (m *KeyExchangeDhInitMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteBigInt(m.E)
	return nil
}

func (m *KeyExchangeDhInitMessage) ToBuffer() []byte { return toBuffer(m) }

// KeyExchangeDhReplyMessage represents SSH_MSG_KEXDH_REPLY (type 31).
// Sent by the server with its host key, DH/ECDH public value, and signature.
type KeyExchangeDhReplyMessage struct {
	HostKey   []byte
	F         *big.Int
	Signature []byte
}

func (m *KeyExchangeDhReplyMessage) MessageType() byte { return MsgNumKeyExchangeDhReply }

func (m *KeyExchangeDhReplyMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.HostKey, err = reader.ReadBinary()
	if err != nil {
		return err
	}
	m.F, err = reader.ReadBigInt()
	if err != nil {
		return err
	}
	m.Signature, err = reader.ReadBinary()
	return err
}

func (m *KeyExchangeDhReplyMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteBinary(m.HostKey)
	writer.WriteBigInt(m.F)
	writer.WriteBinary(m.Signature)
	return nil
}

func (m *KeyExchangeDhReplyMessage) ToBuffer() []byte { return toBuffer(m) }
