// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// AuthenticationRequestMessage represents SSH_MSG_USERAUTH_REQUEST (type 50).
// Fields are populated based on MethodName: password, publickey, or keyboard-interactive.
type AuthenticationRequestMessage struct {
	Username    string
	ServiceName string
	MethodName  string

	// Password is set when MethodName == "password".
	Password string

	// Public key fields, set when MethodName == "publickey" or "hostbased".
	HasSignature     bool
	KeyAlgorithmName string
	PublicKey        []byte
	Signature        []byte

	// Host-based fields, set when MethodName == "hostbased" (RFC 4252 Section 9).
	ClientHostname string
	ClientUsername string

	// PayloadWithoutSignature is the raw message bytes before the signature field.
	// Used by the server to verify the client's signature.
	PayloadWithoutSignature []byte
}

func (m *AuthenticationRequestMessage) MessageType() byte { return MsgNumAuthenticationRequest }

func (m *AuthenticationRequestMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.Username, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.ServiceName, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.MethodName, err = reader.ReadString()
	if err != nil {
		return err
	}

	switch m.MethodName {
	case "password":
		// boolean FALSE (not changing old password) + string password
		_, err = reader.ReadBoolean()
		if err != nil {
			return err
		}
		m.Password, err = reader.ReadString()
		if err != nil {
			return err
		}

	case "publickey":
		m.HasSignature, err = reader.ReadBoolean()
		if err != nil {
			return err
		}
		m.KeyAlgorithmName, err = reader.ReadString()
		if err != nil {
			return err
		}
		m.PublicKey, err = reader.ReadBinary()
		if err != nil {
			return err
		}
		if m.HasSignature {
			m.Signature, err = reader.ReadBinary()
			if err != nil {
				return err
			}
		}

	case "hostbased":
		// RFC 4252 Section 9: key-algorithm, public-key, client-hostname, client-username, signature
		m.KeyAlgorithmName, err = reader.ReadString()
		if err != nil {
			return err
		}
		m.PublicKey, err = reader.ReadBinary()
		if err != nil {
			return err
		}
		m.ClientHostname, err = reader.ReadString()
		if err != nil {
			return err
		}
		m.ClientUsername, err = reader.ReadString()
		if err != nil {
			return err
		}
		m.Signature, err = reader.ReadBinary()
		if err != nil {
			return err
		}

	case "keyboard-interactive":
		// language tag and submethods (typically empty, but must be read)
		if reader.Available() > 0 {
			_, _ = reader.ReadString() // language tag
		}
		if reader.Available() > 0 {
			_, _ = reader.ReadString() // submethods
		}
	}

	return nil
}

func (m *AuthenticationRequestMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.Username)
	writer.WriteString(m.ServiceName)
	writer.WriteString(m.MethodName)

	switch m.MethodName {
	case "password":
		writer.WriteBoolean(false) // not changing old password
		writer.WriteString(m.Password)

	case "publickey":
		writer.WriteBoolean(m.HasSignature)
		writer.WriteString(m.KeyAlgorithmName)
		writer.WriteBinary(m.PublicKey)
		if m.HasSignature {
			writer.WriteBinary(m.Signature)
		}

	case "hostbased":
		writer.WriteString(m.KeyAlgorithmName)
		writer.WriteBinary(m.PublicKey)
		writer.WriteString(m.ClientHostname)
		writer.WriteString(m.ClientUsername)
		writer.WriteBinary(m.Signature)

	case "keyboard-interactive":
		writer.WriteString("") // language tag
		writer.WriteString("") // submethods
	}

	return nil
}

func (m *AuthenticationRequestMessage) ToBuffer() []byte { return toBuffer(m) }

// AuthenticationFailureMessage represents SSH_MSG_USERAUTH_FAILURE (type 51).
type AuthenticationFailureMessage struct {
	MethodNames    []string
	PartialSuccess bool
}

func (m *AuthenticationFailureMessage) MessageType() byte { return MsgNumAuthenticationFailure }

func (m *AuthenticationFailureMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.MethodNames, err = reader.ReadList()
	if err != nil {
		return err
	}
	m.PartialSuccess, err = reader.ReadBoolean()
	return err
}

func (m *AuthenticationFailureMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteList(m.MethodNames)
	writer.WriteBoolean(m.PartialSuccess)
	return nil
}

func (m *AuthenticationFailureMessage) ToBuffer() []byte { return toBuffer(m) }

// AuthenticationSuccessMessage represents SSH_MSG_USERAUTH_SUCCESS (type 52).
type AuthenticationSuccessMessage struct{}

func (m *AuthenticationSuccessMessage) MessageType() byte { return MsgNumAuthenticationSuccess }

func (m *AuthenticationSuccessMessage) Read(reader *sshio.SSHDataReader) error {
	return nil
}

func (m *AuthenticationSuccessMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	return nil
}

func (m *AuthenticationSuccessMessage) ToBuffer() []byte { return toBuffer(m) }

// PublicKeyOkMessage represents SSH_MSG_USERAUTH_PK_OK (type 60).
// Sent by the server to indicate that the offered public key is acceptable.
type PublicKeyOkMessage struct {
	KeyAlgorithmName string
	PublicKey        []byte
}

func (m *PublicKeyOkMessage) MessageType() byte { return MsgNumPublicKeyOk }

func (m *PublicKeyOkMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.KeyAlgorithmName, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.PublicKey, err = reader.ReadBinary()
	return err
}

func (m *PublicKeyOkMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.KeyAlgorithmName)
	writer.WriteBinary(m.PublicKey)
	return nil
}

func (m *PublicKeyOkMessage) ToBuffer() []byte { return toBuffer(m) }

// AuthenticationInfoRequestPrompt represents a single prompt in an
// SSH_MSG_USERAUTH_INFO_REQUEST message.
type AuthenticationInfoRequestPrompt struct {
	Prompt string
	Echo   bool
}

// AuthenticationInfoRequestMessage represents SSH_MSG_USERAUTH_INFO_REQUEST (type 60).
// Used by the keyboard-interactive authentication method to request information
// from the user.
//
// Serialization follows the C# and TypeScript implementations: all prompt
// strings are written first, followed by all echo booleans. This matches
// the wire format used by the other Dev Tunnels SSH implementations.
type AuthenticationInfoRequestMessage struct {
	Name        string
	Instruction string
	Language    string
	Prompts     []AuthenticationInfoRequestPrompt
}

func (m *AuthenticationInfoRequestMessage) MessageType() byte { return MsgNumAuthInfoRequest }

func (m *AuthenticationInfoRequestMessage) Read(reader *sshio.SSHDataReader) error {
	var err error
	m.Name, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.Instruction, err = reader.ReadString()
	if err != nil {
		return err
	}
	m.Language, err = reader.ReadString()
	if err != nil {
		return err
	}
	count, err := reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.Prompts = make([]AuthenticationInfoRequestPrompt, count)
	// Read all prompt strings first.
	for i := uint32(0); i < count; i++ {
		m.Prompts[i].Prompt, err = reader.ReadString()
		if err != nil {
			return err
		}
	}
	// Then read all echo flags.
	for i := uint32(0); i < count; i++ {
		m.Prompts[i].Echo, err = reader.ReadBoolean()
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *AuthenticationInfoRequestMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteString(m.Name)
	writer.WriteString(m.Instruction)
	writer.WriteString(m.Language)
	writer.WriteUInt32(uint32(len(m.Prompts)))
	// Write all prompt strings first.
	for _, p := range m.Prompts {
		writer.WriteString(p.Prompt)
	}
	// Then write all echo flags.
	for _, p := range m.Prompts {
		writer.WriteBoolean(p.Echo)
	}
	return nil
}

func (m *AuthenticationInfoRequestMessage) ToBuffer() []byte { return toBuffer(m) }

// AuthenticationInfoResponseMessage represents SSH_MSG_USERAUTH_INFO_RESPONSE (type 61).
// Sent by the client in response to an AuthenticationInfoRequestMessage.
//
// Serialization follows RFC 4256 Section 3.4: num-responses followed by
// response strings. The number of responses must match the num-prompts
// from the corresponding InfoRequest.
type AuthenticationInfoResponseMessage struct {
	Responses []string
}

func (m *AuthenticationInfoResponseMessage) MessageType() byte { return MsgNumAuthInfoResponse }

func (m *AuthenticationInfoResponseMessage) Read(reader *sshio.SSHDataReader) error {
	count, err := reader.ReadUInt32()
	if err != nil {
		return err
	}
	m.Responses = make([]string, count)
	for i := uint32(0); i < count; i++ {
		m.Responses[i], err = reader.ReadString()
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *AuthenticationInfoResponseMessage) Write(writer *sshio.SSHDataWriter) error {
	_ = writer.WriteByte(m.MessageType())
	writer.WriteUInt32(uint32(len(m.Responses)))
	for _, r := range m.Responses {
		writer.WriteString(r)
	}
	return nil
}

func (m *AuthenticationInfoResponseMessage) ToBuffer() []byte { return toBuffer(m) }
