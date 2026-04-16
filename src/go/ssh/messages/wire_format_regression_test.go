// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	"math/big"
	"testing"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// --- Wire Format Regression Tests ---
// These tests verify exact byte-level wire format for critical message types,
// ensuring compatibility with the C#/TS implementations.

// TestKeyboardInteractiveWireFormat verifies the CRIT-01 fix: keyboard-interactive
// info request messages serialize all prompts first, then all echo flags
// (matching C#/TS and RFC 4256 Section 3.2).
func TestKeyboardInteractiveWireFormat(t *testing.T) {
	msg := &AuthenticationInfoRequestMessage{
		Name:        "auth",
		Instruction: "Please respond",
		Language:    "en",
		Prompts: []AuthenticationInfoRequestPrompt{
			{Prompt: "Password: ", Echo: false},
			{Prompt: "OTP: ", Echo: true},
			{Prompt: "PIN: ", Echo: false},
		},
	}

	buf := msg.ToBuffer()
	if buf[0] != MsgNumAuthInfoRequest {
		t.Fatalf("first byte should be %d, got %d", MsgNumAuthInfoRequest, buf[0])
	}

	// Parse the wire format manually to verify field order.
	r := sshio.NewSSHDataReader(buf[1:]) // skip type byte

	name, _ := r.ReadString()
	if name != "auth" {
		t.Errorf("name = %q, want %q", name, "auth")
	}

	instruction, _ := r.ReadString()
	if instruction != "Please respond" {
		t.Errorf("instruction = %q, want %q", instruction, "Please respond")
	}

	lang, _ := r.ReadString()
	if lang != "en" {
		t.Errorf("language = %q, want %q", lang, "en")
	}

	count, _ := r.ReadUInt32()
	if count != 3 {
		t.Fatalf("prompt count = %d, want 3", count)
	}

	// All prompts must come first (CRIT-01 fix).
	prompts := make([]string, count)
	for i := uint32(0); i < count; i++ {
		prompts[i], _ = r.ReadString()
	}
	if prompts[0] != "Password: " {
		t.Errorf("prompt[0] = %q, want %q", prompts[0], "Password: ")
	}
	if prompts[1] != "OTP: " {
		t.Errorf("prompt[1] = %q, want %q", prompts[1], "OTP: ")
	}
	if prompts[2] != "PIN: " {
		t.Errorf("prompt[2] = %q, want %q", prompts[2], "PIN: ")
	}

	// Then all echo flags.
	echos := make([]bool, count)
	for i := uint32(0); i < count; i++ {
		echos[i], _ = r.ReadBoolean()
	}
	if echos[0] != false {
		t.Error("echo[0] should be false")
	}
	if echos[1] != true {
		t.Error("echo[1] should be true")
	}
	if echos[2] != false {
		t.Error("echo[2] should be false")
	}
}

// TestSessionChannelRequestWireFormat verifies the CRIT-03 fix:
// SessionChannelRequestMessage includes the embedded ChannelRequestMessage's
// type byte in the wire format (matching C#/TS).
func TestSessionChannelRequestWireFormat(t *testing.T) {
	msg := &SessionChannelRequestMessage{
		SessionRequestMessage: SessionRequestMessage{
			RequestType: "open-channel-request",
			WantReply:   true,
		},
		SenderChannel: 42,
		Request: &ChannelRequestMessage{
			RecipientChannel: 7,
			RequestType:      "shell",
			WantReply:        true,
		},
	}

	buf := msg.ToBuffer()
	if buf[0] != MsgNumSessionRequest {
		t.Fatalf("first byte should be %d, got %d", MsgNumSessionRequest, buf[0])
	}

	// Parse the wire format manually.
	r := sshio.NewSSHDataReader(buf[1:]) // skip type byte

	reqType, _ := r.ReadString()
	if reqType != "open-channel-request" {
		t.Errorf("requestType = %q, want %q", reqType, "open-channel-request")
	}

	wantReply, _ := r.ReadBoolean()
	if !wantReply {
		t.Error("wantReply should be true")
	}

	senderCh, _ := r.ReadUInt32()
	if senderCh != 42 {
		t.Errorf("senderChannel = %d, want 42", senderCh)
	}

	// The embedded ChannelRequestMessage must have its type byte.
	embeddedType, _ := r.ReadByte()
	if embeddedType != MsgNumChannelRequest {
		t.Fatalf("embedded message type should be %d (ChannelRequest), got %d",
			MsgNumChannelRequest, embeddedType)
	}

	// Read the embedded channel request fields.
	recipientCh, _ := r.ReadUInt32()
	if recipientCh != 7 {
		t.Errorf("embedded recipientChannel = %d, want 7", recipientCh)
	}

	innerReqType, _ := r.ReadString()
	if innerReqType != "shell" {
		t.Errorf("embedded requestType = %q, want %q", innerReqType, "shell")
	}

	innerWantReply, _ := r.ReadBoolean()
	if !innerWantReply {
		t.Error("embedded wantReply should be true")
	}
}

// TestKeyExchangeInitWireFormat verifies the wire format of KeyExchangeInitMessage
// including the 16-byte cookie and all algorithm name lists.
func TestKeyExchangeInitWireFormat(t *testing.T) {
	cookie := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	msg := &KeyExchangeInitMessage{
		Cookie:                                 cookie,
		KeyExchangeAlgorithms:                  []string{"ecdh-sha2-nistp256"},
		ServerHostKeyAlgorithms:                []string{"ecdsa-sha2-nistp256"},
		EncryptionAlgorithmsClientToServer:     []string{"aes256-gcm@openssh.com"},
		EncryptionAlgorithmsServerToClient:     []string{"aes256-gcm@openssh.com"},
		MacAlgorithmsClientToServer:            []string{},
		MacAlgorithmsServerToClient:            []string{},
		CompressionAlgorithmsClientToServer:    []string{"none"},
		CompressionAlgorithmsServerToClient:    []string{"none"},
		LanguagesClientToServer:                []string{},
		LanguagesServerToClient:                []string{},
		FirstKexPacketFollows:                  false,
		Reserved:                               0,
	}

	buf := msg.ToBuffer()
	if buf[0] != MsgNumKeyExchangeInit {
		t.Fatalf("first byte should be %d, got %d", MsgNumKeyExchangeInit, buf[0])
	}

	// Verify the cookie is at bytes 1-16.
	for i := 0; i < 16; i++ {
		if buf[1+i] != cookie[i] {
			t.Errorf("cookie[%d] = %d, want %d", i, buf[1+i], cookie[i])
		}
	}

	// Round-trip to verify all fields.
	target := &KeyExchangeInitMessage{}
	roundTrip(t, msg, target)

	if target.Cookie != cookie {
		t.Error("cookie not preserved in round-trip")
	}
	assertStringSlice(t, "KeyExchangeAlgorithms",
		target.KeyExchangeAlgorithms, msg.KeyExchangeAlgorithms)
	assertStringSlice(t, "ServerHostKeyAlgorithms",
		target.ServerHostKeyAlgorithms, msg.ServerHostKeyAlgorithms)
	assertStringSlice(t, "EncryptionAlgorithmsClientToServer",
		target.EncryptionAlgorithmsClientToServer, msg.EncryptionAlgorithmsClientToServer)
	assertStringSlice(t, "EncryptionAlgorithmsServerToClient",
		target.EncryptionAlgorithmsServerToClient, msg.EncryptionAlgorithmsServerToClient)
	assertStringSlice(t, "CompressionAlgorithmsClientToServer",
		target.CompressionAlgorithmsClientToServer, msg.CompressionAlgorithmsClientToServer)
	assertStringSlice(t, "CompressionAlgorithmsServerToClient",
		target.CompressionAlgorithmsServerToClient, msg.CompressionAlgorithmsServerToClient)
	if target.FirstKexPacketFollows != false {
		t.Error("firstKexPacketFollows should be false")
	}
}

// TestServiceRequestWireFormat verifies the wire format of ServiceRequestMessage.
func TestServiceRequestWireFormat(t *testing.T) {
	msg := &ServiceRequestMessage{ServiceName: "ssh-userauth"}

	buf := msg.ToBuffer()
	if buf[0] != MsgNumServiceRequest {
		t.Fatalf("first byte should be %d, got %d", MsgNumServiceRequest, buf[0])
	}

	// Parse manually: type (1) + string-length (4) + string data.
	r := sshio.NewSSHDataReader(buf[1:])
	name, err := r.ReadString()
	if err != nil {
		t.Fatalf("ReadString failed: %v", err)
	}
	if name != "ssh-userauth" {
		t.Errorf("serviceName = %q, want %q", name, "ssh-userauth")
	}

	// Round-trip.
	target := &ServiceRequestMessage{}
	roundTrip(t, msg, target)
	if target.ServiceName != "ssh-userauth" {
		t.Errorf("round-trip serviceName = %q, want %q", target.ServiceName, "ssh-userauth")
	}
}

// --- Additional regression: DH message wire format ---

// TestKeyExchangeDhInitWireFormat verifies that KeyExchangeDhInitMessage
// correctly serializes a big.Int DH public value.
func TestKeyExchangeDhInitWireFormat(t *testing.T) {
	e := new(big.Int).SetBytes([]byte{0x00, 0x80, 0x01, 0x02, 0x03})
	msg := &KeyExchangeDhInitMessage{E: e}

	buf := msg.ToBuffer()
	if buf[0] != MsgNumKeyExchangeDhInit {
		t.Fatalf("first byte should be %d, got %d", MsgNumKeyExchangeDhInit, buf[0])
	}

	target := &KeyExchangeDhInitMessage{}
	roundTrip(t, msg, target)
	if target.E.Cmp(e) != 0 {
		t.Errorf("E = %v, want %v", target.E, e)
	}
}

// TestKeyExchangeDhReplyWireFormat verifies the DH reply message wire format.
func TestKeyExchangeDhReplyWireFormat(t *testing.T) {
	f := new(big.Int).SetBytes([]byte{0x42, 0x43, 0x44})
	msg := &KeyExchangeDhReplyMessage{
		HostKey:   []byte{0x01, 0x02, 0x03},
		F:         f,
		Signature: []byte{0xAA, 0xBB, 0xCC},
	}

	buf := msg.ToBuffer()
	if buf[0] != MsgNumKeyExchangeDhReply {
		t.Fatalf("first byte should be %d, got %d", MsgNumKeyExchangeDhReply, buf[0])
	}

	target := &KeyExchangeDhReplyMessage{}
	roundTrip(t, msg, target)
	assertByteSlice(t, "HostKey", target.HostKey, msg.HostKey)
	if target.F.Cmp(f) != 0 {
		t.Errorf("F = %v, want %v", target.F, f)
	}
	assertByteSlice(t, "Signature", target.Signature, msg.Signature)
}
