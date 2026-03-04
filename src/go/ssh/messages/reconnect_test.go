// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	"bytes"
	"testing"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// --- SessionReconnectRequestMessage tests ---

func TestSessionReconnectRequestMessageRoundTrip(t *testing.T) {
	token := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	original := &SessionReconnectRequestMessage{
		RequestType:                "session-reconnect@microsoft.com",
		WantReply:                  true,
		ClientReconnectToken:       token,
		LastReceivedSequenceNumber: 42,
	}
	target := &SessionReconnectRequestMessage{}
	roundTrip(t, original, target)

	if target.RequestType != "session-reconnect@microsoft.com" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "session-reconnect@microsoft.com")
	}
	if target.WantReply != true {
		t.Error("WantReply should be true")
	}
	if !bytes.Equal(target.ClientReconnectToken, token) {
		t.Errorf("ClientReconnectToken = %v, want %v", target.ClientReconnectToken, token)
	}
	if target.LastReceivedSequenceNumber != 42 {
		t.Errorf("LastReceivedSequenceNumber = %d, want 42", target.LastReceivedSequenceNumber)
	}
}

func TestSessionReconnectRequestMessageType(t *testing.T) {
	m := &SessionReconnectRequestMessage{}
	if m.MessageType() != 80 {
		t.Errorf("MessageType() = %d, want 80", m.MessageType())
	}
}

func TestSessionReconnectRequestMessageLargeToken(t *testing.T) {
	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(i)
	}
	original := &SessionReconnectRequestMessage{
		RequestType:                "session-reconnect@microsoft.com",
		WantReply:                  true,
		ClientReconnectToken:       token,
		LastReceivedSequenceNumber: 0xFFFFFFFFFFFFFFFF,
	}
	target := &SessionReconnectRequestMessage{}
	roundTrip(t, original, target)

	if !bytes.Equal(target.ClientReconnectToken, token) {
		t.Error("ClientReconnectToken mismatch for large token")
	}
	if target.LastReceivedSequenceNumber != 0xFFFFFFFFFFFFFFFF {
		t.Errorf("LastReceivedSequenceNumber = %d, want max uint64", target.LastReceivedSequenceNumber)
	}
}

func TestSessionReconnectRequestMessageZeroSequence(t *testing.T) {
	original := &SessionReconnectRequestMessage{
		RequestType:                "session-reconnect@microsoft.com",
		WantReply:                  true,
		ClientReconnectToken:       []byte{0xFF},
		LastReceivedSequenceNumber: 0,
	}
	target := &SessionReconnectRequestMessage{}
	roundTrip(t, original, target)

	if target.LastReceivedSequenceNumber != 0 {
		t.Errorf("LastReceivedSequenceNumber = %d, want 0", target.LastReceivedSequenceNumber)
	}
}

// --- SessionReconnectResponseMessage tests ---

func TestSessionReconnectResponseMessageRoundTrip(t *testing.T) {
	token := []byte{0x10, 0x20, 0x30, 0x40}
	original := &SessionReconnectResponseMessage{
		ServerReconnectToken:       token,
		LastReceivedSequenceNumber: 100,
	}
	target := &SessionReconnectResponseMessage{}
	roundTrip(t, original, target)

	if !bytes.Equal(target.ServerReconnectToken, token) {
		t.Errorf("ServerReconnectToken = %v, want %v", target.ServerReconnectToken, token)
	}
	if target.LastReceivedSequenceNumber != 100 {
		t.Errorf("LastReceivedSequenceNumber = %d, want 100", target.LastReceivedSequenceNumber)
	}
}

func TestSessionReconnectResponseMessageType(t *testing.T) {
	m := &SessionReconnectResponseMessage{}
	if m.MessageType() != 81 {
		t.Errorf("MessageType() = %d, want 81", m.MessageType())
	}
}

func TestSessionReconnectResponseMessageEmptyToken(t *testing.T) {
	original := &SessionReconnectResponseMessage{
		ServerReconnectToken:       []byte{},
		LastReceivedSequenceNumber: 0,
	}
	target := &SessionReconnectResponseMessage{}
	roundTrip(t, original, target)

	if len(target.ServerReconnectToken) != 0 {
		t.Errorf("ServerReconnectToken length = %d, want 0", len(target.ServerReconnectToken))
	}
}

// --- SessionReconnectFailureMessage tests ---

func TestSessionReconnectFailureMessageRoundTrip(t *testing.T) {
	original := &SessionReconnectFailureMessage{
		ReasonCode:  ReconnectFailureSessionNotFound,
		Description: "session not found",
		Language:    "en",
	}
	target := &SessionReconnectFailureMessage{}
	roundTrip(t, original, target)

	if target.ReasonCode != ReconnectFailureSessionNotFound {
		t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, ReconnectFailureSessionNotFound)
	}
	if target.Description != "session not found" {
		t.Errorf("Description = %q, want %q", target.Description, "session not found")
	}
	if target.Language != "en" {
		t.Errorf("Language = %q, want %q", target.Language, "en")
	}
}

func TestSessionReconnectFailureMessageType(t *testing.T) {
	m := &SessionReconnectFailureMessage{}
	if m.MessageType() != 82 {
		t.Errorf("MessageType() = %d, want 82", m.MessageType())
	}
}

func TestSessionReconnectFailureMessageAllReasonCodes(t *testing.T) {
	codes := []SSHReconnectFailureReason{
		ReconnectFailureNone,
		ReconnectFailureUnknownServerFailure,
		ReconnectFailureSessionNotFound,
		ReconnectFailureInvalidClientReconnectToken,
		ReconnectFailureServerDroppedMessages,
		ReconnectFailureUnknownClientFailure,
		ReconnectFailureDifferentServerHostKey,
		ReconnectFailureInvalidServerReconnectToken,
		ReconnectFailureClientDroppedMessages,
	}
	for _, code := range codes {
		original := &SessionReconnectFailureMessage{
			ReasonCode:  code,
			Description: "test",
			Language:    "",
		}
		target := &SessionReconnectFailureMessage{}
		roundTrip(t, original, target)
		if target.ReasonCode != code {
			t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, code)
		}
	}
}

func TestSessionReconnectFailureMessageEmptyPayload(t *testing.T) {
	// Simulate a plain SessionRequestFailure with no reconnect payload
	// by directly creating a buffer with just the type byte
	buf := []byte{MsgNumSessionRequestFailure}
	target := &SessionReconnectFailureMessage{}
	err := ReadMessage(target, buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	// Should default to UnknownClientFailure
	if target.ReasonCode != ReconnectFailureUnknownClientFailure {
		t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, ReconnectFailureUnknownClientFailure)
	}
}

func TestSessionReconnectFailureMessageEmptyDescription(t *testing.T) {
	original := &SessionReconnectFailureMessage{
		ReasonCode:  ReconnectFailureDifferentServerHostKey,
		Description: "",
		Language:    "",
	}
	target := &SessionReconnectFailureMessage{}
	roundTrip(t, original, target)

	if target.ReasonCode != ReconnectFailureDifferentServerHostKey {
		t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, ReconnectFailureDifferentServerHostKey)
	}
	if target.Description != "" {
		t.Errorf("Description = %q, want empty", target.Description)
	}
}

// --- Wire format tests ---

func TestSessionReconnectResponseMessageWireFormat(t *testing.T) {
	token := []byte{0xAA, 0xBB}
	m := &SessionReconnectResponseMessage{
		ServerReconnectToken:       token,
		LastReceivedSequenceNumber: 1,
	}
	buf := m.ToBuffer()

	r := sshio.NewSSHDataReader(buf)

	// type byte
	msgType, _ := r.ReadByte()
	if msgType != 81 {
		t.Errorf("msgType = %d, want 81", msgType)
	}

	// binary: uint32(2) + 2 bytes
	tokenData, _ := r.ReadBinary()
	if !bytes.Equal(tokenData, token) {
		t.Errorf("token = %v, want %v", tokenData, token)
	}

	// uint64(1)
	seq, _ := r.ReadUInt64()
	if seq != 1 {
		t.Errorf("seq = %d, want 1", seq)
	}
}

func TestSessionReconnectRequestMessageWireFormat(t *testing.T) {
	m := &SessionReconnectRequestMessage{
		RequestType:                "session-reconnect@microsoft.com",
		WantReply:                  true,
		ClientReconnectToken:       []byte{0x01},
		LastReceivedSequenceNumber: 5,
	}
	buf := m.ToBuffer()

	r := sshio.NewSSHDataReader(buf)

	// type byte
	msgType, _ := r.ReadByte()
	if msgType != 80 {
		t.Errorf("msgType = %d, want 80", msgType)
	}

	// request type string
	reqType, _ := r.ReadString()
	if reqType != "session-reconnect@microsoft.com" {
		t.Errorf("reqType = %q, want %q", reqType, "session-reconnect@microsoft.com")
	}

	// want reply
	wantReply, _ := r.ReadBoolean()
	if wantReply != true {
		t.Error("wantReply should be true")
	}

	// token
	token, _ := r.ReadBinary()
	if !bytes.Equal(token, []byte{0x01}) {
		t.Errorf("token = %v, want [0x01]", token)
	}

	// sequence number
	seq, _ := r.ReadUInt64()
	if seq != 5 {
		t.Errorf("seq = %d, want 5", seq)
	}
}
