// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	"testing"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// roundTrip writes a message to a buffer, then reads it back into a new message.
func roundTrip(t *testing.T, original Message, target Message) {
	t.Helper()
	buf := original.ToBuffer()
	if len(buf) == 0 {
		t.Fatal("ToBuffer returned empty buffer")
	}
	if buf[0] != original.MessageType() {
		t.Fatalf("first byte should be message type %d, got %d", original.MessageType(), buf[0])
	}
	err := ReadMessage(target, buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
}

// --- DisconnectMessage tests ---

func TestDisconnectMessageRoundTrip(t *testing.T) {
	original := &DisconnectMessage{
		ReasonCode:  DisconnectByApplication,
		Description: "goodbye",
		Language:    "en",
	}
	target := &DisconnectMessage{}
	roundTrip(t, original, target)

	if target.ReasonCode != DisconnectByApplication {
		t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, DisconnectByApplication)
	}
	if target.Description != "goodbye" {
		t.Errorf("Description = %q, want %q", target.Description, "goodbye")
	}
	if target.Language != "en" {
		t.Errorf("Language = %q, want %q", target.Language, "en")
	}
}

func TestDisconnectMessageEmptyFields(t *testing.T) {
	original := &DisconnectMessage{
		ReasonCode:  DisconnectConnectionLost,
		Description: "",
		Language:    "",
	}
	target := &DisconnectMessage{}
	roundTrip(t, original, target)

	if target.ReasonCode != DisconnectConnectionLost {
		t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, DisconnectConnectionLost)
	}
	if target.Description != "" {
		t.Errorf("Description = %q, want empty", target.Description)
	}
}

func TestDisconnectMessageAllReasonCodes(t *testing.T) {
	codes := []SSHDisconnectReason{
		DisconnectHostNotAllowedToConnect,
		DisconnectProtocolError,
		DisconnectKeyExchangeFailed,
		DisconnectReserved,
		DisconnectMACError,
		DisconnectCompressionError,
		DisconnectServiceNotAvailable,
		DisconnectProtocolVersionNotSupported,
		DisconnectHostKeyNotVerifiable,
		DisconnectConnectionLost,
		DisconnectByApplication,
		DisconnectTooManyConnections,
		DisconnectAuthCancelledByUser,
		DisconnectNoMoreAuthMethodsAvailable,
		DisconnectIllegalUserName,
	}
	for _, code := range codes {
		original := &DisconnectMessage{ReasonCode: code, Description: "test"}
		target := &DisconnectMessage{}
		roundTrip(t, original, target)
		if target.ReasonCode != code {
			t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, code)
		}
	}
}

func TestDisconnectMessageType(t *testing.T) {
	m := &DisconnectMessage{}
	if m.MessageType() != 1 {
		t.Errorf("MessageType() = %d, want 1", m.MessageType())
	}
}

func TestDisconnectMessageUnicodeDescription(t *testing.T) {
	original := &DisconnectMessage{
		ReasonCode:  DisconnectByApplication,
		Description: "connection closed: \u00e9\u00e8\u00ea",
		Language:    "",
	}
	target := &DisconnectMessage{}
	roundTrip(t, original, target)

	if target.Description != original.Description {
		t.Errorf("Description = %q, want %q", target.Description, original.Description)
	}
}

// --- IgnoreMessage tests ---

func TestIgnoreMessageRoundTrip(t *testing.T) {
	original := &IgnoreMessage{}
	target := &IgnoreMessage{}
	roundTrip(t, original, target)
}

func TestIgnoreMessageType(t *testing.T) {
	m := &IgnoreMessage{}
	if m.MessageType() != 2 {
		t.Errorf("MessageType() = %d, want 2", m.MessageType())
	}
}

func TestIgnoreMessageBufferSize(t *testing.T) {
	m := &IgnoreMessage{}
	buf := m.ToBuffer()
	// Ignore message should be exactly 1 byte (just the type)
	if len(buf) != 1 {
		t.Errorf("buffer length = %d, want 1", len(buf))
	}
}

// --- UnimplementedMessage tests ---

func TestUnimplementedMessageRoundTrip(t *testing.T) {
	original := &UnimplementedMessage{SequenceNumber: 42}
	target := &UnimplementedMessage{}
	roundTrip(t, original, target)

	if target.SequenceNumber != 42 {
		t.Errorf("SequenceNumber = %d, want 42", target.SequenceNumber)
	}
}

func TestUnimplementedMessageType(t *testing.T) {
	m := &UnimplementedMessage{}
	if m.MessageType() != 3 {
		t.Errorf("MessageType() = %d, want 3", m.MessageType())
	}
}

func TestUnimplementedMessageMaxSequence(t *testing.T) {
	original := &UnimplementedMessage{SequenceNumber: 0xFFFFFFFF}
	target := &UnimplementedMessage{}
	roundTrip(t, original, target)

	if target.SequenceNumber != 0xFFFFFFFF {
		t.Errorf("SequenceNumber = %d, want %d", target.SequenceNumber, uint32(0xFFFFFFFF))
	}
}

func TestUnimplementedMessageZeroSequence(t *testing.T) {
	original := &UnimplementedMessage{SequenceNumber: 0}
	target := &UnimplementedMessage{}
	roundTrip(t, original, target)

	if target.SequenceNumber != 0 {
		t.Errorf("SequenceNumber = %d, want 0", target.SequenceNumber)
	}
}

// --- DebugMessage tests ---

func TestDebugMessageRoundTrip(t *testing.T) {
	original := &DebugMessage{
		AlwaysDisplay: true,
		Message:       "debug info",
		Language:      "en-US",
	}
	target := &DebugMessage{}
	roundTrip(t, original, target)

	if target.AlwaysDisplay != true {
		t.Error("AlwaysDisplay should be true")
	}
	if target.Message != "debug info" {
		t.Errorf("Message = %q, want %q", target.Message, "debug info")
	}
	if target.Language != "en-US" {
		t.Errorf("Language = %q, want %q", target.Language, "en-US")
	}
}

func TestDebugMessageType(t *testing.T) {
	m := &DebugMessage{}
	if m.MessageType() != 4 {
		t.Errorf("MessageType() = %d, want 4", m.MessageType())
	}
}

func TestDebugMessageAlwaysDisplayFalse(t *testing.T) {
	original := &DebugMessage{
		AlwaysDisplay: false,
		Message:       "quiet debug",
		Language:      "",
	}
	target := &DebugMessage{}
	roundTrip(t, original, target)

	if target.AlwaysDisplay != false {
		t.Error("AlwaysDisplay should be false")
	}
	if target.Message != "quiet debug" {
		t.Errorf("Message = %q, want %q", target.Message, "quiet debug")
	}
}

// --- ServiceRequestMessage tests ---

func TestServiceRequestMessageRoundTrip(t *testing.T) {
	original := &ServiceRequestMessage{ServiceName: "ssh-userauth"}
	target := &ServiceRequestMessage{}
	roundTrip(t, original, target)

	if target.ServiceName != "ssh-userauth" {
		t.Errorf("ServiceName = %q, want %q", target.ServiceName, "ssh-userauth")
	}
}

func TestServiceRequestMessageType(t *testing.T) {
	m := &ServiceRequestMessage{}
	if m.MessageType() != 5 {
		t.Errorf("MessageType() = %d, want 5", m.MessageType())
	}
}

func TestServiceRequestMessageConnection(t *testing.T) {
	original := &ServiceRequestMessage{ServiceName: "ssh-connection"}
	target := &ServiceRequestMessage{}
	roundTrip(t, original, target)

	if target.ServiceName != "ssh-connection" {
		t.Errorf("ServiceName = %q, want %q", target.ServiceName, "ssh-connection")
	}
}

// --- ServiceAcceptMessage tests ---

func TestServiceAcceptMessageRoundTrip(t *testing.T) {
	original := &ServiceAcceptMessage{ServiceName: "ssh-userauth"}
	target := &ServiceAcceptMessage{}
	roundTrip(t, original, target)

	if target.ServiceName != "ssh-userauth" {
		t.Errorf("ServiceName = %q, want %q", target.ServiceName, "ssh-userauth")
	}
}

func TestServiceAcceptMessageType(t *testing.T) {
	m := &ServiceAcceptMessage{}
	if m.MessageType() != 6 {
		t.Errorf("MessageType() = %d, want 6", m.MessageType())
	}
}

// --- ExtensionInfoMessage tests ---

func TestExtensionInfoMessageRoundTripSingle(t *testing.T) {
	original := &ExtensionInfoMessage{
		Extensions: map[string]string{
			"server-sig-algs": "rsa-sha2-256,rsa-sha2-512",
		},
	}
	target := &ExtensionInfoMessage{}
	roundTrip(t, original, target)

	if len(target.Extensions) != 1 {
		t.Fatalf("Extensions length = %d, want 1", len(target.Extensions))
	}
	v, ok := target.Extensions["server-sig-algs"]
	if !ok {
		t.Fatal("missing key 'server-sig-algs'")
	}
	if v != "rsa-sha2-256,rsa-sha2-512" {
		t.Errorf("value = %q, want %q", v, "rsa-sha2-256,rsa-sha2-512")
	}
}

func TestExtensionInfoMessageRoundTripMultiple(t *testing.T) {
	original := &ExtensionInfoMessage{
		Extensions: map[string]string{
			"server-sig-algs":                    "rsa-sha2-256",
			"session-reconnect@microsoft.com":    "true",
			"session-latency@microsoft.com":      "true",
			"open-channel-request@microsoft.com": "true",
		},
	}
	target := &ExtensionInfoMessage{}
	roundTrip(t, original, target)

	if len(target.Extensions) != 4 {
		t.Fatalf("Extensions length = %d, want 4", len(target.Extensions))
	}
	for k, expectedV := range original.Extensions {
		actualV, ok := target.Extensions[k]
		if !ok {
			t.Errorf("missing key %q", k)
			continue
		}
		if actualV != expectedV {
			t.Errorf("Extensions[%q] = %q, want %q", k, actualV, expectedV)
		}
	}
}

func TestExtensionInfoMessageEmpty(t *testing.T) {
	original := &ExtensionInfoMessage{Extensions: map[string]string{}}
	target := &ExtensionInfoMessage{}
	roundTrip(t, original, target)

	if len(target.Extensions) != 0 {
		t.Errorf("Extensions length = %d, want 0", len(target.Extensions))
	}
}

func TestExtensionInfoMessageNil(t *testing.T) {
	original := &ExtensionInfoMessage{Extensions: nil}
	target := &ExtensionInfoMessage{}
	roundTrip(t, original, target)

	if len(target.Extensions) != 0 {
		t.Errorf("Extensions length = %d, want 0", len(target.Extensions))
	}
}

func TestExtensionInfoMessageType(t *testing.T) {
	m := &ExtensionInfoMessage{}
	if m.MessageType() != 7 {
		t.Errorf("MessageType() = %d, want 7", m.MessageType())
	}
}

// --- SessionRequestMessage tests ---

func TestSessionRequestMessageRoundTrip(t *testing.T) {
	original := &SessionRequestMessage{
		RequestType: "keepalive@openssh.com",
		WantReply:   true,
	}
	target := &SessionRequestMessage{}
	roundTrip(t, original, target)

	if target.RequestType != "keepalive@openssh.com" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "keepalive@openssh.com")
	}
	if target.WantReply != true {
		t.Error("WantReply should be true")
	}
}

func TestSessionRequestMessageType(t *testing.T) {
	m := &SessionRequestMessage{}
	if m.MessageType() != 80 {
		t.Errorf("MessageType() = %d, want 80", m.MessageType())
	}
}

func TestSessionRequestMessageNoReply(t *testing.T) {
	original := &SessionRequestMessage{
		RequestType: "tcpip-forward",
		WantReply:   false,
	}
	target := &SessionRequestMessage{}
	roundTrip(t, original, target)

	if target.RequestType != "tcpip-forward" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "tcpip-forward")
	}
	if target.WantReply != false {
		t.Error("WantReply should be false")
	}
}

// --- SessionRequestSuccessMessage tests ---

func TestSessionRequestSuccessMessageRoundTrip(t *testing.T) {
	original := &SessionRequestSuccessMessage{}
	target := &SessionRequestSuccessMessage{}
	roundTrip(t, original, target)
}

func TestSessionRequestSuccessMessageType(t *testing.T) {
	m := &SessionRequestSuccessMessage{}
	if m.MessageType() != 81 {
		t.Errorf("MessageType() = %d, want 81", m.MessageType())
	}
}

func TestSessionRequestSuccessMessageBufferSize(t *testing.T) {
	m := &SessionRequestSuccessMessage{}
	buf := m.ToBuffer()
	if len(buf) != 1 {
		t.Errorf("buffer length = %d, want 1", len(buf))
	}
}

// --- SessionRequestFailureMessage tests ---

func TestSessionRequestFailureMessageRoundTrip(t *testing.T) {
	original := &SessionRequestFailureMessage{}
	target := &SessionRequestFailureMessage{}
	roundTrip(t, original, target)
}

func TestSessionRequestFailureMessageType(t *testing.T) {
	m := &SessionRequestFailureMessage{}
	if m.MessageType() != 82 {
		t.Errorf("MessageType() = %d, want 82", m.MessageType())
	}
}

// --- SessionChannelRequestMessage tests (CRIT-03) ---

func TestSessionChannelRequestTypeBytePresent(t *testing.T) {
	// Verify the embedded ChannelRequestMessage includes its type byte.
	original := &SessionChannelRequestMessage{
		SessionRequestMessage: SessionRequestMessage{
			RequestType: "initial-channel-request@microsoft.com",
			WantReply:   true,
		},
		SenderChannel: 7,
		Request: &ChannelRequestMessage{
			RecipientChannel: 3,
			RequestType:      "exec",
			WantReply:        false,
		},
	}
	buf := original.ToBuffer()
	r := sshio.NewSSHDataReader(buf)

	// Read outer SessionRequestMessage fields.
	outerType, _ := r.ReadByte()
	if outerType != MsgNumSessionRequest {
		t.Fatalf("outer message type = %d, want %d", outerType, MsgNumSessionRequest)
	}
	_, _ = r.ReadString()  // RequestType
	_, _ = r.ReadBoolean() // WantReply

	// Read SenderChannel.
	sc, _ := r.ReadUInt32()
	if sc != 7 {
		t.Fatalf("SenderChannel = %d, want 7", sc)
	}

	// The next byte should be the ChannelRequestMessage type byte.
	innerType, _ := r.ReadByte()
	if innerType != MsgNumChannelRequest {
		t.Fatalf("inner message type = %d, want %d (MsgNumChannelRequest)", innerType, MsgNumChannelRequest)
	}

	// Read remaining ChannelRequestMessage fields.
	rc, _ := r.ReadUInt32()
	if rc != 3 {
		t.Fatalf("RecipientChannel = %d, want 3", rc)
	}
	rt, _ := r.ReadString()
	if rt != "exec" {
		t.Fatalf("RequestType = %q, want %q", rt, "exec")
	}
	wr, _ := r.ReadBoolean()
	if wr != false {
		t.Fatal("WantReply should be false")
	}
}

func TestSessionChannelRequestRoundTrip(t *testing.T) {
	original := &SessionChannelRequestMessage{
		SessionRequestMessage: SessionRequestMessage{
			RequestType: "initial-channel-request@microsoft.com",
			WantReply:   true,
		},
		SenderChannel: 42,
		Request: &ChannelRequestMessage{
			RecipientChannel: 10,
			RequestType:      "shell",
			WantReply:        true,
		},
	}
	buf := original.ToBuffer()

	// Read back: skip the outer message type byte first (ReadMessage does this).
	target := &SessionChannelRequestMessage{}
	err := ReadMessage(target, buf)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if target.RequestType != "initial-channel-request@microsoft.com" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "initial-channel-request@microsoft.com")
	}
	if target.WantReply != true {
		t.Error("WantReply should be true")
	}
	if target.SenderChannel != 42 {
		t.Errorf("SenderChannel = %d, want 42", target.SenderChannel)
	}
	if target.Request == nil {
		t.Fatal("Request is nil")
	}
	if target.Request.RecipientChannel != 10 {
		t.Errorf("Request.RecipientChannel = %d, want 10", target.Request.RecipientChannel)
	}
	if target.Request.RequestType != "shell" {
		t.Errorf("Request.RequestType = %q, want %q", target.Request.RequestType, "shell")
	}
	if target.Request.WantReply != true {
		t.Error("Request.WantReply should be true")
	}
}

// --- Wire format tests ---

func TestDisconnectMessageWireFormat(t *testing.T) {
	m := &DisconnectMessage{
		ReasonCode:  DisconnectByApplication,
		Description: "bye",
		Language:    "",
	}
	buf := m.ToBuffer()

	// Verify wire format manually:
	// byte 1: message type (1)
	// uint32: reason code (11)
	// string: "bye" (uint32 len=3, then "bye")
	// string: "" (uint32 len=0)
	r := sshio.NewSSHDataReader(buf)

	msgType, _ := r.ReadByte()
	if msgType != 1 {
		t.Errorf("msgType = %d, want 1", msgType)
	}

	rc, _ := r.ReadUInt32()
	if rc != 11 {
		t.Errorf("reasonCode = %d, want 11", rc)
	}

	desc, _ := r.ReadString()
	if desc != "bye" {
		t.Errorf("description = %q, want %q", desc, "bye")
	}

	lang, _ := r.ReadString()
	if lang != "" {
		t.Errorf("language = %q, want empty", lang)
	}
}

func TestUnimplementedMessageWireFormat(t *testing.T) {
	m := &UnimplementedMessage{SequenceNumber: 256}
	buf := m.ToBuffer()

	// byte: type(3), uint32: 256
	if len(buf) != 5 {
		t.Fatalf("buffer length = %d, want 5", len(buf))
	}
	if buf[0] != 3 {
		t.Errorf("buf[0] = %d, want 3", buf[0])
	}
	// 256 in big-endian: 0x00 0x00 0x01 0x00
	if buf[1] != 0 || buf[2] != 0 || buf[3] != 1 || buf[4] != 0 {
		t.Errorf("sequence bytes = %v, want [0 0 1 0]", buf[1:5])
	}
}

// --- ReadMessage error tests ---

func TestReadMessageWrongType(t *testing.T) {
	// Write a Disconnect message but try to read as Ignore
	m := &DisconnectMessage{ReasonCode: DisconnectByApplication, Description: "test"}
	buf := m.ToBuffer()

	target := &IgnoreMessage{}
	err := ReadMessage(target, buf)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
	if _, ok := err.(*InvalidMessageTypeError); !ok {
		t.Errorf("expected InvalidMessageTypeError, got %T", err)
	}
}

func TestReadMessageEmptyBuffer(t *testing.T) {
	target := &DisconnectMessage{}
	err := ReadMessage(target, []byte{})
	if err == nil {
		t.Fatal("expected error for empty buffer")
	}
}

func TestReadMessageTruncatedData(t *testing.T) {
	// Just the message type byte with no fields
	target := &DisconnectMessage{}
	err := ReadMessage(target, []byte{1})
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
}

// --- InvalidMessageTypeError test ---

func TestInvalidMessageTypeErrorMessage(t *testing.T) {
	e := &InvalidMessageTypeError{Expected: 1, Actual: 2}
	msg := e.Error()
	if msg != "invalid message type: expected 1, got 2" {
		t.Errorf("error message = %q", msg)
	}
}
