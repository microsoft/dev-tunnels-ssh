// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	"bytes"
	"testing"
)

// --- ChannelOpenMessage tests ---

func TestChannelOpenMessageRoundTrip(t *testing.T) {
	original := &ChannelOpenMessage{
		ChannelType:   "session",
		SenderChannel: 0,
		MaxWindowSize: 1048576,
		MaxPacketSize: 32768,
	}
	target := &ChannelOpenMessage{}
	roundTrip(t, original, target)

	if target.ChannelType != "session" {
		t.Errorf("ChannelType = %q, want %q", target.ChannelType, "session")
	}
	if target.SenderChannel != 0 {
		t.Errorf("SenderChannel = %d, want 0", target.SenderChannel)
	}
	if target.MaxWindowSize != 1048576 {
		t.Errorf("MaxWindowSize = %d, want 1048576", target.MaxWindowSize)
	}
	if target.MaxPacketSize != 32768 {
		t.Errorf("MaxPacketSize = %d, want 32768", target.MaxPacketSize)
	}
}

func TestChannelOpenMessageType(t *testing.T) {
	m := &ChannelOpenMessage{}
	if m.MessageType() != 90 {
		t.Errorf("MessageType() = %d, want 90", m.MessageType())
	}
}

func TestChannelOpenMessageCustomType(t *testing.T) {
	original := &ChannelOpenMessage{
		ChannelType:   "direct-tcpip",
		SenderChannel: 42,
		MaxWindowSize: 2097152,
		MaxPacketSize: 65536,
	}
	target := &ChannelOpenMessage{}
	roundTrip(t, original, target)

	if target.ChannelType != "direct-tcpip" {
		t.Errorf("ChannelType = %q, want %q", target.ChannelType, "direct-tcpip")
	}
	if target.SenderChannel != 42 {
		t.Errorf("SenderChannel = %d, want 42", target.SenderChannel)
	}
	if target.MaxWindowSize != 2097152 {
		t.Errorf("MaxWindowSize = %d, want 2097152", target.MaxWindowSize)
	}
	if target.MaxPacketSize != 65536 {
		t.Errorf("MaxPacketSize = %d, want 65536", target.MaxPacketSize)
	}
}

func TestChannelOpenMessageMaxValues(t *testing.T) {
	original := &ChannelOpenMessage{
		ChannelType:   "x",
		SenderChannel: 0xFFFFFFFF,
		MaxWindowSize: 0xFFFFFFFF,
		MaxPacketSize: 0xFFFFFFFF,
	}
	target := &ChannelOpenMessage{}
	roundTrip(t, original, target)

	if target.SenderChannel != 0xFFFFFFFF {
		t.Errorf("SenderChannel = %d, want %d", target.SenderChannel, uint32(0xFFFFFFFF))
	}
}

// --- ChannelOpenConfirmationMessage tests ---

func TestChannelOpenConfirmationMessageRoundTrip(t *testing.T) {
	original := &ChannelOpenConfirmationMessage{
		RecipientChannel: 0,
		SenderChannel:    1,
		MaxWindowSize:    1048576,
		MaxPacketSize:    32768,
	}
	target := &ChannelOpenConfirmationMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 0 {
		t.Errorf("RecipientChannel = %d, want 0", target.RecipientChannel)
	}
	if target.SenderChannel != 1 {
		t.Errorf("SenderChannel = %d, want 1", target.SenderChannel)
	}
	if target.MaxWindowSize != 1048576 {
		t.Errorf("MaxWindowSize = %d, want 1048576", target.MaxWindowSize)
	}
	if target.MaxPacketSize != 32768 {
		t.Errorf("MaxPacketSize = %d, want 32768", target.MaxPacketSize)
	}
}

func TestChannelOpenConfirmationMessageType(t *testing.T) {
	m := &ChannelOpenConfirmationMessage{}
	if m.MessageType() != 91 {
		t.Errorf("MessageType() = %d, want 91", m.MessageType())
	}
}

// --- ChannelOpenFailureMessage tests ---

func TestChannelOpenFailureMessageRoundTrip(t *testing.T) {
	original := &ChannelOpenFailureMessage{
		RecipientChannel: 5,
		ReasonCode:       ChannelOpenFailureConnectFailed,
		Description:      "connection refused",
		Language:         "en",
	}
	target := &ChannelOpenFailureMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 5 {
		t.Errorf("RecipientChannel = %d, want 5", target.RecipientChannel)
	}
	if target.ReasonCode != ChannelOpenFailureConnectFailed {
		t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, ChannelOpenFailureConnectFailed)
	}
	if target.Description != "connection refused" {
		t.Errorf("Description = %q, want %q", target.Description, "connection refused")
	}
	if target.Language != "en" {
		t.Errorf("Language = %q, want %q", target.Language, "en")
	}
}

func TestChannelOpenFailureMessageType(t *testing.T) {
	m := &ChannelOpenFailureMessage{}
	if m.MessageType() != 92 {
		t.Errorf("MessageType() = %d, want 92", m.MessageType())
	}
}

func TestChannelOpenFailureMessageAllReasonCodes(t *testing.T) {
	codes := []SSHChannelOpenFailureReason{
		ChannelOpenFailureAdministrativelyProhibited,
		ChannelOpenFailureConnectFailed,
		ChannelOpenFailureUnknownChannelType,
		ChannelOpenFailureResourceShortage,
	}
	for _, code := range codes {
		original := &ChannelOpenFailureMessage{
			RecipientChannel: 0,
			ReasonCode:       code,
			Description:      "test",
			Language:         "",
		}
		target := &ChannelOpenFailureMessage{}
		roundTrip(t, original, target)
		if target.ReasonCode != code {
			t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, code)
		}
	}
}

func TestChannelOpenFailureMessageEmptyFields(t *testing.T) {
	original := &ChannelOpenFailureMessage{
		RecipientChannel: 0,
		ReasonCode:       ChannelOpenFailureNone,
		Description:      "",
		Language:         "",
	}
	target := &ChannelOpenFailureMessage{}
	roundTrip(t, original, target)

	if target.ReasonCode != ChannelOpenFailureNone {
		t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, ChannelOpenFailureNone)
	}
	if target.Description != "" {
		t.Errorf("Description = %q, want empty", target.Description)
	}
}

// --- ChannelWindowAdjustMessage tests ---

func TestChannelWindowAdjustMessageRoundTrip(t *testing.T) {
	original := &ChannelWindowAdjustMessage{
		RecipientChannel: 3,
		BytesToAdd:       524288,
	}
	target := &ChannelWindowAdjustMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 3 {
		t.Errorf("RecipientChannel = %d, want 3", target.RecipientChannel)
	}
	if target.BytesToAdd != 524288 {
		t.Errorf("BytesToAdd = %d, want 524288", target.BytesToAdd)
	}
}

func TestChannelWindowAdjustMessageType(t *testing.T) {
	m := &ChannelWindowAdjustMessage{}
	if m.MessageType() != 93 {
		t.Errorf("MessageType() = %d, want 93", m.MessageType())
	}
}

func TestChannelWindowAdjustMessageZeroBytes(t *testing.T) {
	original := &ChannelWindowAdjustMessage{
		RecipientChannel: 0,
		BytesToAdd:       0,
	}
	target := &ChannelWindowAdjustMessage{}
	roundTrip(t, original, target)

	if target.BytesToAdd != 0 {
		t.Errorf("BytesToAdd = %d, want 0", target.BytesToAdd)
	}
}

// --- ChannelDataMessage tests ---

func TestChannelDataMessageRoundTrip(t *testing.T) {
	data := []byte("hello, world!")
	original := &ChannelDataMessage{
		RecipientChannel: 7,
		Data:             data,
	}
	target := &ChannelDataMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 7 {
		t.Errorf("RecipientChannel = %d, want 7", target.RecipientChannel)
	}
	if !bytes.Equal(target.Data, data) {
		t.Errorf("Data = %v, want %v", target.Data, data)
	}
}

func TestChannelDataMessageType(t *testing.T) {
	m := &ChannelDataMessage{}
	if m.MessageType() != 94 {
		t.Errorf("MessageType() = %d, want 94", m.MessageType())
	}
}

func TestChannelDataMessageEmptyData(t *testing.T) {
	original := &ChannelDataMessage{
		RecipientChannel: 0,
		Data:             []byte{},
	}
	target := &ChannelDataMessage{}
	roundTrip(t, original, target)

	if len(target.Data) != 0 {
		t.Errorf("Data length = %d, want 0", len(target.Data))
	}
}

func TestChannelDataMessageBinaryData(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	original := &ChannelDataMessage{
		RecipientChannel: 1,
		Data:             data,
	}
	target := &ChannelDataMessage{}
	roundTrip(t, original, target)

	if !bytes.Equal(target.Data, data) {
		t.Error("Data mismatch for binary data")
	}
}

func TestChannelDataMessageLargeData(t *testing.T) {
	data := make([]byte, 32768) // Max packet size
	for i := range data {
		data[i] = byte(i % 251)
	}
	original := &ChannelDataMessage{
		RecipientChannel: 0,
		Data:             data,
	}
	target := &ChannelDataMessage{}
	roundTrip(t, original, target)

	if !bytes.Equal(target.Data, data) {
		t.Error("Data mismatch for large data")
	}
}

// --- ChannelExtendedDataMessage tests ---

func TestChannelExtendedDataMessageRoundTrip(t *testing.T) {
	data := []byte("error output")
	original := &ChannelExtendedDataMessage{
		RecipientChannel: 2,
		DataTypeCode:     1, // SSH_EXTENDED_DATA_STDERR
		Data:             data,
	}
	target := &ChannelExtendedDataMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 2 {
		t.Errorf("RecipientChannel = %d, want 2", target.RecipientChannel)
	}
	if target.DataTypeCode != 1 {
		t.Errorf("DataTypeCode = %d, want 1", target.DataTypeCode)
	}
	if !bytes.Equal(target.Data, data) {
		t.Errorf("Data = %v, want %v", target.Data, data)
	}
}

func TestChannelExtendedDataMessageType(t *testing.T) {
	m := &ChannelExtendedDataMessage{}
	if m.MessageType() != 95 {
		t.Errorf("MessageType() = %d, want 95", m.MessageType())
	}
}

// --- ChannelEofMessage tests ---

func TestChannelEofMessageRoundTrip(t *testing.T) {
	original := &ChannelEofMessage{RecipientChannel: 10}
	target := &ChannelEofMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 10 {
		t.Errorf("RecipientChannel = %d, want 10", target.RecipientChannel)
	}
}

func TestChannelEofMessageType(t *testing.T) {
	m := &ChannelEofMessage{}
	if m.MessageType() != 96 {
		t.Errorf("MessageType() = %d, want 96", m.MessageType())
	}
}

// --- ChannelCloseMessage tests ---

func TestChannelCloseMessageRoundTrip(t *testing.T) {
	original := &ChannelCloseMessage{RecipientChannel: 99}
	target := &ChannelCloseMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 99 {
		t.Errorf("RecipientChannel = %d, want 99", target.RecipientChannel)
	}
}

func TestChannelCloseMessageType(t *testing.T) {
	m := &ChannelCloseMessage{}
	if m.MessageType() != 97 {
		t.Errorf("MessageType() = %d, want 97", m.MessageType())
	}
}

// --- ChannelRequestMessage tests ---

func TestChannelRequestMessageRoundTrip(t *testing.T) {
	original := &ChannelRequestMessage{
		RecipientChannel: 4,
		RequestType:      "shell",
		WantReply:        true,
	}
	target := &ChannelRequestMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 4 {
		t.Errorf("RecipientChannel = %d, want 4", target.RecipientChannel)
	}
	if target.RequestType != "shell" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "shell")
	}
	if target.WantReply != true {
		t.Error("WantReply should be true")
	}
}

func TestChannelRequestMessageType(t *testing.T) {
	m := &ChannelRequestMessage{}
	if m.MessageType() != 98 {
		t.Errorf("MessageType() = %d, want 98", m.MessageType())
	}
}

func TestChannelRequestMessageNoReply(t *testing.T) {
	original := &ChannelRequestMessage{
		RecipientChannel: 0,
		RequestType:      "exec",
		WantReply:        false,
	}
	target := &ChannelRequestMessage{}
	roundTrip(t, original, target)

	if target.WantReply != false {
		t.Error("WantReply should be false")
	}
	if target.RequestType != "exec" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "exec")
	}
}

func TestChannelRequestMessageSubsystem(t *testing.T) {
	original := &ChannelRequestMessage{
		RecipientChannel: 1,
		RequestType:      "subsystem",
		WantReply:        true,
	}
	target := &ChannelRequestMessage{}
	roundTrip(t, original, target)

	if target.RequestType != "subsystem" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "subsystem")
	}
}

func TestChannelRequestMessageWithPayload(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	original := &ChannelRequestMessage{
		RecipientChannel: 7,
		RequestType:      "custom-request",
		WantReply:        true,
		Payload:          payload,
	}
	target := &ChannelRequestMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 7 {
		t.Errorf("RecipientChannel = %d, want 7", target.RecipientChannel)
	}
	if target.RequestType != "custom-request" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "custom-request")
	}
	if target.WantReply != true {
		t.Error("WantReply should be true")
	}
	if !bytes.Equal(target.Payload, payload) {
		t.Errorf("Payload = %v, want %v", target.Payload, payload)
	}
}

func TestChannelRequestMessageEmptyPayload(t *testing.T) {
	original := &ChannelRequestMessage{
		RecipientChannel: 0,
		RequestType:      "shell",
		WantReply:        true,
	}
	target := &ChannelRequestMessage{}
	roundTrip(t, original, target)

	if len(target.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(target.Payload))
	}
}

// --- ChannelSignalMessage tests ---

func TestChannelSignalMessageExitStatus(t *testing.T) {
	original := &ChannelSignalMessage{
		RecipientChannel: 5,
		RequestType:      "exit-status",
		WantReply:        false,
		ExitStatus:       11,
	}
	target := &ChannelSignalMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 5 {
		t.Errorf("RecipientChannel = %d, want 5", target.RecipientChannel)
	}
	if target.RequestType != "exit-status" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "exit-status")
	}
	if target.ExitStatus != 11 {
		t.Errorf("ExitStatus = %d, want 11", target.ExitStatus)
	}
}

func TestChannelSignalMessageSignal(t *testing.T) {
	original := &ChannelSignalMessage{
		RecipientChannel: 0,
		RequestType:      "signal",
		WantReply:        false,
		Signal:           "TERM",
	}
	target := &ChannelSignalMessage{}
	roundTrip(t, original, target)

	if target.Signal != "TERM" {
		t.Errorf("Signal = %q, want %q", target.Signal, "TERM")
	}
}

func TestChannelSignalMessageExitSignal(t *testing.T) {
	original := &ChannelSignalMessage{
		RecipientChannel: 1,
		RequestType:      "exit-signal",
		WantReply:        false,
		ExitSignal:       "test",
		ErrorMessage:     "something went wrong",
	}
	target := &ChannelSignalMessage{}
	roundTrip(t, original, target)

	if target.ExitSignal != "test" {
		t.Errorf("ExitSignal = %q, want %q", target.ExitSignal, "test")
	}
	if target.ErrorMessage != "something went wrong" {
		t.Errorf("ErrorMessage = %q, want %q", target.ErrorMessage, "something went wrong")
	}
}

func TestChannelSignalMessageType(t *testing.T) {
	m := &ChannelSignalMessage{}
	if m.MessageType() != 98 {
		t.Errorf("MessageType() = %d, want 98", m.MessageType())
	}
}

func TestChannelSignalMessageExitStatusZero(t *testing.T) {
	original := &ChannelSignalMessage{
		RecipientChannel: 0,
		RequestType:      "exit-status",
		WantReply:        false,
		ExitStatus:       0,
	}
	target := &ChannelSignalMessage{}
	roundTrip(t, original, target)

	if target.ExitStatus != 0 {
		t.Errorf("ExitStatus = %d, want 0", target.ExitStatus)
	}
}

// --- ChannelSuccessMessage tests ---

func TestChannelSuccessMessageRoundTrip(t *testing.T) {
	original := &ChannelSuccessMessage{RecipientChannel: 15}
	target := &ChannelSuccessMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 15 {
		t.Errorf("RecipientChannel = %d, want 15", target.RecipientChannel)
	}
}

func TestChannelSuccessMessageType(t *testing.T) {
	m := &ChannelSuccessMessage{}
	if m.MessageType() != 99 {
		t.Errorf("MessageType() = %d, want 99", m.MessageType())
	}
}

// --- ChannelFailureMessage tests ---

func TestChannelFailureMessageRoundTrip(t *testing.T) {
	original := &ChannelFailureMessage{RecipientChannel: 20}
	target := &ChannelFailureMessage{}
	roundTrip(t, original, target)

	if target.RecipientChannel != 20 {
		t.Errorf("RecipientChannel = %d, want 20", target.RecipientChannel)
	}
}

func TestChannelFailureMessageType(t *testing.T) {
	m := &ChannelFailureMessage{}
	if m.MessageType() != 100 {
		t.Errorf("MessageType() = %d, want 100", m.MessageType())
	}
}

// --- Wire format tests ---

func TestChannelOpenMessageWireFormat(t *testing.T) {
	m := &ChannelOpenMessage{
		ChannelType:   "session",
		SenderChannel: 0,
		MaxWindowSize: 1048576,
		MaxPacketSize: 32768,
	}
	buf := m.ToBuffer()

	// Verify: type(90), string("session"), uint32(0), uint32(1048576), uint32(32768)
	if buf[0] != 90 {
		t.Errorf("buf[0] = %d, want 90", buf[0])
	}
	// String "session" has length 7
	// buf[1..4] = uint32(7), buf[5..11] = "session"
	if buf[1] != 0 || buf[2] != 0 || buf[3] != 0 || buf[4] != 7 {
		t.Errorf("string length bytes = %v, want [0 0 0 7]", buf[1:5])
	}
	if string(buf[5:12]) != "session" {
		t.Errorf("channel type = %q, want %q", string(buf[5:12]), "session")
	}
}

func TestChannelEofMessageWireFormat(t *testing.T) {
	m := &ChannelEofMessage{RecipientChannel: 1}
	buf := m.ToBuffer()

	// type(96), uint32(1) = 5 bytes total
	if len(buf) != 5 {
		t.Fatalf("buffer length = %d, want 5", len(buf))
	}
	if buf[0] != 96 {
		t.Errorf("buf[0] = %d, want 96", buf[0])
	}
	// 1 in big-endian: 0x00 0x00 0x00 0x01
	if buf[1] != 0 || buf[2] != 0 || buf[3] != 0 || buf[4] != 1 {
		t.Errorf("channel bytes = %v, want [0 0 0 1]", buf[1:5])
	}
}

func TestChannelCloseMessageWireFormat(t *testing.T) {
	m := &ChannelCloseMessage{RecipientChannel: 256}
	buf := m.ToBuffer()

	// type(97), uint32(256) = 5 bytes total
	if len(buf) != 5 {
		t.Fatalf("buffer length = %d, want 5", len(buf))
	}
	if buf[0] != 97 {
		t.Errorf("buf[0] = %d, want 97", buf[0])
	}
	// 256 in big-endian: 0x00 0x00 0x01 0x00
	if buf[1] != 0 || buf[2] != 0 || buf[3] != 1 || buf[4] != 0 {
		t.Errorf("channel bytes = %v, want [0 0 1 0]", buf[1:5])
	}
}

func TestChannelSuccessMessageWireFormat(t *testing.T) {
	m := &ChannelSuccessMessage{RecipientChannel: 0}
	buf := m.ToBuffer()

	// type(99), uint32(0) = 5 bytes total
	if len(buf) != 5 {
		t.Fatalf("buffer length = %d, want 5", len(buf))
	}
	if buf[0] != 99 {
		t.Errorf("buf[0] = %d, want 99", buf[0])
	}
}

func TestChannelFailureMessageWireFormat(t *testing.T) {
	m := &ChannelFailureMessage{RecipientChannel: 0}
	buf := m.ToBuffer()

	// type(100), uint32(0) = 5 bytes total
	if len(buf) != 5 {
		t.Fatalf("buffer length = %d, want 5", len(buf))
	}
	if buf[0] != 100 {
		t.Errorf("buf[0] = %d, want 100", buf[0])
	}
}

// --- ReadMessage error tests for channel messages ---

func TestChannelOpenMessageWrongType(t *testing.T) {
	// Write a ChannelClose message but try to read as ChannelOpen
	m := &ChannelCloseMessage{RecipientChannel: 0}
	buf := m.ToBuffer()

	target := &ChannelOpenMessage{}
	err := ReadMessage(target, buf)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
	if _, ok := err.(*InvalidMessageTypeError); !ok {
		t.Errorf("expected InvalidMessageTypeError, got %T", err)
	}
}
