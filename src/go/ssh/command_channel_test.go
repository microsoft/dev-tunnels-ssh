// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// TestCommandRequestMessageRoundTrip verifies that CommandRequestMessage
// serializes and deserializes correctly (round-trip).
func TestCommandRequestMessageRoundTrip(t *testing.T) {
	original := messages.NewCommandRequestMessage("ls -la /tmp")
	original.RecipientChannel = 42
	original.WantReply = true

	// Serialize.
	buf := original.ToBuffer()

	// Deserialize.
	decoded := &messages.CommandRequestMessage{}
	if err := messages.ReadMessage(decoded, buf); err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if decoded.RecipientChannel != original.RecipientChannel {
		t.Errorf("RecipientChannel: got %d, want %d", decoded.RecipientChannel, original.RecipientChannel)
	}
	if decoded.RequestType != "exec" {
		t.Errorf("RequestType: got %q, want %q", decoded.RequestType, "exec")
	}
	if decoded.WantReply != original.WantReply {
		t.Errorf("WantReply: got %v, want %v", decoded.WantReply, original.WantReply)
	}
	if decoded.Command != original.Command {
		t.Errorf("Command: got %q, want %q", decoded.Command, original.Command)
	}
}

// TestCommandRequestMessageEmptyCommand verifies round-trip with an empty command string.
func TestCommandRequestMessageEmptyCommand(t *testing.T) {
	original := &messages.CommandRequestMessage{
		RecipientChannel: 7,
		RequestType:      "exec",
		WantReply:        false,
		Command:          "",
	}

	buf := original.ToBuffer()

	decoded := &messages.CommandRequestMessage{}
	if err := messages.ReadMessage(decoded, buf); err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if decoded.Command != "" {
		t.Errorf("Command: got %q, want empty string", decoded.Command)
	}
	if decoded.WantReply != false {
		t.Errorf("WantReply: got %v, want false", decoded.WantReply)
	}
}

// TestCommandRequestMessageUnicodeCommand verifies round-trip with Unicode characters.
func TestCommandRequestMessageUnicodeCommand(t *testing.T) {
	original := messages.NewCommandRequestMessage("echo 'héllo wörld' 日本語")
	original.RecipientChannel = 1

	buf := original.ToBuffer()

	decoded := &messages.CommandRequestMessage{}
	if err := messages.ReadMessage(decoded, buf); err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if decoded.Command != original.Command {
		t.Errorf("Command: got %q, want %q", decoded.Command, original.Command)
	}
}

// TestCommandRequestMessageType verifies the message type is MsgNumChannelRequest (98).
func TestCommandRequestMessageType(t *testing.T) {
	msg := messages.NewCommandRequestMessage("test")
	if msg.MessageType() != messages.MsgNumChannelRequest {
		t.Errorf("MessageType: got %d, want %d", msg.MessageType(), messages.MsgNumChannelRequest)
	}
}

// TestCommandRequestMessageBinaryFormat verifies the serialized bytes start with
// message type 98 (channel request) and contain the "exec" request type.
func TestCommandRequestMessageBinaryFormat(t *testing.T) {
	msg := messages.NewCommandRequestMessage("whoami")
	buf := msg.ToBuffer()

	if len(buf) == 0 {
		t.Fatal("ToBuffer returned empty buffer")
	}
	if buf[0] != messages.MsgNumChannelRequest {
		t.Errorf("first byte: got %d, want %d", buf[0], messages.MsgNumChannelRequest)
	}
	// The "exec" string should appear in the buffer.
	if !bytes.Contains(buf, []byte("exec")) {
		t.Error("buffer does not contain 'exec' request type string")
	}
	// The "whoami" command should appear in the buffer.
	if !bytes.Contains(buf, []byte("whoami")) {
		t.Error("buffer does not contain 'whoami' command string")
	}
}

// TestChannelOpenMessageProperty verifies that Channel.OpenMessage() is non-nil
// after the channel is opened, on both client and server sides.
func TestChannelOpenMessageProperty(t *testing.T) {
	clientSession, serverSession := createSessionPair(t, nil)

	// Open channel from client.
	clientCh, err := clientSession.OpenChannelWithType(context.Background(), "test-open-msg")
	if err != nil {
		t.Fatalf("OpenChannelWithType failed: %v", err)
	}

	// Accept channel on server.
	serverCh, err := serverSession.AcceptChannel(context.Background())
	if err != nil {
		t.Fatalf("AcceptChannel failed: %v", err)
	}

	// Client side: OpenMessage should be set.
	if clientCh.OpenMessage() == nil {
		t.Error("client channel OpenMessage is nil")
	} else {
		if clientCh.OpenMessage().ChannelType != "test-open-msg" {
			t.Errorf("client OpenMessage.ChannelType: got %q, want %q",
				clientCh.OpenMessage().ChannelType, "test-open-msg")
		}
	}

	// Server side: OpenMessage should be set.
	if serverCh.OpenMessage() == nil {
		t.Error("server channel OpenMessage is nil")
	} else {
		if serverCh.OpenMessage().ChannelType != "test-open-msg" {
			t.Errorf("server OpenMessage.ChannelType: got %q, want %q",
				serverCh.OpenMessage().ChannelType, "test-open-msg")
		}
	}
}

// TestChannelOpenConfirmationMessageProperty verifies that Channel.OpenConfirmationMessage()
// is non-nil after the channel open is confirmed, on both client and server sides.
func TestChannelOpenConfirmationMessageProperty(t *testing.T) {
	clientSession, serverSession := createSessionPair(t, nil)

	// Open channel from client.
	clientCh, err := clientSession.OpenChannelWithType(context.Background(), "test-confirm-msg")
	if err != nil {
		t.Fatalf("OpenChannelWithType failed: %v", err)
	}

	// Accept channel on server.
	serverCh, err := serverSession.AcceptChannel(context.Background())
	if err != nil {
		t.Fatalf("AcceptChannel failed: %v", err)
	}

	// Client side: OpenConfirmationMessage should be set.
	if clientCh.OpenConfirmationMessage() == nil {
		t.Error("client channel OpenConfirmationMessage is nil")
	} else {
		if clientCh.OpenConfirmationMessage().MaxWindowSize == 0 {
			t.Error("client OpenConfirmationMessage.MaxWindowSize is 0")
		}
	}

	// Server side: OpenConfirmationMessage should be set.
	if serverCh.OpenConfirmationMessage() == nil {
		t.Error("server channel OpenConfirmationMessage is nil")
	} else {
		if serverCh.OpenConfirmationMessage().MaxWindowSize == 0 {
			t.Error("server OpenConfirmationMessage.MaxWindowSize is 0")
		}
	}
}

// TestChannelOpenMessageMatchesChannelProperties verifies that the OpenMessage
// properties are consistent with the Channel's own properties.
func TestChannelOpenMessageMatchesChannelProperties(t *testing.T) {
	clientSession, serverSession := createSessionPair(t, nil)

	clientCh, err := clientSession.OpenChannelWithType(context.Background(), "session")
	if err != nil {
		t.Fatalf("OpenChannelWithType failed: %v", err)
	}

	serverCh, err := serverSession.AcceptChannel(context.Background())
	if err != nil {
		t.Fatalf("AcceptChannel failed: %v", err)
	}

	// Client's open message sender channel should match the client channel ID.
	if clientCh.OpenMessage().SenderChannel != clientCh.ChannelID {
		t.Errorf("client OpenMessage.SenderChannel (%d) != ChannelID (%d)",
			clientCh.OpenMessage().SenderChannel, clientCh.ChannelID)
	}

	// Server's confirmation recipient channel should match the client's channel ID
	// (the remote side's perspective).
	if serverCh.OpenConfirmationMessage().SenderChannel != serverCh.ChannelID {
		t.Errorf("server OpenConfirmationMessage.SenderChannel (%d) != server ChannelID (%d)",
			serverCh.OpenConfirmationMessage().SenderChannel, serverCh.ChannelID)
	}
}
