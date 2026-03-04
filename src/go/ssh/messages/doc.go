// Copyright (c) Microsoft Corporation. All rights reserved.

// Package messages defines SSH protocol message types and their serialization.
//
// Each SSH message type (defined in RFC 4253, 4252, 4254) is represented as a
// struct implementing the [Message] interface, which supports reading from and
// writing to SSH binary wire format via the sshio package.
//
// Message types are organized by protocol layer:
//   - Transport: [DisconnectMessage], [IgnoreMessage], [UnimplementedMessage], [DebugMessage]
//   - Key exchange: [KeyExchangeInitMessage], [KeyExchangeDhInitMessage], [KeyExchangeDhReplyMessage], [NewKeysMessage]
//   - Authentication: [AuthenticationRequestMessage], [AuthenticationSuccessMessage], [AuthenticationFailureMessage]
//   - Connection: [ChannelOpenMessage], [ChannelDataMessage], [ChannelCloseMessage], etc.
//   - Session: [SessionRequestMessage], [SessionRequestSuccessMessage], [SessionRequestFailureMessage]
//   - Extensions: [ExtensionInfoMessage], [SessionReconnectRequestMessage]
//
// Use [ReadMessage] to deserialize a message from a byte buffer and
// [Message.ToBuffer] to serialize a message for transmission.
package messages
