// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// Progress represents connection progress events reported during session lifecycle.
// These match the C#/TS Progress enum values.
type Progress int

const (
	// ProgressOpeningSSHSessionConnection is reported when starting a new SSH session connection.
	ProgressOpeningSSHSessionConnection Progress = iota
	// ProgressOpenedSSHSessionConnection is reported after the SSH session connection is fully established.
	ProgressOpenedSSHSessionConnection
	// ProgressStartingProtocolVersionExchange is reported when starting the protocol version exchange.
	ProgressStartingProtocolVersionExchange
	// ProgressCompletedProtocolVersionExchange is reported after the protocol version exchange completes.
	ProgressCompletedProtocolVersionExchange
	// ProgressStartingKeyExchange is reported when starting the key exchange.
	ProgressStartingKeyExchange
	// ProgressCompletedKeyExchange is reported after the key exchange completes.
	ProgressCompletedKeyExchange
	// ProgressStartingSessionAuthentication is reported when starting session authentication.
	ProgressStartingSessionAuthentication
	// ProgressCompletedSessionAuthentication is reported after session authentication completes.
	ProgressCompletedSessionAuthentication
)

// AuthenticatingEventArgs contains arguments for session authentication events.
type AuthenticatingEventArgs struct {
	AuthenticationType AuthenticationType
	Username           string
	Password           string
	PublicKey       KeyPair
	ClientHostname  string
	ClientUsername  string
	InfoRequest     *messages.AuthenticationInfoRequestMessage
	InfoResponse    *messages.AuthenticationInfoResponseMessage
	Ctx             context.Context

	// AuthenticationResult should be set by the event handler.
	// A non-nil value indicates successful authentication.
	AuthenticationResult interface{}
}

// ChannelOpeningEventArgs contains arguments for channel opening events.
type ChannelOpeningEventArgs struct {
	Request            *messages.ChannelOpenMessage
	Channel            *Channel
	IsRemoteRequest    bool
	FailureReason      messages.SSHChannelOpenFailureReason
	FailureDescription string
	Ctx                context.Context

	// Payload contains the raw message payload bytes.
	// Services can use this to parse extended fields beyond the base ChannelOpenMessage.
	Payload []byte
}

// SessionClosedEventArgs contains arguments for session closed events.
type SessionClosedEventArgs struct {
	Reason  messages.SSHDisconnectReason
	Message string
	Err     error
}

// ChannelClosedEventArgs contains arguments for channel closed events.
type ChannelClosedEventArgs struct {
	ExitStatus *uint32
	ExitSignal string
	ErrorMessage string
	Err        error
}

// RequestEventArgs contains arguments for session or channel request events.
type RequestEventArgs struct {
	RequestType string
	Request     messages.Message
	IsAuthorized bool
	Ctx         context.Context

	// Principal holds the authenticated identity from the session.
	// This is populated from Session.Principal when the request is dispatched.
	Principal interface{}

	// Payload contains the raw message payload bytes.
	// Services can use this to parse extended fields beyond the base message.
	Payload []byte

	// ResponseMessage, if set, will be sent instead of the plain success message
	// when IsAuthorized is true. This allows services to send custom response data
	// (e.g., allocated port in port forwarding).
	ResponseMessage messages.Message

	// ResponseHandled indicates the service has already sent the response.
	// When true, the session will not send any automatic response.
	ResponseHandled bool
}
