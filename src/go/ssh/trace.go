// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

// TraceLevel represents the severity level of a trace event.
type TraceLevel int

const (
	// TraceLevelError indicates an error event.
	TraceLevelError TraceLevel = iota
	// TraceLevelWarning indicates a warning event.
	TraceLevelWarning
	// TraceLevelInfo indicates an informational event.
	TraceLevelInfo
	// TraceLevelVerbose indicates a verbose/debug event.
	TraceLevelVerbose
)

// String returns the string representation of a TraceLevel.
func (l TraceLevel) String() string {
	switch l {
	case TraceLevelError:
		return "error"
	case TraceLevelWarning:
		return "warning"
	case TraceLevelInfo:
		return "info"
	case TraceLevelVerbose:
		return "verbose"
	default:
		return "unknown"
	}
}

// TraceFunc is the function signature for handling SSH trace events.
// level is the severity level of the event.
// eventID is an integer that identifies the type of event (one of the SSHTraceEventID constants).
// message is a human-readable description of the event.
type TraceFunc func(level TraceLevel, eventID int, message string)

// SSHTraceEventID constants match the C#/TypeScript implementations.
// Event IDs use a base of 9000.
const (
	baseEventID = 9000

	// Error / Warning events

	// TraceEventUnknownError is reported for unexpected errors.
	TraceEventUnknownError = baseEventID + 0
	// TraceEventStreamReadError is reported when reading from the stream fails.
	TraceEventStreamReadError = baseEventID + 1
	// TraceEventStreamWriteError is reported when writing to the stream fails.
	TraceEventStreamWriteError = baseEventID + 2
	// TraceEventStreamCloseError is reported when closing the stream fails.
	TraceEventStreamCloseError = baseEventID + 3
	// TraceEventSendMessageFailed is reported when sending a message fails.
	TraceEventSendMessageFailed = baseEventID + 4
	// TraceEventReceiveMessageFailed is reported when receiving a message fails.
	TraceEventReceiveMessageFailed = baseEventID + 5
	// TraceEventHandleMessageFailed is reported when handling a message fails.
	TraceEventHandleMessageFailed = baseEventID + 6
	// TraceEventServerAuthenticationFailed is reported when server authentication fails.
	TraceEventServerAuthenticationFailed = baseEventID + 7
	// TraceEventClientAuthenticationFailed is reported when client authentication fails.
	TraceEventClientAuthenticationFailed = baseEventID + 8
	// TraceEventAuthenticationError is reported for authentication errors.
	TraceEventAuthenticationError = baseEventID + 9
	// TraceEventChannelWindowAdjustFailed is reported when a channel window adjust fails.
	TraceEventChannelWindowAdjustFailed = baseEventID + 10
	// TraceEventSessionReconnectInitFailed is reported when reconnect initialization fails.
	TraceEventSessionReconnectInitFailed = baseEventID + 20
	// TraceEventServerSessionReconnectFailed is reported when server reconnect fails.
	TraceEventServerSessionReconnectFailed = baseEventID + 21
	// TraceEventClientSessionReconnectFailed is reported when client reconnect fails.
	TraceEventClientSessionReconnectFailed = baseEventID + 22
	// TraceEventSessionRequestFailed is reported when a session request fails.
	TraceEventSessionRequestFailed = baseEventID + 23
	// TraceEventChannelRequestFailed is reported when a channel request fails.
	TraceEventChannelRequestFailed = baseEventID + 24
	// TraceEventChannelCloseFailed is reported when closing a channel fails.
	TraceEventChannelCloseFailed = baseEventID + 25
	// TraceEventKeepAliveFailed is reported when a keep-alive fails.
	TraceEventKeepAliveFailed = baseEventID + 62
	// TraceEventKeepAliveResponseNotReceived is reported when keep-alive response times out.
	TraceEventKeepAliveResponseNotReceived = baseEventID + 64

	// Info / Verbose events

	// TraceEventProtocolVersion is reported after version exchange.
	TraceEventProtocolVersion = baseEventID + 100
	// TraceEventSendingMessage is reported when sending a non-channel-data message.
	TraceEventSendingMessage = baseEventID + 101
	// TraceEventReceivingMessage is reported when receiving a non-channel-data message.
	TraceEventReceivingMessage = baseEventID + 102
	// TraceEventSendingChannelData is reported when sending channel data (TraceChannelData only).
	TraceEventSendingChannelData = baseEventID + 103
	// TraceEventReceivingChannelData is reported when receiving channel data (TraceChannelData only).
	TraceEventReceivingChannelData = baseEventID + 104
	// TraceEventSessionEncrypted is reported after key exchange completes and encryption is active.
	TraceEventSessionEncrypted = baseEventID + 110
	// TraceEventSessionAuthenticating is reported when authentication starts.
	TraceEventSessionAuthenticating = baseEventID + 111
	// TraceEventSessionAuthenticated is reported when authentication succeeds.
	TraceEventSessionAuthenticated = baseEventID + 112
	// TraceEventSessionClosing is reported when the session is closing.
	TraceEventSessionClosing = baseEventID + 113
	// TraceEventSessionConnecting is reported when the session is connecting.
	TraceEventSessionConnecting = baseEventID + 114
	// TraceEventChannelOpened is reported when a channel is successfully opened.
	TraceEventChannelOpened = baseEventID + 120
	// TraceEventChannelOpenFailed is reported when a channel open fails.
	TraceEventChannelOpenFailed = baseEventID + 121
	// TraceEventChannelClosed is reported when a channel is closed.
	TraceEventChannelClosed = baseEventID + 123
	// TraceEventSessionDisconnected is reported when the session is disconnected.
	TraceEventSessionDisconnected = baseEventID + 160
	// TraceEventClientSessionReconnecting is reported when a client is reconnecting.
	TraceEventClientSessionReconnecting = baseEventID + 161
	// TraceEventServerSessionReconnecting is reported when a server is reconnecting.
	TraceEventServerSessionReconnecting = baseEventID + 162
	// TraceEventAlgorithmNegotiation is reported during algorithm negotiation.
	TraceEventAlgorithmNegotiation = baseEventID + 170
)
