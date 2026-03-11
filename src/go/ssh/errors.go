// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"errors"
	"fmt"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// Sentinel errors for common SSH session states.
var (
	ErrSessionClosed  = errors.New("session is closed")
	ErrClosed = errors.New("resource is closed")
	ErrNotConnected   = errors.New("session is not connected")
	ErrNotAuthenticated = errors.New("session is not authenticated")
)

// ConnectionError represents an SSH connection error with a disconnect reason.
type ConnectionError struct {
	Reason messages.SSHDisconnectReason
	Msg    string
	Err    error
}

func (e *ConnectionError) Error() string {
	msg := e.Msg
	if msg == "" {
		msg = "SSH connection error"
	}
	if e.Reason != 0 {
		msg = fmt.Sprintf("%s (reason: %d)", msg, e.Reason)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

func (e *ConnectionError) Unwrap() error {
	return e.Err
}

// ChannelError represents an SSH channel error with a failure reason.
type ChannelError struct {
	Reason messages.SSHChannelOpenFailureReason
	Msg    string
	Err    error
}

func (e *ChannelError) Error() string {
	msg := e.Msg
	if msg == "" {
		msg = "SSH channel error"
	}
	if e.Reason != 0 {
		msg = fmt.Sprintf("%s (reason: %d)", msg, e.Reason)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

func (e *ChannelError) Unwrap() error {
	return e.Err
}

// ReconnectError represents an SSH reconnection error with a failure reason.
type ReconnectError struct {
	Reason messages.SSHReconnectFailureReason
	Msg    string
	Err    error
}

func (e *ReconnectError) Error() string {
	msg := e.Msg
	if msg == "" {
		msg = "SSH reconnect error"
	}
	if e.Reason != 0 {
		msg = fmt.Sprintf("%s (reason: %d)", msg, e.Reason)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

func (e *ReconnectError) Unwrap() error {
	return e.Err
}
