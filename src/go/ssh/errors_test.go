// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"errors"
	"fmt"
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

func TestConnectionErrorBasic(t *testing.T) {
	err := &ConnectionError{
		Reason: messages.DisconnectConnectionLost,
		Msg:    "connection lost",
	}
	if err.Error() != "connection lost (reason: 10)" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
	if err.Unwrap() != nil {
		t.Error("expected nil unwrap")
	}
}

func TestConnectionErrorWithWrapped(t *testing.T) {
	inner := fmt.Errorf("network failure")
	err := &ConnectionError{
		Reason: messages.DisconnectProtocolError,
		Msg:    "connection failed",
		Err:    inner,
	}
	if !errors.Is(err, inner) {
		t.Error("expected errors.Is to find inner error")
	}
	if err.Unwrap() != inner {
		t.Error("expected Unwrap to return inner error")
	}
}

func TestConnectionErrorDefaultMessage(t *testing.T) {
	err := &ConnectionError{Reason: messages.DisconnectByApplication}
	msg := err.Error()
	if msg != "SSH connection error (reason: 11)" {
		t.Errorf("unexpected error message: %s", msg)
	}
}

func TestConnectionErrorNoReason(t *testing.T) {
	err := &ConnectionError{Msg: "something happened"}
	if err.Error() != "something happened" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestChannelErrorBasic(t *testing.T) {
	err := &ChannelError{
		Reason: messages.ChannelOpenFailureConnectFailed,
		Msg:    "channel connect failed",
	}
	if err.Error() != "channel connect failed (reason: 2)" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestChannelErrorWithWrapped(t *testing.T) {
	inner := fmt.Errorf("resource issue")
	err := &ChannelError{
		Reason: messages.ChannelOpenFailureResourceShortage,
		Msg:    "channel error",
		Err:    inner,
	}
	if !errors.Is(err, inner) {
		t.Error("expected errors.Is to find inner error")
	}
}

func TestChannelErrorDefaultMessage(t *testing.T) {
	err := &ChannelError{Reason: messages.ChannelOpenFailureAdministrativelyProhibited}
	if err.Error() != "SSH channel error (reason: 1)" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestReconnectErrorBasic(t *testing.T) {
	err := &ReconnectError{
		Reason: messages.ReconnectFailureSessionNotFound,
		Msg:    "session not found",
	}
	if err.Error() != "session not found (reason: 2)" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestReconnectErrorWithWrapped(t *testing.T) {
	inner := fmt.Errorf("token invalid")
	err := &ReconnectError{
		Reason: messages.ReconnectFailureInvalidClientReconnectToken,
		Msg:    "reconnect failed",
		Err:    inner,
	}
	if !errors.Is(err, inner) {
		t.Error("expected errors.Is to find inner error")
	}
}

func TestReconnectErrorDefaultMessage(t *testing.T) {
	err := &ReconnectError{Reason: messages.ReconnectFailureDifferentServerHostKey}
	if err.Error() != "SSH reconnect error (reason: 102)" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrSessionClosed", ErrSessionClosed, "session is closed"},
		{"ErrClosed", ErrClosed, "resource is closed"},
		{"ErrNotConnected", ErrNotConnected, "session is not connected"},
		{"ErrNotAuthenticated", ErrNotAuthenticated, "session is not authenticated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.msg {
				t.Errorf("expected %q, got %q", tt.msg, tt.err.Error())
			}
		})
	}
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	sentinels := []error{ErrSessionClosed, ErrClosed, ErrNotConnected, ErrNotAuthenticated}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel errors %d and %d should not be equal", i, j)
			}
		}
	}
}

func TestErrorsIsWithWrappedSentinel(t *testing.T) {
	wrapped := &ConnectionError{
		Msg: "session closed",
		Err: ErrSessionClosed,
	}
	if !errors.Is(wrapped, ErrSessionClosed) {
		t.Error("expected errors.Is to find ErrSessionClosed through ConnectionError")
	}
}
