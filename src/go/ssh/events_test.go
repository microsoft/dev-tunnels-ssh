// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

func TestAuthenticatingEventArgsFields(t *testing.T) {
	args := &AuthenticatingEventArgs{
		AuthenticationType: AuthClientPassword,
		Username:           "testuser",
		Password:           "secret",
	}
	if args.AuthenticationType != AuthClientPassword {
		t.Error("unexpected auth type")
	}
	if args.Username != "testuser" {
		t.Error("unexpected username")
	}
	if args.Password != "secret" {
		t.Error("unexpected password")
	}
}

func TestChannelOpeningEventArgsFields(t *testing.T) {
	req := &messages.ChannelOpenMessage{
		ChannelType:   "session",
		SenderChannel: 1,
		MaxWindowSize: 1024,
		MaxPacketSize: 512,
	}
	args := &ChannelOpeningEventArgs{
		Request:         req,
		IsRemoteRequest: true,
	}
	if args.Request.ChannelType != "session" {
		t.Error("unexpected channel type")
	}
	if !args.IsRemoteRequest {
		t.Error("expected remote request")
	}
	if args.FailureReason != messages.ChannelOpenFailureNone {
		t.Error("expected no failure reason by default")
	}
}

func TestSessionClosedEventArgsFields(t *testing.T) {
	args := &SessionClosedEventArgs{
		Reason:  messages.DisconnectConnectionLost,
		Message: "connection lost",
	}
	if args.Reason != messages.DisconnectConnectionLost {
		t.Error("unexpected reason")
	}
	if args.Message != "connection lost" {
		t.Error("unexpected message")
	}
	if args.Err != nil {
		t.Error("expected nil error")
	}
}

func TestChannelClosedEventArgsWithExitStatus(t *testing.T) {
	exitStatus := uint32(11)
	args := &ChannelClosedEventArgs{
		ExitStatus: &exitStatus,
	}
	if args.ExitStatus == nil || *args.ExitStatus != 11 {
		t.Error("expected exit status 11")
	}
}

func TestChannelClosedEventArgsWithSignal(t *testing.T) {
	args := &ChannelClosedEventArgs{
		ExitSignal:   "KILL",
		ErrorMessage: "killed",
	}
	if args.ExitSignal != "KILL" {
		t.Error("unexpected exit signal")
	}
	if args.ErrorMessage != "killed" {
		t.Error("unexpected error message")
	}
}

func TestRequestEventArgsFields(t *testing.T) {
	args := &RequestEventArgs{
		RequestType:  "shell",
		IsAuthorized: true,
	}
	if args.RequestType != "shell" {
		t.Error("unexpected request type")
	}
	if !args.IsAuthorized {
		t.Error("expected authorized")
	}
}
