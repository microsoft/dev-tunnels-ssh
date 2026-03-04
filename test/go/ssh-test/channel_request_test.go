// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

const requestTestTimeout = 5 * time.Second

// --- Channel request tests ---

func TestChannelRequestSuccess(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	pair.ServerSession.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
		e.Channel.OnRequest = func(args *ssh.RequestEventArgs) {
			args.IsAuthorized = true
		}
	}

	clientCh, _ := pair.OpenChannel(ctx)

	reqMsg := &messages.ChannelRequestMessage{
		RequestType: "test",
		WantReply:   true,
	}

	success, err := clientCh.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if !success {
		t.Error("expected request to succeed")
	}
}

func TestChannelRequestFailure(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	pair.ServerSession.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
		e.Channel.OnRequest = func(args *ssh.RequestEventArgs) {
			args.IsAuthorized = false
		}
	}

	clientCh, _ := pair.OpenChannel(ctx)

	reqMsg := &messages.ChannelRequestMessage{
		RequestType: "test",
		WantReply:   true,
	}

	success, err := clientCh.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("request returned error: %v", err)
	}
	if success {
		t.Error("expected request to fail")
	}
}

func TestChannelRequestEarlyCancellation(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	pair.ServerSession.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
		e.Channel.OnRequest = func(args *ssh.RequestEventArgs) {
			args.IsAuthorized = true
		}
	}

	// Accept channel on server side.
	var serverCh *ssh.Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = pair.ServerSession.AcceptChannel(ctx)
	}()

	clientCh, err := pair.ClientSession.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("open channel failed: %v", err)
	}
	wg.Wait()
	_ = serverCh

	// Cancel before sending.
	cancelCtx, cancelFn := context.WithCancel(ctx)
	cancelFn()

	reqMsg := &messages.ChannelRequestMessage{
		RequestType: "test",
		WantReply:   true,
	}

	_, reqErr := clientCh.Request(cancelCtx, reqMsg)
	if reqErr == nil {
		t.Fatal("expected cancellation error")
	}
	if !errors.Is(reqErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", reqErr)
	}

	// Session should still be open.
	if pair.ClientSession.IsClosed() {
		t.Error("client session should not be closed")
	}
	if pair.ServerSession.IsClosed() {
		t.Error("server session should not be closed")
	}

	// Open another channel to verify session is still functional.
	var clientCh2 *ssh.Channel
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh2, _ = pair.ClientSession.OpenChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		_, _ = pair.ServerSession.AcceptChannel(ctx)
	}()
	wg.Wait()

	reqMsg2 := &messages.ChannelRequestMessage{
		RequestType: "test",
		WantReply:   true,
	}
	success, err := clientCh2.Request(ctx, reqMsg2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if !success {
		t.Error("expected second request to succeed")
	}
}

func TestChannelRequestLateCancellation(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	cancelCtx, cancelFn := context.WithCancel(ctx)

	pair.ServerSession.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
		e.Channel.OnRequest = func(args *ssh.RequestEventArgs) {
			// Cancel the context when the server receives the request.
			// On fast in-memory streams this races with the response:
			// either cancellation or success may be observed by the client.
			cancelFn()
			args.IsAuthorized = true
		}
	}

	clientCh, _ := pair.OpenChannel(ctx)

	reqMsg := &messages.ChannelRequestMessage{
		RequestType: "test",
		WantReply:   true,
	}

	success, reqErr := clientCh.Request(cancelCtx, reqMsg)
	// Either outcome is valid since cancellation and response race:
	// - context.Canceled means cancellation won
	// - success=true, err=nil means the response arrived first
	if reqErr != nil && !errors.Is(reqErr, context.Canceled) {
		t.Fatalf("expected context.Canceled or success, got: %v", reqErr)
	}
	if reqErr == nil && !success {
		t.Fatal("expected success when no error returned")
	}

	// Session should still be open regardless of which branch won.
	if pair.ClientSession.IsClosed() {
		t.Error("client session should not be closed")
	}
	if pair.ServerSession.IsClosed() {
		t.Error("server session should not be closed")
	}

	// Open another channel to verify session is still functional.
	var clientCh2 *ssh.Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh2, _ = pair.ClientSession.OpenChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		_, _ = pair.ServerSession.AcceptChannel(ctx)
	}()
	wg.Wait()

	reqMsg2 := &messages.ChannelRequestMessage{
		RequestType: "test",
		WantReply:   true,
	}
	success2, err := clientCh2.Request(ctx, reqMsg2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if !success2 {
		t.Error("expected second request to succeed")
	}
}

func TestChannelRequestHandlerClosesChannel(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	pair.ServerSession.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
		ch := e.Channel
		ch.OnRequest = func(args *ssh.RequestEventArgs) {
			args.IsAuthorized = true
			if args.RequestType == "close" {
				go func() {
					_ = ch.Close()
				}()
			}
		}
	}

	clientCh, _ := pair.OpenChannel(ctx)

	closedCh := make(chan struct{})
	clientCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		close(closedCh)
	}

	closeReq := &messages.ChannelRequestMessage{
		RequestType: "close",
		WantReply:   true,
	}

	// The request may return true or false depending on timing, but should not error.
	_, err := clientCh.Request(ctx, closeReq)
	if err != nil {
		t.Fatalf("request returned error: %v", err)
	}

	// The channel should be closed shortly after.
	select {
	case <-closedCh:
	case <-time.After(requestTestTimeout):
		t.Fatal("timed out waiting for channel close")
	}

	if !clientCh.IsClosed() {
		t.Error("client channel should be closed")
	}

	// Open another channel to verify session is still functional.
	var clientCh2 *ssh.Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh2, _ = pair.ClientSession.OpenChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		_, _ = pair.ServerSession.AcceptChannel(ctx)
	}()
	wg.Wait()

	testReq := &messages.ChannelRequestMessage{
		RequestType: "test",
		WantReply:   true,
	}
	success, err := clientCh2.Request(ctx, testReq)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if !success {
		t.Error("expected second request to succeed")
	}

	if pair.ClientSession.IsClosed() {
		t.Error("client session should not be closed")
	}
	if pair.ServerSession.IsClosed() {
		t.Error("server session should not be closed")
	}
}

func TestChannelRequestHandlerException(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	pair.ServerSession.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
		e.Channel.OnRequest = func(args *ssh.RequestEventArgs) {
			args.IsAuthorized = true
			if args.RequestType == "test" {
				panic("test exception")
			}
		}
	}

	clientCh, _ := pair.OpenChannel(ctx)

	testReq := &messages.ChannelRequestMessage{
		RequestType: "test",
		WantReply:   true,
	}

	success, err := clientCh.Request(ctx, testReq)
	if err != nil {
		t.Fatalf("request returned error: %v", err)
	}
	if success {
		t.Error("expected request to fail when handler panics")
	}
}

// --- Channel close with status/signal tests ---

func TestCloseChannelWithStatus(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	closedCh := make(chan *ssh.ChannelClosedEventArgs, 1)
	clientCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		closedCh <- args
	}

	if err := serverCh.CloseWithStatus(ctx, 11); err != nil {
		t.Fatalf("close with status failed: %v", err)
	}

	select {
	case args := <-closedCh:
		if args == nil {
			t.Fatal("closed event args should not be nil")
		}
		if args.ExitStatus == nil {
			t.Fatal("exit status should not be nil")
		}
		if *args.ExitStatus != 11 {
			t.Errorf("exit status = %d, want 11", *args.ExitStatus)
		}
	case <-time.After(requestTestTimeout):
		t.Fatal("timed out waiting for close event")
	}
}

func TestCloseChannelWithSignal(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	closedCh := make(chan *ssh.ChannelClosedEventArgs, 1)
	clientCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		closedCh <- args
	}

	if err := serverCh.CloseWithSignal(ctx, "test", "message"); err != nil {
		t.Fatalf("close with signal failed: %v", err)
	}

	select {
	case args := <-closedCh:
		if args == nil {
			t.Fatal("closed event args should not be nil")
		}
		if args.ExitSignal != "test" {
			t.Errorf("exit signal = %q, want %q", args.ExitSignal, "test")
		}
		if args.ErrorMessage != "message" {
			t.Errorf("error message = %q, want %q", args.ErrorMessage, "message")
		}
	case <-time.After(requestTestTimeout):
		t.Fatal("timed out waiting for close event")
	}
}

// --- Session close propagation tests ---

func TestCloseSessionClosesChannel(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, _ := pair.OpenChannel(ctx)

	closedCh := make(chan *ssh.ChannelClosedEventArgs, 1)
	clientCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		closedCh <- args
	}

	pair.ClientSession.CloseWithReason(ctx, messages.DisconnectByApplication, "test")

	select {
	case args := <-closedCh:
		if args == nil {
			t.Fatal("closed event args should not be nil")
		}
		var connErr *ssh.ConnectionError
		if !errors.As(args.Err, &connErr) {
			t.Fatalf("expected ConnectionError, got: %T", args.Err)
		}
		if connErr.Reason != messages.DisconnectByApplication {
			t.Errorf("disconnect reason = %d, want %d", connErr.Reason, messages.DisconnectByApplication)
		}
	case <-time.After(requestTestTimeout):
		t.Fatal("timed out waiting for close event")
	}
}

func TestCloseSessionClosesChannelWithException(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, _ := pair.OpenChannel(ctx)

	closedCh := make(chan *ssh.ChannelClosedEventArgs, 1)
	clientCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		closedCh <- args
	}

	testErr := fmt.Errorf("test error")
	pair.ClientSession.CloseWithError(messages.DisconnectProtocolError, "test", testErr)

	select {
	case args := <-closedCh:
		if args == nil {
			t.Fatal("closed event args should not be nil")
		}
		if args.Err != testErr {
			t.Errorf("expected test error, got: %v", args.Err)
		}
	case <-time.After(requestTestTimeout):
		t.Fatal("timed out waiting for close event")
	}
}

// --- Bilateral close tests ---

func TestCloseServerChannel(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	closedCh := make(chan *ssh.ChannelClosedEventArgs, 1)
	clientCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		closedCh <- args
	}

	if err := serverCh.Close(); err != nil {
		t.Fatalf("close server channel failed: %v", err)
	}

	select {
	case args := <-closedCh:
		if args == nil {
			t.Fatal("closed event args should not be nil")
		}
		if args.ExitStatus != nil {
			t.Error("exit status should be nil")
		}
		if args.ExitSignal != "" {
			t.Error("exit signal should be empty")
		}
		if args.Err != nil {
			t.Errorf("error should be nil, got: %v", args.Err)
		}
	case <-time.After(requestTestTimeout):
		t.Fatal("timed out waiting for close event")
	}
}

func TestCloseClientChannel(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	closedCh := make(chan *ssh.ChannelClosedEventArgs, 1)
	serverCh.OnClosed = func(args *ssh.ChannelClosedEventArgs) {
		closedCh <- args
	}

	if err := clientCh.Close(); err != nil {
		t.Fatalf("close client channel failed: %v", err)
	}

	select {
	case args := <-closedCh:
		if args == nil {
			t.Fatal("closed event args should not be nil")
		}
		if args.ExitStatus != nil {
			t.Error("exit status should be nil")
		}
		if args.ExitSignal != "" {
			t.Error("exit signal should be empty")
		}
		if args.Err != nil {
			t.Errorf("error should be nil, got: %v", args.Err)
		}
	case <-time.After(requestTestTimeout):
		t.Fatal("timed out waiting for close event")
	}
}

// --- Unknown channel message handling tests ---

func TestUnknownChannelDataIsIgnored(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	// Set up request handler.
	serverCh.OnRequest = func(args *ssh.RequestEventArgs) {
		args.IsAuthorized = true
	}

	// Verify session works with a channel request.
	reqMsg := &messages.ChannelRequestMessage{
		RequestType: "test",
		WantReply:   true,
	}
	success, err := clientCh.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("initial request failed: %v", err)
	}
	if !success {
		t.Error("initial request should succeed")
	}

	// Send data to an invalid channel ID. This should be silently ignored.
	invalidDataMsg := &messages.ChannelDataMessage{
		RecipientChannel: 99,
		Data:             make([]byte, 16),
	}
	if err := pair.ServerSession.SendMessage(invalidDataMsg); err != nil {
		t.Fatalf("send invalid data failed: %v", err)
	}

	// Also send from client side.
	invalidDataMsg2 := &messages.ChannelDataMessage{
		RecipientChannel: 99,
		Data:             make([]byte, 16),
	}
	if err := pair.ClientSession.SendMessage(invalidDataMsg2); err != nil {
		t.Fatalf("send invalid data from client failed: %v", err)
	}

	// Give time for messages to be processed.
	time.Sleep(100 * time.Millisecond)

	if pair.ServerSession.IsClosed() {
		t.Error("server session should not be closed")
	}
	if pair.ClientSession.IsClosed() {
		t.Error("client session should not be closed")
	}
}

func TestUnknownChannelEofIsIgnored(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	_, _ = pair.OpenChannel(ctx)

	// Send EOF to an invalid channel ID.
	invalidEofMsg := &messages.ChannelEofMessage{
		RecipientChannel: 99,
	}
	if err := pair.ServerSession.SendMessage(invalidEofMsg); err != nil {
		t.Fatalf("send invalid eof failed: %v", err)
	}
	if err := pair.ClientSession.SendMessage(invalidEofMsg); err != nil {
		t.Fatalf("send invalid eof from client failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if pair.ServerSession.IsClosed() {
		t.Error("server session should not be closed")
	}
	if pair.ClientSession.IsClosed() {
		t.Error("client session should not be closed")
	}
}

func TestUnknownChannelAdjustWindowIsIgnored(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	_, _ = pair.OpenChannel(ctx)

	// Send WindowAdjust to an invalid channel ID.
	invalidAdjustMsg := &messages.ChannelWindowAdjustMessage{
		RecipientChannel: 99,
		BytesToAdd:       1,
	}
	if err := pair.ServerSession.SendMessage(invalidAdjustMsg); err != nil {
		t.Fatalf("send invalid adjust failed: %v", err)
	}
	if err := pair.ClientSession.SendMessage(invalidAdjustMsg); err != nil {
		t.Fatalf("send invalid adjust from client failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if pair.ServerSession.IsClosed() {
		t.Error("server session should not be closed")
	}
	if pair.ClientSession.IsClosed() {
		t.Error("client session should not be closed")
	}
}

// --- Open channel cancellation tests ---

func TestOpenChannelCancelByOpener(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Cancel immediately.
	cancelCtx, cancelFn := context.WithCancel(ctx)
	cancelFn()

	_, err := pair.ClientSession.OpenChannel(cancelCtx)
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestOpenChannelCancelByAcceptor(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	pair.ServerSession.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
		e.FailureReason = messages.ChannelOpenFailureConnectFailed
		e.FailureDescription = "OpenChannelCancelByAcceptor"
	}

	_, err := pair.ClientSession.OpenChannel(ctx)
	if err == nil {
		t.Fatal("expected channel error")
	}

	var channelErr *ssh.ChannelError
	if !errors.As(err, &channelErr) {
		t.Fatalf("expected ChannelError, got: %T (%v)", err, err)
	}
	if channelErr.Reason != messages.ChannelOpenFailureConnectFailed {
		t.Errorf("failure reason = %d, want %d", channelErr.Reason, messages.ChannelOpenFailureConnectFailed)
	}
}

// Note: C# has OpenChannelWithMultipleRequests which tests overlapping requests
// where the first handler blocks until the second arrives. This relies on C#'s
// async request handler pattern (ResponseTask) which allows the message processing
// loop to continue while a handler awaits. In Go, request handlers are synchronous
// and block the message loop, so this specific test pattern is a feature gap.
