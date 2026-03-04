// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// pipeRequestItem represents a session request to be forwarded through a pipe.
type pipeRequestItem struct {
	requestType string
	wantReply   bool
}

// PipeSession pipes two sessions together bidirectionally. When a session request
// arrives on one session, it is forwarded to the other. When a channel is opened
// remotely on one session, a corresponding channel is opened on the other session
// with the same type, and the two channels are piped together (including data,
// extended data, EOF, and close events). When one session closes, the other is
// closed too.
//
// PipeSession blocks until one session closes or the context is cancelled.
func PipeSession(ctx context.Context, sessionA, sessionB *Session) error {
	var (
		once   sync.Once
		doneCh = make(chan struct{})
	)
	signalDone := func() {
		once.Do(func() { close(doneCh) })
	}

	pipeCtx, pipeCancel := context.WithCancel(ctx)

	// Forward close events bidirectionally.
	installSessionCloseForwarder(sessionA, sessionB, signalDone)
	installSessionCloseForwarder(sessionB, sessionA, signalDone)

	// Forward session requests bidirectionally (one goroutine per direction
	// to preserve FIFO response ordering).
	installSessionRequestForwarder(sessionA, sessionB, pipeCtx)
	installSessionRequestForwarder(sessionB, sessionA, pipeCtx)

	// Forward channel opens bidirectionally.
	go pipeSessionChannels(pipeCtx, sessionA, sessionB)
	go pipeSessionChannels(pipeCtx, sessionB, sessionA)

	// Wait for pipe to end.
	select {
	case <-doneCh:
		pipeCancel()
		return nil
	case <-ctx.Done():
		pipeCancel()
		return ctx.Err()
	}
}

// installSessionCloseForwarder installs an OnClosed handler on `from` that closes
// `to` and signals the pipe is done.
func installSessionCloseForwarder(from, to *Session, signalDone func()) {
	from.mu.Lock()
	prev := from.OnClosed
	from.OnClosed = func(args *SessionClosedEventArgs) {
		signalDone()
		_ = to.Close()
		if prev != nil {
			prev(args)
		}
	}
	from.mu.Unlock()
}

// installSessionRequestForwarder sets up request forwarding from `from` to `to`.
// Requests arriving on `from` are forwarded to `to`, and the response is sent
// back through `from`. A dedicated goroutine processes forwarded requests
// sequentially to preserve SSH FIFO response ordering.
func installSessionRequestForwarder(from, to *Session, ctx context.Context) {
	reqCh := make(chan pipeRequestItem, 64)

	from.mu.Lock()
	from.OnRequest = func(args *RequestEventArgs) {
		var wantReply bool
		if reqMsg, ok := args.Request.(*messages.SessionRequestMessage); ok {
			wantReply = reqMsg.WantReply
		}
		args.ResponseHandled = true
		select {
		case reqCh <- pipeRequestItem{requestType: args.RequestType, wantReply: wantReply}:
		default:
			// Buffer full; send failure if reply expected.
			if wantReply {
				_ = from.SendMessage(&messages.SessionRequestFailureMessage{})
			}
		}
	}
	from.mu.Unlock()

	go func() {
		for {
			select {
			case req := <-reqCh:
				fwdMsg := &messages.SessionRequestMessage{
					RequestType: req.requestType,
					WantReply:   req.wantReply,
				}
				success, err := to.Request(ctx, fwdMsg)
				if req.wantReply {
					var reply messages.Message
					if err != nil || !success {
						reply = &messages.SessionRequestFailureMessage{}
					} else {
						reply = &messages.SessionRequestSuccessMessage{}
					}
					_ = from.SendMessage(reply)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// pipeSessionChannels accepts channels from `from` and opens corresponding
// channels on `to`, then pipes each pair together.
func pipeSessionChannels(ctx context.Context, from, to *Session) {
	for {
		ch, err := from.AcceptChannel(ctx)
		if err != nil {
			return
		}
		go func(sourceCh *Channel) {
			targetCh, err := to.OpenChannelWithType(ctx, sourceCh.ChannelType)
			if err != nil {
				_ = sourceCh.Close()
				return
			}
			_ = sourceCh.Pipe(ctx, targetCh)
		}(ch)
	}
}
