// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// Pipe relays data bidirectionally between this channel and the target channel.
// When one channel closes, the other is also closed. Pipe blocks until one of the
// channels is closed.
//
// All handlers are installed synchronously in the calling goroutine before any
// events can be missed. Close handlers are installed atomically (read old + write
// new under a single lock) to prevent a race where the channel closes between
// snapshotting the old handler and installing the new one.
func (c *Channel) Pipe(ctx context.Context, target *Channel) error {
	var (
		once           sync.Once
		doneCh         = make(chan struct{})
		closeForwardFn func()
	)

	closeForwardFn = func() {
		once.Do(func() {
			close(doneCh)
		})
	}

	// Forward data from c to target.
	c.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		if err := target.Send(ctx, buf); err != nil {
			// Send failed — close the pipe to signal the error.
			closeForwardFn()
			return
		}
		c.AdjustWindow(uint32(len(data)))
	})

	// Forward data from target to c.
	target.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		if err := c.Send(ctx, buf); err != nil {
			// Send failed — close the pipe to signal the error.
			closeForwardFn()
			return
		}
		target.AdjustWindow(uint32(len(data)))
	})

	// Forward extended data from c to target.
	c.SetExtendedDataReceivedHandler(func(dataType SSHExtendedDataType, data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		if err := target.SendExtendedData(ctx, dataType, buf); err != nil {
			closeForwardFn()
			return
		}
		c.AdjustWindow(uint32(len(data)))
	})

	// Forward extended data from target to c.
	target.SetExtendedDataReceivedHandler(func(dataType SSHExtendedDataType, data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		if err := c.SendExtendedData(ctx, dataType, buf); err != nil {
			closeForwardFn()
			return
		}
		target.AdjustWindow(uint32(len(data)))
	})

	// Forward EOF from c to target.
	c.SetEofHandler(func() {
		_ = target.Send(ctx, nil)
	})

	// Forward EOF from target to c.
	target.SetEofHandler(func() {
		_ = c.Send(ctx, nil)
	})

	// Forward close from c to target.
	// Atomically snapshot the previous handler and install the new one under a
	// single lock so that no close event can slip through the gap.
	c.mu.Lock()
	prevOnClosedC := c.OnClosed
	c.OnClosed = func(args *ChannelClosedEventArgs) {
		forwardChannelClose(ctx, target, args)
		closeForwardFn()
		if prevOnClosedC != nil {
			prevOnClosedC(args)
		}
	}
	cAlreadyDisposed := c.disposed
	c.mu.Unlock()

	// Forward close from target to c.
	target.mu.Lock()
	prevOnClosedTarget := target.OnClosed
	target.OnClosed = func(args *ChannelClosedEventArgs) {
		forwardChannelClose(ctx, c, args)
		closeForwardFn()
		if prevOnClosedTarget != nil {
			prevOnClosedTarget(args)
		}
	}
	targetAlreadyDisposed := target.disposed
	target.mu.Unlock()

	// Forward channel requests from c to target.
	// Handlers run in the per-channel request goroutine, so blocking on
	// target.Request() is safe and won't stall the dispatch loop.
	// The original message (including type-specific payload) is forwarded
	// with only RecipientChannel updated — matching C#'s PipeAsync behavior.
	c.SetRequestHandler(func(args *RequestEventArgs) {
		reqMsg, ok := args.Request.(*messages.ChannelRequestMessage)
		if !ok {
			return
		}
		fwdMsg := &messages.ChannelRequestMessage{
			RequestType: reqMsg.RequestType,
			WantReply:   reqMsg.WantReply,
			Payload:     reqMsg.Payload,
		}
		success, err := target.Request(ctx, fwdMsg)
		if err == nil {
			args.IsAuthorized = success
		}
	})

	// Forward channel requests from target to c.
	target.SetRequestHandler(func(args *RequestEventArgs) {
		reqMsg, ok := args.Request.(*messages.ChannelRequestMessage)
		if !ok {
			return
		}
		fwdMsg := &messages.ChannelRequestMessage{
			RequestType: reqMsg.RequestType,
			WantReply:   reqMsg.WantReply,
			Payload:     reqMsg.Payload,
		}
		success, err := c.Request(ctx, fwdMsg)
		if err == nil {
			args.IsAuthorized = success
		}
	})

	// If either channel was already disposed before we installed the handlers,
	// fire the pipe completion signal now (the event already fired and won't
	// call our handler).
	if cAlreadyDisposed || targetAlreadyDisposed {
		closeForwardFn()
	}

	// Wait for pipe to end.
	select {
	case <-doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// forwardChannelClose closes the target channel with the same exit status/signal
// as the source channel. Uses the provided context for cancellation.
func forwardChannelClose(ctx context.Context, target *Channel, args *ChannelClosedEventArgs) {
	if args == nil {
		_ = target.Close()
		return
	}

	if args.ExitSignal != "" {
		_ = target.CloseWithSignal(ctx, args.ExitSignal, args.ErrorMessage)
	} else if args.ExitStatus != nil {
		_ = target.CloseWithStatus(ctx, *args.ExitStatus)
	} else {
		_ = target.Close()
	}
}
