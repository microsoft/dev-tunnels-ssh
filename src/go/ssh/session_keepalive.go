// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// startKeepAliveTimer starts the keep-alive goroutine if configured.
// Must be called after the session is connected.
func (s *Session) startKeepAliveTimer() {
	interval := s.Config.KeepAliveIntervalSeconds
	if interval <= 0 {
		return
	}

	s.mu.Lock()
	resetCh := make(chan struct{}, 1)
	s.keepAliveResetCh = resetCh
	s.mu.Unlock()

	go s.keepAliveLoop(time.Duration(interval)*time.Second, resetCh)
}

// resetKeepAliveTimer signals the keep-alive goroutine to reset and sets the response flag.
// Called when any message is received from the remote side.
func (s *Session) resetKeepAliveTimer() {
	s.mu.Lock()
	s.keepAliveResponseReceived = true
	ch := s.keepAliveResetCh
	s.mu.Unlock()

	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// keepAliveLoop runs the keep-alive timer in a dedicated goroutine.
// It fires at the configured interval and resets when a message is received.
// The resetCh parameter is captured at startup to avoid data races with close().
func (s *Session) keepAliveLoop(interval time.Duration, resetCh <-chan struct{}) {
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			s.processKeepAlive()
			timer.Reset(interval)

		case <-resetCh:
			// Reset the timer when a message is received.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(interval)

		case <-s.done:
			return
		}
	}
}

// processKeepAlive handles a keep-alive timer tick: checks for responses,
// fires success/failure events, and sends a new keep-alive request.
func (s *Session) processKeepAlive() {
	s.mu.Lock()
	if s.isClosed || !s.isConnected {
		s.mu.Unlock()
		return
	}

	canAccept := s.canAcceptRequests()
	responseReceived := s.keepAliveResponseReceived
	s.keepAliveResponseReceived = false

	var onSucceeded func(int)
	var onFailed func(int)
	var count int

	if canAccept {
		if responseReceived {
			s.keepAliveFailureCount = 0
			s.keepAliveSuccessCount++
			onSucceeded = s.OnKeepAliveSucceeded
			count = s.keepAliveSuccessCount
		} else {
			s.keepAliveSuccessCount = 0
			s.keepAliveFailureCount++
			onFailed = s.OnKeepAliveFailed
			count = s.keepAliveFailureCount
		}
	}
	s.mu.Unlock()

	// Fire callbacks outside the lock.
	if onSucceeded != nil {
		onSucceeded(count)
	}
	if onFailed != nil {
		onFailed(count)
	}

	// Send keep-alive request asynchronously to avoid blocking the timer loop.
	// With unbuffered streams (io.Pipe), a synchronous write could block indefinitely
	// if the remote side's dispatch loop is not reading.
	if canAccept {
		go s.sendKeepAliveRequest()
	}
}

// sendKeepAliveRequest sends a keep-alive request to the remote side.
func (s *Session) sendKeepAliveRequest() {
	msg := &messages.SessionRequestMessage{
		RequestType: ExtensionRequestKeepAlive,
		WantReply:   true,
	}
	_ = s.SendMessage(msg)
}

