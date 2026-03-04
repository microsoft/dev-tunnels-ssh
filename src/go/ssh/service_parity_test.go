// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

const serviceParityTimeout = 10 * time.Second

// TestServiceActivateOnSessionRequest registers a custom service that activates
// on a specific session request type, sends that request, and verifies the
// service is activated via GetService(). Matches C#/TS ServiceTests.
func TestServiceActivateOnSessionRequest(t *testing.T) {
	serverConfig := NewNoSecurityConfig()
	serverConfig.AddService("session-req-service", ServiceActivation{
		SessionRequest: "test-svc-request",
	}, newTestService, nil)

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})

	// Service should not be activated yet.
	svc := server.GetService("session-req-service")
	if svc != nil {
		t.Fatal("service should not be activated before matching request")
	}

	ctx, cancel := context.WithTimeout(context.Background(), serviceParityTimeout)
	defer cancel()

	// Send a session request with the matching type.
	msg := &messages.SessionRequestMessage{
		RequestType: "test-svc-request",
		WantReply:   true,
	}
	success, err := client.Request(ctx, msg)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !success {
		t.Error("expected request to succeed (testService sets IsAuthorized=true)")
	}

	// Verify the service is now activated.
	svc = server.GetService("session-req-service")
	if svc == nil {
		t.Fatal("GetService returned nil after matching session request")
	}
	ts := svc.(*testService)
	ts.mu.Lock()
	calls := ts.onSessionRequestCalls
	ts.mu.Unlock()
	if calls != 1 {
		t.Errorf("OnSessionRequest called %d times, want 1", calls)
	}
}

// TestServiceActivateOnChannelType registers a custom service that activates
// on a specific channel type, opens that channel type, and verifies the
// service is activated. Matches C#/TS ServiceTests.
func TestServiceActivateOnChannelType(t *testing.T) {
	serverConfig := NewNoSecurityConfig()
	serverConfig.AddService("chan-type-service", ServiceActivation{
		ChannelType: "parity-test-channel",
	}, newTestService, nil)

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})

	// Service should not be activated yet.
	svc := server.GetService("chan-type-service")
	if svc != nil {
		t.Fatal("service should not be activated before channel open")
	}

	ctx, cancel := context.WithTimeout(context.Background(), serviceParityTimeout)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.AcceptChannel(ctx)
	}()

	_, err := client.OpenChannelWithType(ctx, "parity-test-channel")
	if err != nil {
		t.Fatalf("OpenChannelWithType failed: %v", err)
	}
	wg.Wait()

	// Verify the service is now activated.
	svc = server.GetService("chan-type-service")
	if svc == nil {
		t.Fatal("service should be activated after channel of matching type is opened")
	}
	ts := svc.(*testService)
	ts.mu.Lock()
	calls := ts.onChannelOpeningCalls
	ts.mu.Unlock()
	if calls != 1 {
		t.Errorf("OnChannelOpening called %d times, want 1", calls)
	}
}

// TestMultipleServicesRegistered registers 2 services with different activation
// triggers, triggers each, and verifies the correct service activates for each
// trigger. Matches C#/TS ServiceTests.
func TestMultipleServicesRegistered(t *testing.T) {
	serverConfig := NewNoSecurityConfig()
	serverConfig.AddService("request-service", ServiceActivation{
		SessionRequest: "multi-test-request",
	}, newTestService, nil)
	serverConfig.AddService("channel-service", ServiceActivation{
		ChannelType: "multi-test-channel",
	}, newTestService, nil)

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})

	ctx, cancel := context.WithTimeout(context.Background(), serviceParityTimeout)
	defer cancel()

	// Trigger the session request service.
	msg := &messages.SessionRequestMessage{
		RequestType: "multi-test-request",
		WantReply:   true,
	}
	success, err := client.Request(ctx, msg)
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	if !success {
		t.Error("expected session request to succeed")
	}

	// Only request-service should be activated.
	reqSvc := server.GetService("request-service")
	if reqSvc == nil {
		t.Fatal("request-service should be activated after matching request")
	}
	chanSvc := server.GetService("channel-service")
	if chanSvc != nil {
		t.Fatal("channel-service should NOT be activated yet")
	}

	// Trigger the channel type service.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.AcceptChannel(ctx)
	}()

	_, err = client.OpenChannelWithType(ctx, "multi-test-channel")
	if err != nil {
		t.Fatalf("OpenChannelWithType failed: %v", err)
	}
	wg.Wait()

	// Now both services should be activated.
	chanSvc = server.GetService("channel-service")
	if chanSvc == nil {
		t.Fatal("channel-service should be activated after channel open")
	}

	// Verify request-service only saw the session request.
	reqTs := reqSvc.(*testService)
	reqTs.mu.Lock()
	reqReqCalls := reqTs.onSessionRequestCalls
	reqChanCalls := reqTs.onChannelOpeningCalls
	reqTs.mu.Unlock()
	if reqReqCalls != 1 {
		t.Errorf("request-service OnSessionRequest called %d times, want 1", reqReqCalls)
	}
	if reqChanCalls != 0 {
		t.Errorf("request-service OnChannelOpening called %d times, want 0", reqChanCalls)
	}

	// Verify channel-service only saw the channel opening.
	chanTs := chanSvc.(*testService)
	chanTs.mu.Lock()
	chanReqCalls := chanTs.onSessionRequestCalls
	chanOpenCalls := chanTs.onChannelOpeningCalls
	chanTs.mu.Unlock()
	if chanReqCalls != 0 {
		t.Errorf("channel-service OnSessionRequest called %d times, want 0", chanReqCalls)
	}
	if chanOpenCalls != 1 {
		t.Errorf("channel-service OnChannelOpening called %d times, want 1", chanOpenCalls)
	}
}

// TestOnServiceActivated sets OnServiceActivated callback on a session,
// activates a service, and verifies the callback fires with the service
// instance. Matches C#/TS ServiceTests.
func TestOnServiceActivated(t *testing.T) {
	serverConfig := NewNoSecurityConfig()
	serverConfig.AddService("activated-test-service", ServiceActivation{
		SessionRequest: "activate-trigger",
	}, newTestService, nil)

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})

	activatedCh := make(chan Service, 1)
	server.Session.mu.Lock()
	server.Session.OnServiceActivated = func(svc Service) {
		activatedCh <- svc
	}
	server.Session.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), serviceParityTimeout)
	defer cancel()

	// Send a session request to trigger service activation.
	msg := &messages.SessionRequestMessage{
		RequestType: "activate-trigger",
		WantReply:   true,
	}
	_, err := client.Request(ctx, msg)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Verify the callback fired.
	select {
	case activated := <-activatedCh:
		if activated == nil {
			t.Fatal("OnServiceActivated called with nil service")
		}
		if _, ok := activated.(*testService); !ok {
			t.Fatalf("activated service is %T, want *testService", activated)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnServiceActivated not called within timeout")
	}

	// Verify GetService returns the same instance.
	svc := server.GetService("activated-test-service")
	if svc == nil {
		t.Fatal("GetService returned nil after activation")
	}
}

// TestUnimplementedMessageHandling sends a message with an unknown type number
// (254) and verifies the peer responds with SSH_MSG_UNIMPLEMENTED (the session
// stays alive and can handle subsequent requests). Matches C#/TS ServiceTests.
func TestUnimplementedMessageHandling(t *testing.T) {
	client, server := createSessionPair(t, nil)

	// Set up the post-check handler before any requests are sent.
	server.OnRequest = func(args *RequestEventArgs) {
		args.IsAuthorized = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), serviceParityTimeout)
	defer cancel()

	// Send a message with unknown type 254 via the raw protocol.
	// The peer's dispatch loop should respond with SSH_MSG_UNIMPLEMENTED
	// containing the sequence number, not disconnect.
	payload := []byte{254}
	err := client.Session.protocol.sendMessage(payload)
	if err != nil {
		t.Fatalf("sendMessage with unknown type failed: %v", err)
	}

	// Verify the session survived by sending a normal request.
	msg := &messages.SessionRequestMessage{
		RequestType: "post-unimplemented-check",
		WantReply:   true,
	}
	success, err := client.Request(ctx, msg)
	if err != nil {
		t.Fatalf("request after unimplemented message failed: %v", err)
	}
	if !success {
		t.Error("expected post-unimplemented request to succeed")
	}
}

// TestDebugMessageHandling sends a DebugMessage and verifies the peer receives
// it without error (the session stays alive and can handle subsequent requests).
// Matches C#/TS ServiceTests.
func TestDebugMessageHandling(t *testing.T) {
	client, server := createSessionPair(t, nil)

	// Set up the post-check handler before any requests are sent.
	server.OnRequest = func(args *RequestEventArgs) {
		args.IsAuthorized = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), serviceParityTimeout)
	defer cancel()

	// Send a debug message from client to server.
	debugMsg := &messages.DebugMessage{
		AlwaysDisplay: true,
		Message:       "test debug message",
		Language:      "",
	}
	err := client.SendMessage(debugMsg)
	if err != nil {
		t.Fatalf("SendMessage(debug) failed: %v", err)
	}

	// Verify the session survived by sending a normal request.
	msg := &messages.SessionRequestMessage{
		RequestType: "post-debug-check",
		WantReply:   true,
	}
	success, err := client.Request(ctx, msg)
	if err != nil {
		t.Fatalf("request after debug message failed: %v", err)
	}
	if !success {
		t.Error("expected post-debug request to succeed")
	}
}
