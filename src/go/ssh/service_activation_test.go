// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

// testService is a minimal Service implementation for testing service activation.
type testService struct {
	session               *Session
	config                interface{}
	onSessionRequestCalls int
	onChannelOpeningCalls int
	onChannelRequestCalls int
	disposed              bool
	mu                    sync.Mutex
}

func (s *testService) OnSessionRequest(args *RequestEventArgs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onSessionRequestCalls++
	args.IsAuthorized = true
}

func (s *testService) OnChannelOpening(args *ChannelOpeningEventArgs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChannelOpeningCalls++
}

func (s *testService) OnChannelRequest(channel *Channel, args *RequestEventArgs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChannelRequestCalls++
}

func (s *testService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disposed = true
	return nil
}

func newTestService(session *Session, config interface{}) Service {
	return &testService{session: session, config: config}
}

// dropWriteStream wraps an io.ReadWriteCloser and can be configured to silently
// drop all writes, simulating a network where the peer's responses never arrive.
type dropWriteStream struct {
	io.ReadWriteCloser
	mu         sync.Mutex
	dropWrites bool
}

func (d *dropWriteStream) Write(p []byte) (int, error) {
	d.mu.Lock()
	drop := d.dropWrites
	d.mu.Unlock()
	if drop {
		return len(p), nil
	}
	return d.ReadWriteCloser.Write(p)
}

func (d *dropWriteStream) setDropWrites(v bool) {
	d.mu.Lock()
	d.dropWrites = v
	d.mu.Unlock()
}

// TestServiceActivatedByServiceRequest verifies that a service registered with a
// ServiceRequest activation trigger is activated when the client sends a service
// request for that name, and is returned by GetService.
func TestServiceActivatedByServiceRequest(t *testing.T) {
	serverConfig := NewNoSecurityConfig()
	serverConfig.AddService("test-service", ServiceActivation{
		ServiceRequest: "test-service",
	}, newTestService, nil)

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})

	// The test service should not be activated yet (no one requested it).
	svc := server.GetService("test-service")
	if svc != nil {
		t.Fatal("test-service should not be activated before being requested")
	}

	// Client sends a service request for "test-service".
	// The server will activate the service and respond with ServiceAccept.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.RequestServiceContext(ctx, "test-service")
	if err != nil {
		t.Fatalf("RequestServiceContext failed: %v", err)
	}

	// Verify the service is now activated on the server.
	svc = server.GetService("test-service")
	if svc == nil {
		t.Fatal("GetService returned nil after service request")
	}
	ts, ok := svc.(*testService)
	if !ok {
		t.Fatalf("service is %T, want *testService", svc)
	}
	if ts.session == nil {
		t.Error("testService.session should not be nil")
	}
}

// TestServiceActivatedByChannelType verifies that a service registered with a
// ChannelType activation trigger is activated when a channel of that type is opened.
func TestServiceActivatedByChannelType(t *testing.T) {
	serverConfig := NewNoSecurityConfig()
	serverConfig.AddService("channel-test-service", ServiceActivation{
		ChannelType: "test-channel",
	}, newTestService, nil)

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})

	// Service should not be activated yet.
	svc := server.GetService("channel-test-service")
	if svc != nil {
		t.Fatal("service should not be activated before channel open")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Open a channel with the triggering type from the client.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.AcceptChannel(ctx)
	}()

	_, err := client.OpenChannelWithType(ctx, "test-channel")
	if err != nil {
		t.Fatalf("OpenChannelWithType failed: %v", err)
	}
	wg.Wait()

	// Now the service should be activated on the server side.
	svc = server.GetService("channel-test-service")
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

// TestOnServiceActivatedCallbackFires verifies that the OnServiceActivated callback
// is invoked when a service is activated for the first time, and not on subsequent
// activation calls.
func TestOnServiceActivatedCallbackFires(t *testing.T) {
	serverConfig := NewNoSecurityConfig()
	serverConfig.AddService("callback-test-service", ServiceActivation{
		ChannelType: "callback-test",
	}, newTestService, nil)

	_, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})

	activatedCh := make(chan Service, 2)
	server.Session.mu.Lock()
	server.Session.OnServiceActivated = func(svc Service) {
		activatedCh <- svc
	}
	server.Session.mu.Unlock()

	// Manually activate the service.
	svc := server.ActivateService("callback-test-service")
	if svc == nil {
		t.Fatal("ActivateService returned nil")
	}

	// Verify callback fired.
	select {
	case activated := <-activatedCh:
		if activated == nil {
			t.Fatal("OnServiceActivated called with nil service")
		}
		if _, ok := activated.(*testService); !ok {
			t.Fatalf("activated service is %T, want *testService", activated)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnServiceActivated not called within timeout")
	}

	// Activate again — should return existing instance.
	svc2 := server.ActivateService("callback-test-service")
	if svc2 != svc {
		t.Error("second ActivateService should return same instance")
	}

	// Callback should NOT fire again for duplicate activation.
	select {
	case <-activatedCh:
		t.Error("OnServiceActivated should not fire for duplicate activation")
	case <-time.After(200 * time.Millisecond):
		// Good — no duplicate callback.
	}
}

// TestKeepAliveSucceeded verifies that when keep-alive is enabled and the peer is
// responsive, OnKeepAliveSucceeded fires with a non-negative count.
func TestKeepAliveSucceeded(t *testing.T) {
	clientConfig := NewNoSecurityConfig()
	clientConfig.KeepAliveIntervalSeconds = 1

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: clientConfig,
	})

	successCh := make(chan int, 5)
	client.Session.mu.Lock()
	client.Session.OnKeepAliveSucceeded = func(count int) {
		successCh <- count
	}
	client.Session.mu.Unlock()

	// Wait for at least one keep-alive success.
	select {
	case count := <-successCh:
		if count < 1 {
			t.Errorf("success count = %d, want >= 1", count)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for OnKeepAliveSucceeded")
	}

	// Wait for a second success to verify consecutive counting.
	select {
	case count := <-successCh:
		if count < 2 {
			t.Errorf("second success count = %d, want >= 2", count)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for second OnKeepAliveSucceeded")
	}

	_ = server // keep server alive for keep-alive responses
}

// TestKeepAliveFailed verifies that when the peer stops responding to keep-alive
// requests, OnKeepAliveFailed fires.
func TestKeepAliveFailed(t *testing.T) {
	clientConfig := NewNoSecurityConfig()
	clientConfig.KeepAliveIntervalSeconds = 1

	clientStream, serverStream := duplexPipe()

	// Wrap the server stream so we can drop its writes later.
	// When writes are dropped, the server's responses never reach the client,
	// simulating a network black hole where the client's dispatch loop blocks
	// on read while the keep-alive timer continues to fire.
	serverDropStream := &dropWriteStream{ReadWriteCloser: serverStream}

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewServerSession(NewNoSecurityConfig())
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var clientErr, serverErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = client.Connect(ctx, clientStream)
	}()
	go func() {
		defer wg.Done()
		serverErr = server.Connect(ctx, serverDropStream)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server connect failed: %v", serverErr)
	}

	failureCh := make(chan int, 5)
	client.Session.mu.Lock()
	client.Session.OnKeepAliveFailed = func(count int) {
		failureCh <- count
	}
	client.Session.mu.Unlock()

	// Start dropping server writes. The server still reads and processes
	// keep-alive requests, but its responses are silently discarded.
	// The client's dispatch loop blocks on read (no data arriving),
	// while the keep-alive timer fires and detects no response.
	serverDropStream.setDropWrites(true)

	// Wait for the keep-alive failure callback.
	select {
	case count := <-failureCh:
		if count < 1 {
			t.Errorf("failure count = %d, want >= 1", count)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for OnKeepAliveFailed")
	}

	client.Close()
	server.Close()
}
