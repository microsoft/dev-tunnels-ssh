// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"context"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

const serviceTestTimeout = 10 * time.Second

// --- Test service implementations ---

// testServiceConfig is a config object passed to services.
type testServiceConfig struct {
	value string
}

// testService1 is activated via ServiceRequest.
type testService1 struct {
	session  *ssh.Session
	config   *testServiceConfig
	disposed bool
	mu       sync.Mutex
}

func (s *testService1) OnSessionRequest(args *ssh.RequestEventArgs)              {}
func (s *testService1) OnChannelOpening(args *ssh.ChannelOpeningEventArgs)       {}
func (s *testService1) OnChannelRequest(ch *ssh.Channel, args *ssh.RequestEventArgs) {}
func (s *testService1) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disposed = true
	return nil
}
func (s *testService1) IsDisposed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.disposed
}

// testService2 is activated via SessionRequest.
type testService2 struct {
	session       *ssh.Session
	config        *testServiceConfig
	requestMsg    *messages.SessionRequestMessage
	mu            sync.Mutex
}

func (s *testService2) OnSessionRequest(args *ssh.RequestEventArgs) {
	s.mu.Lock()
	s.requestMsg = args.Request.(*messages.SessionRequestMessage)
	s.mu.Unlock()
	args.IsAuthorized = true
}
func (s *testService2) OnChannelOpening(args *ssh.ChannelOpeningEventArgs)       {}
func (s *testService2) OnChannelRequest(ch *ssh.Channel, args *ssh.RequestEventArgs) {}
func (s *testService2) Close() error                                              { return nil }

// testService3 is activated via ChannelType.
type testService3 struct {
	session *ssh.Session
	config  *testServiceConfig
	channel *ssh.Channel
	mu      sync.Mutex
}

func (s *testService3) OnSessionRequest(args *ssh.RequestEventArgs) {}
func (s *testService3) OnChannelOpening(args *ssh.ChannelOpeningEventArgs) {
	s.mu.Lock()
	s.channel = args.Channel
	s.mu.Unlock()
}
func (s *testService3) OnChannelRequest(ch *ssh.Channel, args *ssh.RequestEventArgs) {}
func (s *testService3) Close() error                                                  { return nil }

// testService4 is activated via ChannelRequest.
type testService4 struct {
	session    *ssh.Session
	requestMsg *messages.ChannelRequestMessage
	channel    *ssh.Channel
	mu         sync.Mutex
}

func (s *testService4) OnSessionRequest(args *ssh.RequestEventArgs) {}
func (s *testService4) OnChannelOpening(args *ssh.ChannelOpeningEventArgs) {}
func (s *testService4) OnChannelRequest(ch *ssh.Channel, args *ssh.RequestEventArgs) {
	s.mu.Lock()
	s.channel = ch
	s.requestMsg = args.Request.(*messages.ChannelRequestMessage)
	s.mu.Unlock()
	args.IsAuthorized = true
}
func (s *testService4) Close() error { return nil }

// testService5 is activated via ChannelType + ChannelRequest (both must match).
type testService5 struct {
	session    *ssh.Session
	requestMsg *messages.ChannelRequestMessage
	channel    *ssh.Channel
	mu         sync.Mutex
}

func (s *testService5) OnSessionRequest(args *ssh.RequestEventArgs) {}
func (s *testService5) OnChannelOpening(args *ssh.ChannelOpeningEventArgs) {}
func (s *testService5) OnChannelRequest(ch *ssh.Channel, args *ssh.RequestEventArgs) {
	s.mu.Lock()
	s.channel = ch
	s.requestMsg = args.Request.(*messages.ChannelRequestMessage)
	s.mu.Unlock()
	args.IsAuthorized = true
}
func (s *testService5) Close() error { return nil }

// --- Constants ---
const (
	testService1Name    = "test-service-1"
	testService2Request = "test-service-2"
	testService3Channel = "test-service-3"
	testService4Request = "test-service-4"
	testService5Channel = "test-service-5-channel"
	testService5Request = "test-service-5"
)

// createServiceTestPair creates a SessionPair with test services registered on the server.
func createServiceTestPair(t *testing.T) (*helpers.SessionPair, *testServiceConfig) {
	t.Helper()

	cfg := &testServiceConfig{value: "test-config"}

	serverConfig := ssh.NewNoSecurityConfig()
	serverConfig.AddService(testService1Name, ssh.ServiceActivation{
		ServiceRequest: testService1Name,
	}, func(session *ssh.Session, config interface{}) ssh.Service {
		return &testService1{session: session, config: nil} // no config passed
	}, nil)

	serverConfig.AddService(testService2Request, ssh.ServiceActivation{
		SessionRequest: testService2Request,
	}, func(session *ssh.Session, config interface{}) ssh.Service {
		var c *testServiceConfig
		if config != nil {
			c = config.(*testServiceConfig)
		}
		return &testService2{session: session, config: c}
	}, cfg)

	serverConfig.AddService(testService3Channel, ssh.ServiceActivation{
		ChannelType: testService3Channel,
	}, func(session *ssh.Session, config interface{}) ssh.Service {
		var c *testServiceConfig
		if config != nil {
			c = config.(*testServiceConfig)
		}
		return &testService3{session: session, config: c}
	}, cfg)

	serverConfig.AddService(testService4Request, ssh.ServiceActivation{
		ChannelRequest: testService4Request,
	}, func(session *ssh.Session, config interface{}) ssh.Service {
		return &testService4{session: session}
	}, nil)

	serverConfig.AddService(testService5Request, ssh.ServiceActivation{
		ChannelType:    testService5Channel,
		ChannelRequest: testService5Request,
	}, func(session *ssh.Session, config interface{}) ssh.Service {
		return &testService5{session: session}
	}, nil)

	clientConfig := ssh.NewNoSecurityConfig()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})

	return pair, cfg
}

// findService finds a service of the specified type by doing a linear search
// and type assertion. Returns the typed service and true if found.
func findService1(services []ssh.Service) (*testService1, bool) {
	for _, svc := range services {
		if typed, ok := svc.(*testService1); ok {
			return typed, true
		}
	}
	return nil, false
}

func findService2(services []ssh.Service) (*testService2, bool) {
	for _, svc := range services {
		if typed, ok := svc.(*testService2); ok {
			return typed, true
		}
	}
	return nil, false
}

func findService3(services []ssh.Service) (*testService3, bool) {
	for _, svc := range services {
		if typed, ok := svc.(*testService3); ok {
			return typed, true
		}
	}
	return nil, false
}

func findService4(services []ssh.Service) (*testService4, bool) {
	for _, svc := range services {
		if typed, ok := svc.(*testService4); ok {
			return typed, true
		}
	}
	return nil, false
}

func findService5(services []ssh.Service) (*testService5, bool) {
	for _, svc := range services {
		if typed, ok := svc.(*testService5); ok {
			return typed, true
		}
	}
	return nil, false
}

// --- Tests ---

func TestActivateOnServiceRequest(t *testing.T) {
	pair, _ := createServiceTestPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), serviceTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	var activatedService ssh.Service
	pair.ServerSession.OnServiceActivated = func(svc ssh.Service) {
		activatedService = svc
	}

	// Verify service is not yet activated.
	services := pair.ServerSession.Services()
	_, found := findService1(services)
	if found {
		t.Fatal("testService1 should not be activated before service request")
	}

	// Send service request from client.
	err := pair.ClientSession.RequestService(testService1Name)
	if err != nil {
		t.Fatalf("RequestService failed: %v", err)
	}

	// Verify service is now activated.
	services = pair.ServerSession.Services()
	svc1, found := findService1(services)
	if !found {
		t.Fatal("testService1 should be activated after service request")
	}
	if svc1.config != nil {
		t.Error("testService1 config should be nil (no config passed)")
	}

	// Verify activated event fired.
	if activatedService == nil {
		t.Fatal("OnServiceActivated should have fired")
	}
	if _, ok := activatedService.(*testService1); !ok {
		t.Fatal("activated service should be testService1")
	}

	// Verify dispose on close.
	if svc1.IsDisposed() {
		t.Error("testService1 should not be disposed before session close")
	}

	pair.Close()

	// Server may be closing asynchronously (triggered by client's disconnect
	// message processed in the server dispatch loop). Poll briefly for disposal.
	deadline := time.After(time.Second)
	for !svc1.IsDisposed() {
		select {
		case <-deadline:
			t.Fatal("testService1 should be disposed after session close")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestActivateOnSessionRequest(t *testing.T) {
	pair, cfg := createServiceTestPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), serviceTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	var activatedService ssh.Service
	pair.ServerSession.OnServiceActivated = func(svc ssh.Service) {
		activatedService = svc
	}

	// Verify service is not yet activated.
	services := pair.ServerSession.Services()
	_, found := findService2(services)
	if found {
		t.Fatal("testService2 should not be activated before session request")
	}

	// Send session request from client.
	reqMsg := &messages.SessionRequestMessage{
		RequestType: testService2Request,
		WantReply:   true,
	}
	result, err := pair.ClientSession.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !result {
		t.Error("expected session request to succeed")
	}

	// Verify service is now activated.
	services = pair.ServerSession.Services()
	svc2, found := findService2(services)
	if !found {
		t.Fatal("testService2 should be activated after session request")
	}
	if svc2.config != cfg {
		t.Error("testService2 config should match provided config")
	}

	// Verify the request message was captured.
	svc2.mu.Lock()
	reqCaptured := svc2.requestMsg
	svc2.mu.Unlock()
	if reqCaptured == nil {
		t.Fatal("testService2 should have received the request message")
	}

	// Verify activated event fired.
	if activatedService == nil {
		t.Fatal("OnServiceActivated should have fired")
	}
	if _, ok := activatedService.(*testService2); !ok {
		t.Fatal("activated service should be testService2")
	}
}

func TestActivateOnChannelType(t *testing.T) {
	pair, cfg := createServiceTestPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), serviceTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	var activatedService ssh.Service
	pair.ServerSession.OnServiceActivated = func(svc ssh.Service) {
		activatedService = svc
	}

	// Verify service is not yet activated.
	services := pair.ServerSession.Services()
	_, found := findService3(services)
	if found {
		t.Fatal("testService3 should not be activated before channel open")
	}

	// Open channel with the service's channel type.
	var clientCh *ssh.Channel
	var serverCh *ssh.Channel
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, clientErr = pair.ClientSession.OpenChannelWithType(ctx, testService3Channel)
	}()
	go func() {
		defer wg.Done()
		serverCh, serverErr = pair.ServerSession.AcceptChannelWithType(ctx, testService3Channel)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("open channel failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("accept channel failed: %v", serverErr)
	}

	_ = clientCh
	_ = serverCh

	// Verify service is now activated.
	services = pair.ServerSession.Services()
	svc3, found := findService3(services)
	if !found {
		t.Fatal("testService3 should be activated after channel open with matching type")
	}
	if svc3.config != cfg {
		t.Error("testService3 config should match provided config")
	}

	// Verify the channel was captured.
	svc3.mu.Lock()
	channelCaptured := svc3.channel
	svc3.mu.Unlock()
	if channelCaptured == nil {
		t.Fatal("testService3 should have received the channel")
	}

	// Verify activated event fired.
	if activatedService == nil {
		t.Fatal("OnServiceActivated should have fired")
	}
	if _, ok := activatedService.(*testService3); !ok {
		t.Fatal("activated service should be testService3")
	}
}

func TestActivateOnChannelRequest(t *testing.T) {
	pair, _ := createServiceTestPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), serviceTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	var activatedService ssh.Service
	pair.ServerSession.OnServiceActivated = func(svc ssh.Service) {
		activatedService = svc
	}

	// Verify service is not yet activated.
	services := pair.ServerSession.Services()
	_, found := findService4(services)
	if found {
		t.Fatal("testService4 should not be activated before channel request")
	}

	// Open a default channel first.
	clientCh, _ := pair.OpenChannel(ctx)

	// Verify service is still not activated after opening a default channel.
	services = pair.ServerSession.Services()
	_, found = findService4(services)
	if found {
		t.Fatal("testService4 should not be activated by opening a default channel")
	}

	// Send channel request that matches service's activation rule.
	reqMsg := &messages.ChannelRequestMessage{
		RequestType: testService4Request,
		WantReply:   true,
	}
	_, err := clientCh.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("channel request failed: %v", err)
	}

	// Verify service is now activated.
	services = pair.ServerSession.Services()
	svc4, found := findService4(services)
	if !found {
		t.Fatal("testService4 should be activated after channel request")
	}

	// Verify the request message was captured.
	svc4.mu.Lock()
	reqCaptured := svc4.requestMsg
	svc4.mu.Unlock()
	if reqCaptured == nil {
		t.Fatal("testService4 should have received the request message")
	}

	// Verify activated event fired.
	if activatedService == nil {
		t.Fatal("OnServiceActivated should have fired")
	}
	if _, ok := activatedService.(*testService4); !ok {
		t.Fatal("activated service should be testService4")
	}
}

func TestActivateOnChannelTypeChannelRequest(t *testing.T) {
	pair, _ := createServiceTestPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), serviceTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	var activatedService ssh.Service
	pair.ServerSession.OnServiceActivated = func(svc ssh.Service) {
		activatedService = svc
	}

	// Verify service is not yet activated.
	services := pair.ServerSession.Services()
	_, found := findService5(services)
	if found {
		t.Fatal("testService5 should not be activated initially")
	}

	// Open channel with the service's channel type.
	var clientCh *ssh.Channel
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, clientErr = pair.ClientSession.OpenChannelWithType(ctx, testService5Channel)
	}()
	go func() {
		defer wg.Done()
		_, serverErr = pair.ServerSession.AcceptChannelWithType(ctx, testService5Channel)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("open channel failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("accept channel failed: %v", serverErr)
	}

	// Verify service is still NOT activated (needs both channel type AND request).
	services = pair.ServerSession.Services()
	_, found = findService5(services)
	if found {
		t.Fatal("testService5 should not be activated by channel open alone")
	}

	// Send channel request that matches the service's request type.
	reqMsg := &messages.ChannelRequestMessage{
		RequestType: testService5Request,
		WantReply:   true,
	}
	_, err := clientCh.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("channel request failed: %v", err)
	}

	// Now service should be activated (both channel type AND request match).
	services = pair.ServerSession.Services()
	svc5, found := findService5(services)
	if !found {
		t.Fatal("testService5 should be activated after channel request on matching channel type")
	}

	// Verify both channel and request message were captured.
	svc5.mu.Lock()
	channelCaptured := svc5.channel
	reqCaptured := svc5.requestMsg
	svc5.mu.Unlock()
	if channelCaptured == nil {
		t.Fatal("testService5 should have received the channel")
	}
	if reqCaptured == nil {
		t.Fatal("testService5 should have received the request message")
	}

	// Verify activated event fired.
	if activatedService == nil {
		t.Fatal("OnServiceActivated should have fired")
	}
	if _, ok := activatedService.(*testService5); !ok {
		t.Fatal("activated service should be testService5")
	}
}

func TestSendUnimplementedMessage(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), serviceTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Send a custom/unknown message type (199) directly via the protocol.
	// The server should respond with SSH_MSG_UNIMPLEMENTED and the session should stay open.
	unknownMsg := []byte{199, 0, 0, 0, 0} // type 199, 4 bytes of padding
	err := pair.ClientSession.SendRawMessage(unknownMsg)
	if err != nil {
		t.Fatalf("failed to send unknown message: %v", err)
	}

	// Verify session is still open by opening a channel.
	clientCh, serverCh := pair.OpenChannel(ctx)
	if clientCh == nil || serverCh == nil {
		t.Fatal("session should still be open after sending unknown message")
	}
}

func TestSendDebugMessage(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), serviceTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Send a debug message directly.
	debugMsg := &messages.DebugMessage{
		AlwaysDisplay: false,
		Message:       "test debug message",
		Language:      "en",
	}
	err := pair.ClientSession.SendMessage(debugMsg)
	if err != nil {
		t.Fatalf("failed to send debug message: %v", err)
	}

	// Verify session is still open by opening a channel.
	clientCh, serverCh := pair.OpenChannel(ctx)
	if clientCh == nil || serverCh == nil {
		t.Fatal("session should still be open after sending debug message")
	}
}
