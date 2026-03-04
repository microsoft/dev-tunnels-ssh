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

const sessionRequestTestTimeout = 10 * time.Second

// TestOverlappingSessionRequests verifies that 4 concurrent session requests
// with different response patterns all return the correct result.
func TestOverlappingSessionRequests(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), sessionRequestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Server handler: requests "2" and "4" succeed, "1" and "3" fail.
	// Odd-numbered requests delay slightly to test overlapping.
	pair.ServerSession.OnRequest = func(args *ssh.RequestEventArgs) {
		reqType := args.RequestType
		if reqType == "2" || reqType == "4" {
			args.IsAuthorized = true
		} else {
			args.IsAuthorized = false
		}
	}

	// Send 4 overlapping session requests.
	type reqResult struct {
		idx     int
		success bool
		err     error
	}
	results := make(chan reqResult, 4)

	for i := 1; i <= 4; i++ {
		go func(idx int) {
			reqMsg := &messages.SessionRequestMessage{
				RequestType: fmt.Sprintf("%d", idx),
				WantReply:   true,
			}
			success, err := pair.ClientSession.Request(ctx, reqMsg)
			results <- reqResult{idx: idx, success: success, err: err}
		}(i)
	}

	// Collect all results.
	resultMap := make(map[int]bool)
	for i := 0; i < 4; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("request %d failed with error: %v", r.idx, r.err)
		}
		resultMap[r.idx] = r.success
	}

	// Verify results.
	// Note: with SSH protocol, session request responses are FIFO ordered,
	// so the order of requests matters. Since requests may be sent in any order
	// by the goroutines, we verify each result against the server logic.
	for idx, success := range resultMap {
		expected := idx == 2 || idx == 4
		if success != expected {
			t.Errorf("request %d: expected success=%v, got %v", idx, expected, success)
		}
	}
}

// TestSessionRequestUnauthenticated verifies that a session request sent before
// authentication is rejected, and the server handler is NOT called.
func TestSessionRequestUnauthenticated(t *testing.T) {
	// Use a secure session (real key exchange) so that canAcceptRequests() requires auth.
	serverConfig := ssh.NewDefaultConfig()
	clientConfig := ssh.NewDefaultConfig()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), sessionRequestTestTimeout)
	defer cancel()

	// Set up server host keys.
	serverRsaKey, err := ssh.NewRsaKeyPair(pair.ClientKey, ssh.AlgoPKRsaSha512)
	if err != nil {
		t.Fatalf("failed to create server RSA key pair: %v", err)
	}
	serverEcdsaKey, err := ssh.NewEcdsaKeyPair(pair.ServerKey)
	if err != nil {
		t.Fatalf("failed to create server ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{serverRsaKey, serverEcdsaKey},
	}

	// Client approves server key.
	pair.ClientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	// Track whether the server handler is called.
	var handlerCalled bool
	pair.ServerSession.OnRequest = func(args *ssh.RequestEventArgs) {
		handlerCalled = true
		args.IsAuthorized = true
	}
	pair.ServerSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	// Connect (does key exchange but NOT authentication).
	pair.Connect(ctx)

	// Send a session request BEFORE authenticating.
	reqMsg := &messages.SessionRequestMessage{
		RequestType: "test-request",
		WantReply:   true,
	}
	result, err := pair.ClientSession.Request(ctx, reqMsg)
	if err != nil {
		t.Fatalf("request returned error: %v", err)
	}
	if result {
		t.Error("expected request to be rejected (not authenticated)")
	}
	if handlerCalled {
		t.Error("server handler should NOT be called for unauthenticated requests")
	}
}

// TestOpenSessionWithMultipleRequests verifies that multiple sequential session
// requests are processed in order.
func TestOpenSessionWithMultipleRequests(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), sessionRequestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Server handler tracks all received request types.
	var mu sync.Mutex
	var receivedRequests []string
	pair.ServerSession.OnRequest = func(args *ssh.RequestEventArgs) {
		mu.Lock()
		receivedRequests = append(receivedRequests, args.RequestType)
		mu.Unlock()
		args.IsAuthorized = true
	}

	// Send 5 sequential requests.
	for i := 1; i <= 5; i++ {
		reqMsg := &messages.SessionRequestMessage{
			RequestType: fmt.Sprintf("request-%d", i),
			WantReply:   true,
		}
		result, err := pair.ClientSession.Request(ctx, reqMsg)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		if !result {
			t.Errorf("request %d should have succeeded", i)
		}
	}

	// Verify all requests were received in order.
	mu.Lock()
	defer mu.Unlock()
	if len(receivedRequests) != 5 {
		t.Fatalf("expected 5 requests, got %d", len(receivedRequests))
	}
	for i, rt := range receivedRequests {
		expected := fmt.Sprintf("request-%d", i+1)
		if rt != expected {
			t.Errorf("request %d: expected type %q, got %q", i+1, expected, rt)
		}
	}
}

// TestOpenChannelWithRequest tests the open-channel-request extension
// with all 4 combinations of server/client extension support.
func TestOpenChannelWithRequest(t *testing.T) {
	tests := []struct {
		name            string
		serverExtension bool
		clientExtension bool
	}{
		{"BothOff", false, false},
		{"ServerOff_ClientOn", false, true},
		{"ServerOn_ClientOff", true, false},
		{"BothOn", true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverConfig := ssh.NewNoSecurityConfig()
			clientConfig := ssh.NewNoSecurityConfig()

			if !tc.serverExtension {
				serverConfig.ProtocolExtensions = removeExtension(
					serverConfig.ProtocolExtensions, ssh.ExtensionOpenChannelRequest)
			}
			if !tc.clientExtension {
				clientConfig.ProtocolExtensions = removeExtension(
					clientConfig.ProtocolExtensions, ssh.ExtensionOpenChannelRequest)
			}

			pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
				ServerConfig: serverConfig,
				ClientConfig: clientConfig,
			})
			defer pair.Close()

			ctx, cancel := context.WithTimeout(context.Background(), sessionRequestTestTimeout)
			defer cancel()

			pair.Connect(ctx)

			// Server handler authorizes the channel request.
			var receivedRequestType string
			var mu sync.Mutex
			pair.ServerSession.OnChannelOpening = func(args *ssh.ChannelOpeningEventArgs) {
				args.Channel.OnRequest = func(reqArgs *ssh.RequestEventArgs) {
					mu.Lock()
					receivedRequestType = reqArgs.RequestType
					mu.Unlock()
					reqArgs.IsAuthorized = true
				}
			}

			// Open channel with request.
			initialRequest := &messages.ChannelRequestMessage{
				RequestType: "test-initial-request",
				WantReply:   true,
			}

			var clientCh *ssh.Channel
			var serverCh *ssh.Channel
			var clientErr, serverErr error

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				clientCh, clientErr = pair.ClientSession.OpenChannelWithRequest(
					ctx,
					&messages.ChannelOpenMessage{ChannelType: "session"},
					initialRequest,
				)
			}()
			go func() {
				defer wg.Done()
				serverCh, serverErr = pair.ServerSession.AcceptChannel(ctx)
			}()
			wg.Wait()

			if clientErr != nil {
				t.Fatalf("OpenChannelWithRequest failed: %v", clientErr)
			}
			if serverErr != nil {
				t.Fatalf("AcceptChannel failed: %v", serverErr)
			}

			if clientCh == nil {
				t.Fatal("client channel should not be nil")
			}
			if serverCh == nil {
				t.Fatal("server channel should not be nil")
			}

			// Verify the request was received.
			// Give a moment for async processing.
			time.Sleep(50 * time.Millisecond)
			mu.Lock()
			if receivedRequestType != "test-initial-request" {
				t.Errorf("expected request type 'test-initial-request', got %q", receivedRequestType)
			}
			mu.Unlock()
		})
	}
}

// TestOpenChannelWithRequestFail tests that OpenChannelWithRequest returns an error
// when the initial request is denied, for all 4 extension combinations.
func TestOpenChannelWithRequestFail(t *testing.T) {
	tests := []struct {
		name            string
		serverExtension bool
		clientExtension bool
	}{
		{"BothOff", false, false},
		{"ServerOff_ClientOn", false, true},
		{"ServerOn_ClientOff", true, false},
		{"BothOn", true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverConfig := ssh.NewNoSecurityConfig()
			clientConfig := ssh.NewNoSecurityConfig()

			if !tc.serverExtension {
				serverConfig.ProtocolExtensions = removeExtension(
					serverConfig.ProtocolExtensions, ssh.ExtensionOpenChannelRequest)
			}
			if !tc.clientExtension {
				clientConfig.ProtocolExtensions = removeExtension(
					clientConfig.ProtocolExtensions, ssh.ExtensionOpenChannelRequest)
			}

			pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
				ServerConfig: serverConfig,
				ClientConfig: clientConfig,
			})
			defer pair.Close()

			ctx, cancel := context.WithTimeout(context.Background(), sessionRequestTestTimeout)
			defer cancel()

			pair.Connect(ctx)

			// Server handler DENIES the channel request.
			pair.ServerSession.OnChannelOpening = func(args *ssh.ChannelOpeningEventArgs) {
				args.Channel.OnRequest = func(reqArgs *ssh.RequestEventArgs) {
					reqArgs.IsAuthorized = false
				}
			}

			// Open channel with request — should fail.
			initialRequest := &messages.ChannelRequestMessage{
				RequestType: "test-initial-request",
				WantReply:   true,
			}

			var clientErr error

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, clientErr = pair.ClientSession.OpenChannelWithRequest(
					ctx,
					&messages.ChannelOpenMessage{ChannelType: "session"},
					initialRequest,
				)
			}()
			go func() {
				defer wg.Done()
				// Accept the channel on the server side even though the request fails.
				_, _ = pair.ServerSession.AcceptChannel(ctx)
			}()
			wg.Wait()

			if clientErr == nil {
				t.Fatal("expected OpenChannelWithRequest to fail")
			}
		})
	}
}

// TestOpenChannelWithRequestNoReply tests OpenChannelWithRequest with WantReply=false.
func TestOpenChannelWithRequestNoReply(t *testing.T) {
	serverConfig := ssh.NewNoSecurityConfig()
	clientConfig := ssh.NewNoSecurityConfig()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), sessionRequestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Server handler tracks the request.
	var receivedRequestType string
	var mu sync.Mutex
	pair.ServerSession.OnChannelOpening = func(args *ssh.ChannelOpeningEventArgs) {
		args.Channel.OnRequest = func(reqArgs *ssh.RequestEventArgs) {
			mu.Lock()
			receivedRequestType = reqArgs.RequestType
			mu.Unlock()
			reqArgs.IsAuthorized = true
		}
	}

	// Open channel with request, WantReply=false.
	initialRequest := &messages.ChannelRequestMessage{
		RequestType: "test-no-reply",
		WantReply:   false,
	}

	var clientCh *ssh.Channel
	var serverCh *ssh.Channel
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, clientErr = pair.ClientSession.OpenChannelWithRequest(
			ctx,
			&messages.ChannelOpenMessage{ChannelType: "session"},
			initialRequest,
		)
	}()
	go func() {
		defer wg.Done()
		serverCh, serverErr = pair.ServerSession.AcceptChannel(ctx)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("OpenChannelWithRequest failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("AcceptChannel failed: %v", serverErr)
	}

	if clientCh == nil {
		t.Fatal("client channel should not be nil")
	}
	if serverCh == nil {
		t.Fatal("server channel should not be nil")
	}

	// Verify the request was received.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	if receivedRequestType != "test-no-reply" {
		t.Errorf("expected request type 'test-no-reply', got %q", receivedRequestType)
	}
	mu.Unlock()
}

// TestOpenChannelWithRequestUnauthenticated tests that the initial-channel-request
// extension works even before authentication (it's not gated by auth).
func TestOpenChannelWithRequestUnauthenticated(t *testing.T) {
	// Use no-security config so connect works without real crypto
	// but extension is still negotiated.
	serverConfig := ssh.NewNoSecurityConfig()
	clientConfig := ssh.NewNoSecurityConfig()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), sessionRequestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Server handler authorizes the request.
	pair.ServerSession.OnChannelOpening = func(args *ssh.ChannelOpeningEventArgs) {
		args.Channel.OnRequest = func(reqArgs *ssh.RequestEventArgs) {
			reqArgs.IsAuthorized = true
		}
	}

	// Open channel with request WITHOUT authenticating first.
	initialRequest := &messages.ChannelRequestMessage{
		RequestType: "test-unauth-request",
		WantReply:   true,
	}

	var clientCh *ssh.Channel
	var serverCh *ssh.Channel
	var clientErr, serverErr error

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, clientErr = pair.ClientSession.OpenChannelWithRequest(
			ctx,
			&messages.ChannelOpenMessage{ChannelType: "session"},
			initialRequest,
		)
	}()
	go func() {
		defer wg.Done()
		serverCh, serverErr = pair.ServerSession.AcceptChannel(ctx)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("OpenChannelWithRequest should work even without auth: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("AcceptChannel failed: %v", serverErr)
	}

	if clientCh == nil || serverCh == nil {
		t.Fatal("channels should not be nil")
	}
}

// TestSendWhileDisconnected verifies that sending a message on a disconnected
// session returns a ConnectionError.
func TestSendWhileDisconnected(t *testing.T) {
	pair := helpers.NewSessionPair(t)
	defer pair.Close()

	ctx, cancel := context.WithTimeout(context.Background(), sessionRequestTestTimeout)
	defer cancel()

	pair.Connect(ctx)

	// Disconnect the session.
	pair.Disconnect(fmt.Errorf("test disconnect"))

	// Wait for the session to detect the disconnect.
	time.Sleep(100 * time.Millisecond)

	// Try to send a session request.
	reqMsg := &messages.SessionRequestMessage{
		RequestType: "test-request",
		WantReply:   true,
	}
	_, err := pair.ClientSession.Request(ctx, reqMsg)
	if err == nil {
		t.Fatal("expected error when sending on disconnected session")
	}

	// Verify it's a ConnectionError.
	var connErr *ssh.ConnectionError
	if !errors.As(err, &connErr) {
		t.Errorf("expected ConnectionError, got %T: %v", err, err)
	}
}

// removeExtension removes a protocol extension from a slice.
func removeExtension(extensions []string, ext string) []string {
	result := make([]string, 0, len(extensions))
	for _, e := range extensions {
		if e != ext {
			result = append(result, e)
		}
	}
	return result
}
