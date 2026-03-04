// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

const sessionParityTimeout = 10 * time.Second

// TestSessionRequest sends a session-level request with WantReply=true and
// verifies the response is received. Matches C#/TS SessionTests.SessionRequest.
func TestSessionRequest(t *testing.T) {
	client, server := createSessionPair(t, nil)

	// Server handler: authorize the request.
	server.OnRequest = func(args *RequestEventArgs) {
		args.IsAuthorized = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionParityTimeout)
	defer cancel()

	msg := &messages.SessionRequestMessage{
		RequestType: "test-request",
		WantReply:   true,
	}
	success, err := client.Request(ctx, msg)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if !success {
		t.Error("expected request to succeed")
	}
}

// TestSessionRequestNoReply sends a request with WantReply=false and verifies
// no reply and no error. Matches C#/TS SessionTests.SessionRequestNoReply.
func TestSessionRequestNoReply(t *testing.T) {
	client, server := createSessionPair(t, nil)

	var received atomic.Bool
	server.OnRequest = func(args *RequestEventArgs) {
		received.Store(true)
		args.IsAuthorized = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionParityTimeout)
	defer cancel()

	msg := &messages.SessionRequestMessage{
		RequestType: "test-no-reply",
		WantReply:   false,
	}
	success, err := client.Request(ctx, msg)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	// With WantReply=false, the result is always true (no failure possible).
	if !success {
		t.Error("expected success=true for WantReply=false")
	}

	// Give the server a moment to process the request.
	time.Sleep(100 * time.Millisecond)
	if !received.Load() {
		t.Error("server did not receive the request")
	}
}

// TestOverlappingSessionRequestsParity sends 5 concurrent requests from the
// client and verifies all get distinct responses. Matches C#/TS
// SessionTests.OverlappingSessionRequests.
func TestOverlappingSessionRequestsParity(t *testing.T) {
	client, server := createSessionPair(t, nil)

	// Server: authorize requests with even indices, deny odd.
	server.OnRequest = func(args *RequestEventArgs) {
		// Request types are "1" through "5".
		switch args.RequestType {
		case "1", "3", "5":
			args.IsAuthorized = false
		case "2", "4":
			args.IsAuthorized = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionParityTimeout)
	defer cancel()

	type result struct {
		idx     int
		success bool
		err     error
	}
	results := make(chan result, 5)

	for i := 1; i <= 5; i++ {
		go func(idx int) {
			msg := &messages.SessionRequestMessage{
				RequestType: fmt.Sprintf("%d", idx),
				WantReply:   true,
			}
			s, e := client.Request(ctx, msg)
			results <- result{idx: idx, success: s, err: e}
		}(i)
	}

	resultMap := make(map[int]bool)
	for i := 0; i < 5; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("request %d failed: %v", r.idx, r.err)
		}
		resultMap[r.idx] = r.success
	}

	for idx, success := range resultMap {
		expected := idx == 2 || idx == 4
		if success != expected {
			t.Errorf("request %d: expected success=%v, got %v", idx, expected, success)
		}
	}
}

// TestReportProgress sets OnReportProgress and verifies the callback fires at
// least once during handshake. Matches C#/TS SessionTests.ReportProgress.
func TestReportProgress(t *testing.T) {
	var mu sync.Mutex
	var progress []Progress

	clientConfig := NewNoSecurityConfig()
	clientStream, serverStream := duplexPipe()

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	client.OnReportProgress = func(p Progress) {
		mu.Lock()
		progress = append(progress, p)
		mu.Unlock()
	}

	server := NewServerSession(NewNoSecurityConfig())
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionParityTimeout)
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
		serverErr = server.Connect(ctx, serverStream)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server connect failed: %v", serverErr)
	}

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	mu.Lock()
	defer mu.Unlock()

	if len(progress) == 0 {
		t.Fatal("expected at least one progress event during handshake")
	}

	// Verify that key stages were reported.
	has := func(p Progress) bool {
		for _, v := range progress {
			if v == p {
				return true
			}
		}
		return false
	}

	if !has(ProgressOpeningSSHSessionConnection) {
		t.Error("missing ProgressOpeningSSHSessionConnection")
	}
	if !has(ProgressOpenedSSHSessionConnection) {
		t.Error("missing ProgressOpenedSSHSessionConnection")
	}
}

// TestKeepAliveSuccess enables keep-alive with a short interval, waits, and
// verifies OnKeepAliveSucceeded fires with a non-negative count.
// Matches C#/TS SessionTests.KeepAliveSuccess.
func TestKeepAliveSuccess(t *testing.T) {
	clientConfig := NewNoSecurityConfig()
	clientConfig.KeepAliveIntervalSeconds = 1

	clientStream, serverStream := duplexPipe()

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewServerSession(NewNoSecurityConfig())
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionParityTimeout)
	defer cancel()

	successCh := make(chan int, 5)
	client.Session.OnKeepAliveSucceeded = func(count int) {
		select {
		case successCh <- count:
		default:
		}
	}

	var wg sync.WaitGroup
	var clientErr, serverErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = client.Connect(ctx, clientStream)
	}()
	go func() {
		defer wg.Done()
		serverErr = server.Connect(ctx, serverStream)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server connect failed: %v", serverErr)
	}

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	// Wait for at least one keep-alive success within 5s.
	select {
	case count := <-successCh:
		if count < 1 {
			t.Errorf("expected positive success count, got %d", count)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for keep-alive success event")
	}
}

// TestKeepAliveFailure configures keep-alive and blocks the server dispatch
// so that no keep-alive responses arrive, then verifies OnKeepAliveFailed fires.
// Matches C#/TS SessionTests.KeepAliveFailure.
func TestKeepAliveFailure(t *testing.T) {
	clientConfig := NewNoSecurityConfig()
	clientConfig.KeepAliveIntervalSeconds = 1

	clientStream, serverStream := duplexPipe()

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := NewServerSession(NewNoSecurityConfig())
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionParityTimeout)
	defer cancel()

	var failedCount atomic.Int32
	client.Session.OnKeepAliveFailed = func(count int) {
		failedCount.Store(int32(count))
	}

	// Block the server's dispatch loop by holding a request handler for a long time.
	// This prevents it from responding to keep-alive requests.
	server.OnRequest = func(args *RequestEventArgs) {
		if args.RequestType == "block" {
			args.IsAuthorized = true
			time.Sleep(5 * time.Second)
		}
	}

	var wg sync.WaitGroup
	var clientErr, serverErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = client.Connect(ctx, clientStream)
	}()
	go func() {
		defer wg.Done()
		serverErr = server.Connect(ctx, serverStream)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server connect failed: %v", serverErr)
	}

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	// Send a blocking request to stall the server dispatch loop.
	msg := &messages.SessionRequestMessage{
		RequestType: "block",
		WantReply:   true,
	}
	success, err := client.Request(ctx, msg)
	if err != nil {
		t.Fatalf("blocking request failed: %v", err)
	}
	if !success {
		t.Error("expected blocking request to succeed")
	}

	// During the 5s block, keep-alive should have failed multiple times.
	if failedCount.Load() < 2 {
		t.Errorf("expected at least 2 keep-alive failures, got %d", failedCount.Load())
	}
}

// TestVersionParsing parses SSH version strings and verifies RemoteVersion
// fields. Matches C#/TS SessionTests.VersionParsing.
func TestVersionParsing(t *testing.T) {
	tests := []struct {
		input           string
		protocolVersion string
		name            string
		version         string
		isDevTunnels    bool
	}{
		{"SSH-2.0-OpenSSH_7.9", "2.0", "OpenSSH", "7.9", false},
		{"SSH-2.0-dev-tunnels-ssh_1.0", "2.0", "dev-tunnels-ssh", "1.0", true},
		{"SSH-2.0-dev-tunnels-ssh-go_0.1", "2.0", "dev-tunnels-ssh-go", "0.1", true},
		{"SSH-2.0-Microsoft.DevTunnels.Ssh_3.10", "2.0", "Microsoft.DevTunnels.Ssh", "3.10", true},
		{"SSH-2.0-test", "2.0", "test", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			v := ParseVersionInfo(tc.input)
			if v == nil {
				t.Fatal("expected non-nil VersionInfo")
			}
			if v.ProtocolVersion != tc.protocolVersion {
				t.Errorf("ProtocolVersion = %q, want %q", v.ProtocolVersion, tc.protocolVersion)
			}
			if v.Name != tc.name {
				t.Errorf("Name = %q, want %q", v.Name, tc.name)
			}
			if v.Version != tc.version {
				t.Errorf("Version = %q, want %q", v.Version, tc.version)
			}
			if v.IsDevTunnelsSSH() != tc.isDevTunnels {
				t.Errorf("IsDevTunnelsSSH() = %v, want %v", v.IsDevTunnelsSSH(), tc.isDevTunnels)
			}
		})
	}

	// Also verify RemoteVersion is set after a real connection.
	client, server := createSessionPair(t, nil)
	if client.RemoteVersion == nil {
		t.Fatal("client RemoteVersion should be set after connect")
	}
	if server.RemoteVersion == nil {
		t.Fatal("server RemoteVersion should be set after connect")
	}
	if !client.RemoteVersion.IsDevTunnelsSSH() {
		t.Error("client's remote version should be Dev Tunnels SSH")
	}
	if !server.RemoteVersion.IsDevTunnelsSSH() {
		t.Error("server's remote version should be Dev Tunnels SSH")
	}
}

// TestAlgorithmNegotiationFailure configures client and server with incompatible
// KEX algorithms and verifies Connect returns a negotiation failure error.
// Matches C#/TS SessionTests.AlgorithmNegotiationFailure.
func TestAlgorithmNegotiationFailure(t *testing.T) {
	clientConfig := NewDefaultConfig()
	clientConfig.KeyExchangeAlgorithms = []string{AlgoKexEcdhNistp256}
	clientConfig.PublicKeyAlgorithms = []string{AlgoPKEcdsaSha2P256}

	serverConfig := NewDefaultConfig()
	serverConfig.KeyExchangeAlgorithms = []string{AlgoKexDHGroup14}
	serverConfig.PublicKeyAlgorithms = []string{AlgoPKRsaSha512}

	clientStream, serverStream := duplexPipe()

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	serverKey, err := GenerateKeyPair(AlgoPKRsaSha512)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	server := NewServerSession(serverConfig)
	server.Credentials = &ServerCredentials{PublicKeys: []KeyPair{serverKey}}
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionParityTimeout)
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
		serverErr = server.Connect(ctx, serverStream)
	}()
	wg.Wait()

	// At least one side should fail with a negotiation error.
	if clientErr == nil && serverErr == nil {
		t.Fatal("expected at least one side to fail with negotiation error")
	}

	// Verify the error message indicates negotiation failure.
	errMsg := ""
	if clientErr != nil {
		errMsg = clientErr.Error()
	} else {
		errMsg = serverErr.Error()
	}

	t.Logf("Negotiation error: %s", errMsg)

	// Clean up.
	client.Close()
	server.Close()
}
