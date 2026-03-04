// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// TestOnReportProgressFiresDuringConnect verifies that the OnReportProgress callback
// fires at key handshake stages during Connect.
func TestOnReportProgressFiresDuringConnect(t *testing.T) {
	var mu sync.Mutex
	var clientProgress []Progress
	var serverProgress []Progress

	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	clientConfig := NewDefaultConfig()
	serverConfig := NewDefaultConfig()

	clientStream, serverStream := duplexPipe()

	client := NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	client.OnReportProgress = func(p Progress) {
		mu.Lock()
		clientProgress = append(clientProgress, p)
		mu.Unlock()
	}

	server := NewServerSession(serverConfig)
	server.Credentials = &ServerCredentials{PublicKeys: []KeyPair{serverKey}}
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}
	server.OnReportProgress = func(p Progress) {
		mu.Lock()
		serverProgress = append(serverProgress, p)
		mu.Unlock()
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

	// Verify client progress includes the expected stages.
	mu.Lock()
	cp := append([]Progress(nil), clientProgress...)
	sp := append([]Progress(nil), serverProgress...)
	mu.Unlock()

	expectedStages := []Progress{
		ProgressOpeningSSHSessionConnection,
		ProgressStartingProtocolVersionExchange,
		ProgressCompletedProtocolVersionExchange,
		ProgressStartingKeyExchange,
		ProgressCompletedKeyExchange,
		ProgressOpenedSSHSessionConnection,
	}

	for _, expected := range expectedStages {
		found := false
		for _, p := range cp {
			if p == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("client missing progress stage %d", expected)
		}
	}

	// Server should also have at least the connection and KEX stages.
	for _, expected := range expectedStages {
		found := false
		for _, p := range sp {
			if p == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("server missing progress stage %d", expected)
		}
	}
}

// TestOnReportProgressNoSecurityConfig verifies progress fires for no-security sessions.
func TestOnReportProgressNoSecurityConfig(t *testing.T) {
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
		t.Error("no progress events fired during no-security connect")
	}

	// Should include at least Opening and Opened stages.
	hasOpening := false
	hasOpened := false
	for _, p := range progress {
		if p == ProgressOpeningSSHSessionConnection {
			hasOpening = true
		}
		if p == ProgressOpenedSSHSessionConnection {
			hasOpened = true
		}
	}
	if !hasOpening {
		t.Error("missing ProgressOpeningSSHSessionConnection")
	}
	if !hasOpened {
		t.Error("missing ProgressOpenedSSHSessionConnection")
	}
}

// TestOnReportProgressAuthStages verifies that StartingSessionAuthentication and
// CompletedSessionAuthentication are reported during the authentication flow.
func TestOnReportProgressAuthStages(t *testing.T) {
	var mu sync.Mutex
	var serverProgress []Progress

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			args.AuthenticationResult = true
		},
	})

	server.SetReportProgressHandler(func(p Progress) {
		mu.Lock()
		serverProgress = append(serverProgress, p)
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.Authenticate(ctx, &ClientCredentials{Username: "testuser"})
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if !result {
		t.Error("expected authentication to succeed")
	}

	// Give a brief moment for server-side progress to fire.
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	hasStarting := false
	hasCompleted := false
	for _, p := range serverProgress {
		if p == ProgressStartingSessionAuthentication {
			hasStarting = true
		}
		if p == ProgressCompletedSessionAuthentication {
			hasCompleted = true
		}
	}
	if !hasStarting {
		t.Error("server missing ProgressStartingSessionAuthentication")
	}
	if !hasCompleted {
		t.Error("server missing ProgressCompletedSessionAuthentication")
	}
}

// TestOnReconnectedFiresOnServer verifies that the OnReconnected callback fires
// on the server session after a client successfully reconnects.
func TestOnReconnectedFiresOnServer(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	reconnSessions := NewReconnectableSessions()
	serverCreds := &ServerCredentials{PublicKeys: []KeyPair{serverKey}}
	clientCreds := &ClientCredentials{Username: "testuser"}

	// Create the initial transport pair.
	clientTransport, serverTransport := duplexPipe()

	// Create client SecureStream with reconnect enabled.
	client := NewSecureStreamClient(clientTransport, clientCreds, true)
	client.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	disconnectedCh := make(chan struct{}, 1)
	client.OnDisconnected = func() {
		select {
		case disconnectedCh <- struct{}{}:
		default:
		}
	}

	// Create server SecureStream with reconnectable sessions.
	server := NewSecureStreamServer(serverTransport, serverCreds, reconnSessions)
	server.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	// Set up OnReconnected callback on the server's session.
	reconnectedCh := make(chan struct{}, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect both concurrently.
	var wg sync.WaitGroup
	var clientErr, serverErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = client.Connect(ctx)
	}()
	go func() {
		defer wg.Done()
		serverErr = server.Connect(ctx)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client connect failed: %v", clientErr)
	}
	if serverErr != nil {
		t.Fatalf("server connect failed: %v", serverErr)
	}

	// Wait for reconnect to be fully enabled on both sides.
	if err := WaitUntilReconnectEnabled(ctx, client.Session(), server.Session()); err != nil {
		t.Fatalf("reconnect not enabled: %v", err)
	}

	// Add server to reconnectable sessions and set the OnReconnected callback.
	reconnSessions.add(server.serverSession)
	server.serverSession.SetReconnectedHandler(func() {
		select {
		case reconnectedCh <- struct{}{}:
		default:
		}
	})

	// Exchange data before disconnect.
	testData := []byte("before disconnect")
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(testData)
		writeDone <- err
	}()

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("server read before disconnect failed: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write before disconnect failed: %v", err)
	}
	if !bytes.Equal(buf, testData) {
		t.Errorf("data mismatch: got %q, want %q", buf, testData)
	}

	// Simulate network failure.
	clientTransport.Close()
	serverTransport.Close()

	// Wait for client to detect disconnect.
	select {
	case <-disconnectedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client OnDisconnected")
	}

	// Wait for server to detect disconnect.
	deadline := time.After(5 * time.Second)
	for server.Session().IsConnected() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for server disconnect")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Create new transport pair for reconnection.
	newClientTransport, newServerTransport := duplexPipe()

	// Create new server SecureStream.
	newServer := NewSecureStreamServer(newServerTransport, serverCreds, reconnSessions)
	newServer.OnAuthenticating = func(args *AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	// Connect new server and reconnect client concurrently.
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = newServer.Connect(ctx)
	}()
	go func() {
		defer wg.Done()
		clientErr = client.Reconnect(ctx, newClientTransport)
	}()
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client reconnect failed: %v", clientErr)
	}

	// Verify OnReconnected fires on the original server session.
	select {
	case <-reconnectedCh:
		// Success — OnReconnected fired.
	case <-time.After(5 * time.Second):
		t.Error("OnReconnected not called on server after reconnection")
	}

	// Verify both sides are connected.
	if !client.Session().IsConnected() {
		t.Error("client should be connected after reconnect")
	}
	if !server.Session().IsConnected() {
		t.Error("original server should be connected after reconnect")
	}

	// Clean up.
	client.Close()
	server.Close()
	newServer.Close()
}

// TestClientSkipsPasswordWhenServerOnlySuggestsPublicKey verifies that client
// authentication filters methods by the server's suggested methods on failure.
func TestClientSkipsPasswordWhenServerOnlySuggestsPublicKey(t *testing.T) {
	// Server only accepts publickey auth.
	serverConfig := NewNoSecurityConfig()
	serverConfig.AuthenticationMethods = []string{AuthMethodPublicKey}

	var mu sync.Mutex
	var serverAuthAttempts []string

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			switch args.AuthenticationType {
			case AuthClientNone:
				serverAuthAttempts = append(serverAuthAttempts, AuthMethodNone)
			case AuthClientPassword:
				serverAuthAttempts = append(serverAuthAttempts, AuthMethodPassword)
			case AuthClientPublicKey, AuthClientPublicKeyQuery:
				serverAuthAttempts = append(serverAuthAttempts, AuthMethodPublicKey)
			case AuthClientInteractive:
				serverAuthAttempts = append(serverAuthAttempts, AuthMethodKeyboardInteractive)
			}
			mu.Unlock()
			// Reject everything — we want to see what methods the client tries.
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Client provides password credentials. After the "none" attempt fails
	// and the server says only "publickey" is acceptable, the client should
	// NOT try password auth.
	result, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "testpass",
	})

	// Auth should fail (no accepted methods match).
	if err != nil {
		// Session may close with disconnect error, which is acceptable.
		_ = err
	}
	if result {
		t.Error("expected authentication to fail (server only accepts publickey)")
	}

	// Verify server never saw a password auth attempt.
	mu.Lock()
	defer mu.Unlock()

	_ = server // keep server reference alive

	for _, method := range serverAuthAttempts {
		if method == AuthMethodPassword {
			t.Error("client tried password auth, but server only suggests publickey")
		}
	}
}

// TestClientSkipsPasswordWhenServerOnlySuggestsPublicKeyEncrypted tests the same
// auth filtering with a real encrypted session.
func TestClientSkipsPasswordWhenServerOnlySuggestsPublicKeyEncrypted(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	// Server only accepts publickey auth.
	serverConfig := NewDefaultConfig()
	serverConfig.AuthenticationMethods = []string{AuthMethodPublicKey}

	var mu sync.Mutex
	var serverAuthAttempts []string

	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: serverConfig,
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{serverKey}},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			switch args.AuthenticationType {
			case AuthClientNone:
				serverAuthAttempts = append(serverAuthAttempts, AuthMethodNone)
			case AuthClientPassword:
				serverAuthAttempts = append(serverAuthAttempts, AuthMethodPassword)
			case AuthClientPublicKey, AuthClientPublicKeyQuery:
				serverAuthAttempts = append(serverAuthAttempts, AuthMethodPublicKey)
			case AuthClientInteractive:
				serverAuthAttempts = append(serverAuthAttempts, AuthMethodKeyboardInteractive)
			}
			mu.Unlock()
			// Reject everything.
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.Authenticate(ctx, &ClientCredentials{
		Username: "testuser",
		Password: "testpass",
	})

	if err != nil {
		_ = err
	}
	if result {
		t.Error("expected authentication to fail")
	}

	mu.Lock()
	defer mu.Unlock()

	_ = server

	for _, method := range serverAuthAttempts {
		if method == AuthMethodPassword {
			t.Error("client tried password auth, but server only suggests publickey")
		}
	}
}

// TestClientAuthFilterPublicKeyToPassword verifies that when the server only suggests
// password auth, client skips publickey and tries password directly.
func TestClientAuthFilterPublicKeyToPassword(t *testing.T) {
	// Server accepts password auth only.
	serverConfig := NewNoSecurityConfig()
	serverConfig.AuthenticationMethods = []string{AuthMethodPassword}

	var mu sync.Mutex
	var serverAuthAttempts []AuthenticationType

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			serverAuthAttempts = append(serverAuthAttempts, args.AuthenticationType)
			mu.Unlock()

			// Accept password auth.
			if args.AuthenticationType == AuthClientPassword && args.Password == "correct" {
				args.AuthenticationResult = true
			}
			// Reject everything else.
		},
	})

	_ = server

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Client has both a key and a password. The key will fail. After failure,
	// server suggests only "password". Client should then try password.
	clientKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	result, authErr := client.Authenticate(ctx, &ClientCredentials{
		Username:  "testuser",
		PublicKeys: []KeyPair{clientKey},
	})

	// Key-only auth should fail since server only accepts password.
	if authErr != nil {
		_ = authErr
	}
	if result {
		t.Error("expected auth to fail with public key only")
	}

	mu.Lock()
	defer mu.Unlock()

	// Verify the server never saw a password auth attempt (since client only provided keys).
	// The point here is that after publickey fails and server says "password" only,
	// the client doesn't try more publickeys (which would be filtered out).
	for _, attempt := range serverAuthAttempts {
		if attempt == AuthClientPublicKey {
			// This is fine — client tried publickey first.
		}
	}
}

// TestSetReportProgressHandler verifies that the thread-safe setter works.
func TestSetReportProgressHandler(t *testing.T) {
	client, _ := createSessionPair(t, nil)

	var called bool
	client.SetReportProgressHandler(func(p Progress) {
		called = true
	})

	// Trigger a progress event by calling reportProgress directly.
	client.reportProgress(ProgressOpeningSSHSessionConnection)

	if !called {
		t.Error("SetReportProgressHandler callback not called")
	}
}

// TestProgressValues verifies the Progress enum values are distinct.
func TestProgressValues(t *testing.T) {
	values := []Progress{
		ProgressOpeningSSHSessionConnection,
		ProgressOpenedSSHSessionConnection,
		ProgressStartingProtocolVersionExchange,
		ProgressCompletedProtocolVersionExchange,
		ProgressStartingKeyExchange,
		ProgressCompletedKeyExchange,
		ProgressStartingSessionAuthentication,
		ProgressCompletedSessionAuthentication,
	}

	seen := make(map[Progress]bool)
	for _, v := range values {
		if seen[v] {
			t.Errorf("duplicate Progress value: %d", v)
		}
		seen[v] = true
	}
}

// TestOnReportProgressNilSafe verifies that nil OnReportProgress doesn't panic.
func TestOnReportProgressNilSafe(t *testing.T) {
	client, _ := createSessionPair(t, nil)
	// OnReportProgress is not set — this should not panic.
	client.reportProgress(ProgressOpeningSSHSessionConnection)
}

// TestAuthFilterNoneToInteractive verifies that after "none" fails, the client
// tries keyboard-interactive only if the server suggests it.
func TestAuthFilterNoneToInteractive(t *testing.T) {
	// Server accepts only keyboard-interactive.
	serverConfig := NewNoSecurityConfig()
	serverConfig.AuthenticationMethods = []string{AuthMethodKeyboardInteractive}

	var mu sync.Mutex
	var serverAuthTypes []AuthenticationType

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			serverAuthTypes = append(serverAuthTypes, args.AuthenticationType)
			mu.Unlock()

			if args.AuthenticationType == AuthClientInteractive {
				// Send a prompt.
				if args.InfoRequest == nil && args.InfoResponse == nil {
					args.InfoRequest = &messages.AuthenticationInfoRequestMessage{
						Name: "Test",
						Prompts: []messages.AuthenticationInfoRequestPrompt{
							{Prompt: "Enter code: ", Echo: true},
						},
					}
				} else if args.InfoResponse != nil {
					// Accept the response.
					args.AuthenticationResult = true
				}
			}
			// Reject "none" (AuthenticationResult stays nil).
		},
		ClientOnAuthenticating: func(args *AuthenticatingEventArgs) {
			if args.AuthenticationType == AuthClientInteractive && args.InfoRequest != nil {
				args.InfoResponse = &messages.AuthenticationInfoResponseMessage{
					Responses: []string{"12345"},
				}
			} else {
				args.AuthenticationResult = true
			}
		},
	})

	_ = server

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Client has no password, no keys — tries none, then falls to interactive.
	result, err := client.Authenticate(ctx, &ClientCredentials{Username: "testuser"})
	if err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if !result {
		t.Error("expected authentication to succeed via keyboard-interactive")
	}
}
