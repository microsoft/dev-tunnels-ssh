// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"sync"
	"testing"
	"time"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// sendHostBasedAuth is a test helper that performs hostbased authentication
// from the client side. It builds the signed data per RFC 4252 Section 9,
// signs with the provided host key, and sends the auth request.
// Returns (success, error).
func sendHostBasedAuth(
	ctx context.Context,
	client *ClientSession,
	hostKey KeyPair,
	username, clientHostname, clientUsername string,
) (bool, error) {
	// Step 1: Verify server host key (auto-approved in tests).
	if !client.authenticateServer() {
		return false, nil
	}

	// Step 2: Request the auth service on the server.
	if err := client.RequestService(AuthServiceName); err != nil {
		return false, err
	}

	// Step 3: Activate client-side auth service.
	svc := client.ActivateService(AuthServiceName)
	if svc == nil {
		return false, nil
	}
	authSvc := svc.(*authenticationService)

	// Step 4: Build the hostbased auth message.
	pubBytes, err := hostKey.GetPublicKeyBytes()
	if err != nil {
		return false, err
	}

	keyAlgoName := hostKey.KeyAlgorithmName()

	sessionID := client.SessionID
	if sessionID == nil {
		sessionID = []byte{}
	}

	// Build signed data: session-id || MSG_USERAUTH_REQUEST || username || serviceName
	// || "hostbased" || key-algorithm || public-key || client-hostname || client-username
	w := sshio.NewSSHDataWriter(make([]byte, 0, 256))
	w.WriteBinary(sessionID)
	_ = w.WriteByte(messages.MsgNumAuthenticationRequest)
	w.WriteString(username)
	w.WriteString(ConnectionServiceName)
	w.WriteString(AuthMethodHostBased)
	w.WriteString(keyAlgoName)
	w.WriteBinary(pubBytes)
	w.WriteString(clientHostname)
	w.WriteString(clientUsername)
	signedData := w.ToBuffer()

	rawSig, err := signData(hostKey, signedData)
	if err != nil {
		return false, err
	}
	wrappedSig := wrapSignatureData(keyAlgoName, rawSig)

	authMsg := &messages.AuthenticationRequestMessage{
		Username:         username,
		ServiceName:      ConnectionServiceName,
		MethodName:       AuthMethodHostBased,
		KeyAlgorithmName: keyAlgoName,
		PublicKey:        pubBytes,
		ClientHostname:   clientHostname,
		ClientUsername:   clientUsername,
		Signature:        wrappedSig,
	}

	result, err := client.authenticateWithMethodResult(ctx, authSvc, authMsg)
	if err != nil {
		return false, err
	}
	return result.success, nil
}

// TestHostBasedAuthSuccess verifies that hostbased authentication succeeds when
// the server handler approves, and the server's Authenticating event fires with
// AuthClientHostBased type.
func TestHostBasedAuthSuccess(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	var receivedAuthType AuthenticationType
	var mu sync.Mutex

	serverConfig := NewDefaultConfig()
	serverConfig.AuthenticationMethods = append(serverConfig.AuthenticationMethods, AuthMethodHostBased)

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: serverConfig,
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			defer mu.Unlock()
			receivedAuthType = args.AuthenticationType
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := sendHostBasedAuth(ctx, client, hostKey, "testuser", "client.example.com", "localuser")
	if err != nil {
		t.Fatalf("hostbased auth returned error: %v", err)
	}
	if !success {
		t.Fatal("hostbased auth returned false, want true")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedAuthType != AuthClientHostBased {
		t.Errorf("server received AuthenticationType = %d, want AuthClientHostBased (%d)",
			receivedAuthType, AuthClientHostBased)
	}
}

// TestHostBasedAuthFailure verifies that hostbased authentication fails when
// the server handler rejects (does not set AuthenticationResult).
func TestHostBasedAuthFailure(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	var handlerCalled bool
	var mu sync.Mutex

	serverConfig := NewDefaultConfig()
	serverConfig.AuthenticationMethods = append(serverConfig.AuthenticationMethods, AuthMethodHostBased)

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: serverConfig,
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			defer mu.Unlock()
			handlerCalled = true
			// Do NOT set AuthenticationResult → rejection.
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := sendHostBasedAuth(ctx, client, hostKey, "testuser", "client.example.com", "localuser")
	if err != nil {
		t.Fatalf("hostbased auth returned error: %v", err)
	}
	if success {
		t.Fatal("hostbased auth returned true, want false when handler rejects")
	}

	mu.Lock()
	defer mu.Unlock()
	if !handlerCalled {
		t.Error("server OnAuthenticating handler was not called")
	}
}

// TestHostBasedAuthBadSignature verifies that hostbased authentication fails
// when the client sends an invalid signature, and the handler is NOT called
// (failure occurs before reaching the handler).
func TestHostBasedAuthBadSignature(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	// Generate two different keys: one for the public key field, another for signing.
	// This creates a valid-looking message with a mismatched signature.
	pubKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate public key: %v", err)
	}
	wrongKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	var handlerCalled bool
	var mu sync.Mutex

	serverConfig := NewDefaultConfig()
	serverConfig.AuthenticationMethods = append(serverConfig.AuthenticationMethods, AuthMethodHostBased)

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: serverConfig,
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			defer mu.Unlock()
			handlerCalled = true
			args.AuthenticationResult = true // Would approve if reached.
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Manually build a hostbased auth message with mismatched key/signature.
	if !client.authenticateServer() {
		t.Fatal("server auth failed")
	}
	if err := client.RequestService(AuthServiceName); err != nil {
		t.Fatalf("request service: %v", err)
	}
	svc := client.ActivateService(AuthServiceName)
	authSvc := svc.(*authenticationService)

	pubBytes, _ := pubKey.GetPublicKeyBytes()
	keyAlgoName := pubKey.KeyAlgorithmName()

	sessionID := client.SessionID
	if sessionID == nil {
		sessionID = []byte{}
	}

	// Build signed data (using pubKey's public bytes in the data).
	w := sshio.NewSSHDataWriter(make([]byte, 0, 256))
	w.WriteBinary(sessionID)
	_ = w.WriteByte(messages.MsgNumAuthenticationRequest)
	w.WriteString("testuser")
	w.WriteString(ConnectionServiceName)
	w.WriteString(AuthMethodHostBased)
	w.WriteString(keyAlgoName)
	w.WriteBinary(pubBytes)
	w.WriteString("client.example.com")
	w.WriteString("localuser")
	signedData := w.ToBuffer()

	// Sign with the WRONG key — signature won't match pubKey.
	rawSig, err := signData(wrongKey, signedData)
	if err != nil {
		t.Fatalf("sign data: %v", err)
	}
	wrappedSig := wrapSignatureData(keyAlgoName, rawSig)

	authMsg := &messages.AuthenticationRequestMessage{
		Username:         "testuser",
		ServiceName:      ConnectionServiceName,
		MethodName:       AuthMethodHostBased,
		KeyAlgorithmName: keyAlgoName,
		PublicKey:        pubBytes,
		ClientHostname:   "client.example.com",
		ClientUsername:   "localuser",
		Signature:        wrappedSig,
	}

	result, err := client.authenticateWithMethodResult(ctx, authSvc, authMsg)
	if err != nil {
		t.Fatalf("auth returned error: %v", err)
	}
	if result.success {
		t.Fatal("auth succeeded with bad signature, want failure")
	}

	mu.Lock()
	defer mu.Unlock()
	if handlerCalled {
		t.Error("OnAuthenticating handler was called despite bad signature — should fail before reaching handler")
	}
}

// TestHostBasedAuthEventFields verifies that the AuthenticatingEventArgs
// has ClientHostname and ClientUsername correctly populated from the wire
// message fields.
func TestHostBasedAuthEventFields(t *testing.T) {
	serverKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	var receivedAuthType AuthenticationType
	var receivedUsername string
	var receivedClientHostname string
	var receivedClientUsername string
	var receivedPublicKey KeyPair
	var mu sync.Mutex

	serverConfig := NewDefaultConfig()
	serverConfig.AuthenticationMethods = append(serverConfig.AuthenticationMethods, AuthMethodHostBased)

	client, _ := createSessionPair(t, &SessionPairOptions{
		ClientConfig: NewDefaultConfig(),
		ServerConfig: serverConfig,
		ServerCredentials: &ServerCredentials{
			PublicKeys: []KeyPair{serverKey},
		},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			mu.Lock()
			defer mu.Unlock()
			receivedAuthType = args.AuthenticationType
			receivedUsername = args.Username
			receivedClientHostname = args.ClientHostname
			receivedClientUsername = args.ClientUsername
			receivedPublicKey = args.PublicKey
			args.AuthenticationResult = true
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	success, err := sendHostBasedAuth(ctx, client, hostKey, "sshuser", "myhost.example.com", "hostlocaluser")
	if err != nil {
		t.Fatalf("hostbased auth returned error: %v", err)
	}
	if !success {
		t.Fatal("hostbased auth returned false, want true")
	}

	mu.Lock()
	defer mu.Unlock()

	if receivedAuthType != AuthClientHostBased {
		t.Errorf("AuthenticationType = %d, want AuthClientHostBased (%d)",
			receivedAuthType, AuthClientHostBased)
	}
	if receivedUsername != "sshuser" {
		t.Errorf("Username = %q, want %q", receivedUsername, "sshuser")
	}
	if receivedClientHostname != "myhost.example.com" {
		t.Errorf("ClientHostname = %q, want %q", receivedClientHostname, "myhost.example.com")
	}
	if receivedClientUsername != "hostlocaluser" {
		t.Errorf("ClientUsername = %q, want %q", receivedClientUsername, "hostlocaluser")
	}
	if receivedPublicKey == nil {
		t.Fatal("PublicKey is nil")
	}

	// Verify the server received the correct host public key.
	hostPubBytes, err := hostKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("get host public key bytes: %v", err)
	}
	receivedPubBytes, err := receivedPublicKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("get received public key bytes: %v", err)
	}
	if len(hostPubBytes) != len(receivedPubBytes) {
		t.Errorf("public key bytes length mismatch: got %d, want %d",
			len(receivedPubBytes), len(hostPubBytes))
	}
	for i := range hostPubBytes {
		if hostPubBytes[i] != receivedPubBytes[i] {
			t.Errorf("public key bytes differ at index %d", i)
			break
		}
	}
}
