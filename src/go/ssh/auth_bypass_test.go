package ssh

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// createUnauthenticatedEncryptedPair connects an encrypted pair where the
// server denies every authentication attempt and counts callback invocations.
func createUnauthenticatedEncryptedPair(t *testing.T) (*ClientSession, *ServerSession, *int32) {
	t.Helper()

	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	var authCalls int32
	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig:      NewDefaultConfig(),
		ServerConfig:      NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{hostKey}},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			atomic.AddInt32(&authCalls, 1)
		},
	})
	return client, server, &authCalls
}

// TestPeerCannotSetServerAuthenticatedWithAuthSuccess verifies that a client
// sending SSH_MSG_USERAUTH_SUCCESS does not authenticate a server session.
func TestPeerCannotSetServerAuthenticatedWithAuthSuccess(t *testing.T) {
	client, server, authCalls := createUnauthenticatedEncryptedPair(t)

	if err := client.SendMessage(&messages.ServiceRequestMessage{ServiceName: AuthServiceName}); err != nil {
		t.Fatalf("send service request: %v", err)
	}
	if err := client.SendMessage(&messages.AuthenticationSuccessMessage{}); err != nil {
		t.Fatalf("send auth success: %v", err)
	}

	// Allow the server to process the messages: a following request is
	// dispatched after both, so its (refused) reply proves they were handled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ok, err := client.Request(ctx, &messages.SessionRequestMessage{
		RequestType: "test-request",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if ok {
		t.Error("session request was accepted by an unauthenticated session")
	}

	server.mu.Lock()
	canAccept := server.canAcceptRequests()
	principal := server.Principal
	server.mu.Unlock()
	if canAccept {
		t.Error("server accepts requests after peer-sent USERAUTH_SUCCESS")
	}
	if principal != nil {
		t.Errorf("server Principal = %v, want nil", principal)
	}
	if got := atomic.LoadInt32(authCalls); got != 0 {
		t.Errorf("OnAuthenticating called %d times, want 0", got)
	}
}

// TestUnauthenticatedChannelOpenRefused verifies that an encrypted server
// session refuses channel opens from a peer that never authenticated.
func TestUnauthenticatedChannelOpenRefused(t *testing.T) {
	client, _, authCalls := createUnauthenticatedEncryptedPair(t)

	assertChannelOpenProhibited(t, client, "an unauthenticated session")
	if got := atomic.LoadInt32(authCalls); got != 0 {
		t.Errorf("OnAuthenticating called %d times, want 0", got)
	}

	// The same bypass attempt (USERAUTH_SUCCESS then open) must still fail.
	if err := client.SendMessage(&messages.AuthenticationSuccessMessage{}); err != nil {
		t.Fatalf("send auth success: %v", err)
	}
	assertChannelOpenProhibited(t, client, "a peer-sent USERAUTH_SUCCESS")
}

// assertChannelOpenProhibited attempts a channel open with its own deadline
// and requires an explicit administrativelyProhibited refusal, so a timeout
// cannot be mistaken for an authentication rejection.
func assertChannelOpenProhibited(t *testing.T, client *ClientSession, after string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, err := client.OpenChannel(ctx)
	if err == nil {
		ch.Close()
		t.Fatalf("channel open succeeded on %s", after)
	}
	var chErr *ChannelError
	if !errors.As(err, &chErr) {
		t.Fatalf("channel open on %s failed with %T (%v), want *ChannelError", after, err, err)
	}
	if chErr.Reason != messages.ChannelOpenFailureAdministrativelyProhibited {
		t.Fatalf("channel open on %s reason = %v, want administrativelyProhibited", after, chErr.Reason)
	}
}

// TestAuthenticatedChannelOpenSucceeds is the positive control: after real
// authentication the same channel open is accepted.
func TestAuthenticatedChannelOpenSucceeds(t *testing.T) {
	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig:      NewDefaultConfig(),
		ServerConfig:      NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{hostKey}},
		Authenticate:      true,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() { _, _ = server.AcceptChannel(ctx) }()
	ch, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("authenticated channel open failed: %v", err)
	}
	ch.Close()

	// Reverse direction: the authenticated client must accept a server-opened
	// channel, which relies on the client Principal set after host
	// authentication.
	go func() { _, _ = client.AcceptChannel(ctx) }()
	serverCh, err := server.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("server-to-client channel open failed: %v", err)
	}
	serverCh.Close()
}

// TestServerIgnoresClientDirectionAuthMessages verifies that a
// server session ignores messages that only a server may send.
func TestServerIgnoresClientDirectionAuthMessages(t *testing.T) {
	_, server, _ := createUnauthenticatedEncryptedPair(t)

	svc := server.ActivateService(AuthServiceName)
	authSvc, ok := svc.(*authenticationService)
	if !ok {
		t.Fatalf("unexpected auth service type %T", svc)
	}

	for _, msgType := range []byte{
		messages.MsgNumAuthenticationSuccess,
		messages.MsgNumAuthenticationFailure,
		messages.MsgNumPublicKeyOk,
	} {
		if err := authSvc.handleMessage(msgType, []byte{msgType}); err != nil {
			t.Errorf("handleMessage(%d) = %v, want nil", msgType, err)
		}
	}

	server.mu.Lock()
	canAccept := server.canAcceptRequests()
	server.mu.Unlock()
	if canAccept {
		t.Error("server became able to accept requests from a client-direction auth message")
	}
}

// TestClientIgnoresServerDirectionAuthMessages verifies that a client session
// ignores messages that only a client may send. Before role-based routing, a
// peer could drive the client's authentication handlers (including
// OnAuthenticating) with a forged USERAUTH_REQUEST or info response.
func TestClientIgnoresServerDirectionAuthMessages(t *testing.T) {
	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	var clientAuthCalls int32
	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig:      NewDefaultConfig(),
		ServerConfig:      NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{hostKey}},
		ClientOnAuthenticating: func(args *AuthenticatingEventArgs) {
			atomic.AddInt32(&clientAuthCalls, 1)
			args.AuthenticationResult = true
		},
	})

	// The messages are only routed once the client's auth service is active.
	client.ActivateService(AuthServiceName)

	for _, msg := range []messages.Message{
		&messages.AuthenticationRequestMessage{
			Username:    "attacker",
			ServiceName: ConnectionServiceName,
			MethodName:  "none",
		},
		&messages.AuthenticationInfoResponseMessage{Responses: []string{"x"}},
	} {
		if err := server.SendMessage(msg); err != nil {
			t.Fatalf("send %T: %v", msg, err)
		}
	}

	// A following request is dispatched after both messages, so its reply
	// proves they were handled.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ok, err := server.Request(ctx, &messages.SessionRequestMessage{
		RequestType: "test-request",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if ok {
		t.Error("request was accepted by an unauthenticated client session")
	}

	if got := atomic.LoadInt32(&clientAuthCalls); got != 0 {
		t.Errorf("client OnAuthenticating called %d times, want 0", got)
	}
	client.mu.Lock()
	canAccept := client.canAcceptRequests()
	principal := client.Principal
	client.mu.Unlock()
	if canAccept {
		t.Error("client became able to accept requests from a server-direction auth message")
	}
	if principal != nil {
		t.Errorf("client Principal = %v, want nil", principal)
	}
}

// TestUnauthenticatedRequestsDoNotReachHandlers verifies that requests an
// unauthenticated peer can still send (including the extension requests that
// are exempt from the gate) never reach application handlers or create state,
// and that the same request is delivered once the client authenticates.
func TestUnauthenticatedRequestsDoNotReachHandlers(t *testing.T) {
	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig:      NewDefaultConfig(),
		ServerConfig:      NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{hostKey}},
	})

	var handled int32
	server.OnRequest = func(args *RequestEventArgs) {
		atomic.AddInt32(&handled, 1)
		args.IsAuthorized = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ok, err := client.Request(ctx, &messages.SessionRequestMessage{
		RequestType: "test-request",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if ok {
		t.Error("session request was accepted before authentication")
	}

	// The initial-channel-request extension bypasses the gate, so it must not
	// be able to reach a channel on an unauthenticated session.
	ok, _, err = client.RequestWithPayload(ctx, &messages.SessionChannelRequestMessage{
		SessionRequestMessage: messages.SessionRequestMessage{
			RequestType: ExtensionRequestInitialChannelRequest,
			WantReply:   true,
		},
		SenderChannel: 0,
		Request: &messages.ChannelRequestMessage{
			RequestType: "exec",
		},
	}, true)
	if err != nil {
		t.Fatalf("initial channel request failed: %v", err)
	}
	if ok {
		t.Error("initial channel request succeeded before authentication")
	}

	assertChannelOpenProhibited(t, client, "an unauthenticated session")

	server.mu.Lock()
	channelCount := len(server.channels)
	server.mu.Unlock()
	if channelCount != 0 {
		t.Errorf("server has %d channels after refused opens, want 0", channelCount)
	}
	if got := atomic.LoadInt32(&handled); got != 0 {
		t.Fatalf("OnRequest called %d times before authentication, want 0", got)
	}

	// Positive control: the same request is handled after authentication.
	authenticateTestClient(t, ctx, client)
	ok, err = client.Request(ctx, &messages.SessionRequestMessage{
		RequestType: "test-request",
		WantReply:   true,
	})
	if err != nil {
		t.Fatalf("authenticated request failed: %v", err)
	}
	if !ok {
		t.Error("session request was refused after authentication")
	}
	if got := atomic.LoadInt32(&handled); got != 1 {
		t.Errorf("OnRequest called %d times after authentication, want 1", got)
	}
}
