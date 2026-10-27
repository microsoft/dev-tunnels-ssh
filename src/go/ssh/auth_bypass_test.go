package ssh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// createUnauthenticatedEncryptedPair connects an encrypted pair where the
// server denies every authentication attempt and counts callback invocations.
func createUnauthenticatedEncryptedPair(t *testing.T) (*ClientSession, *ServerSession, *int) {
	t.Helper()

	hostKey, err := GenerateKeyPair(AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}

	authCalls := 0
	client, server := createSessionPair(t, &SessionPairOptions{
		ClientConfig:      NewDefaultConfig(),
		ServerConfig:      NewDefaultConfig(),
		ServerCredentials: &ServerCredentials{PublicKeys: []KeyPair{hostKey}},
		ServerOnAuthenticating: func(args *AuthenticatingEventArgs) {
			authCalls++
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
	if *authCalls != 0 {
		t.Errorf("OnAuthenticating called %d times, want 0", *authCalls)
	}
}

// TestUnauthenticatedChannelOpenRefused verifies that an encrypted server
// session refuses channel opens from a peer that never authenticated.
func TestUnauthenticatedChannelOpenRefused(t *testing.T) {
	client, _, authCalls := createUnauthenticatedEncryptedPair(t)

	assertChannelOpenProhibited(t, client, "an unauthenticated session")
	if *authCalls != 0 {
		t.Errorf("OnAuthenticating called %d times, want 0", *authCalls)
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
