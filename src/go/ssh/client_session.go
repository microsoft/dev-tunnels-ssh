// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// ClientSession is an SSH client session that connects to a server.
type ClientSession struct {
	Session
}

// NewClientSession creates a new SSH client session with the given configuration.
// If config is nil, a no-security configuration is used.
func NewClientSession(config *SessionConfig) *ClientSession {
	if config == nil {
		config = NewNoSecurityConfig()
	}
	cs := &ClientSession{
		Session: Session{
			Config:   config,
			isClient: true,
		},
	}
	cs.sessionMetrics.initMetrics()
	return cs
}

// Authenticate authenticates the client session with the given credentials.
// It first verifies the server's host key (if any), then sends authentication
// credentials to the server. Returns true if authentication succeeds.
func (cs *ClientSession) Authenticate(ctx context.Context, creds *ClientCredentials) (bool, error) {
	if creds == nil {
		creds = &ClientCredentials{}
	}

	// Step 1: Server authentication (verify server host key).
	// In no-security mode (kex:none), there's no host key, so this auto-approves.
	if !cs.authenticateServer() {
		cs.CloseWithReason(ctx, messages.DisconnectHostKeyNotVerifiable,
			"Server host key verification failed.")
		return false, nil
	}

	// Step 2: Send a service request to the server (fire-and-forget).
	// Matching C#/TS behavior: don't wait for ServiceAccept. If the server
	// rejects the service, subsequent auth messages will fail.
	serviceMsg := &messages.ServiceRequestMessage{ServiceName: AuthServiceName}
	if err := cs.SendMessage(serviceMsg); err != nil {
		return false, err
	}

	// Step 3: Activate client-side auth service.
	svc := cs.ActivateService(AuthServiceName)
	if svc == nil {
		return false, fmt.Errorf("authentication service not registered")
	}
	authSvc, ok := svc.(*authenticationService)
	if !ok {
		return false, fmt.Errorf("invalid authentication service type")
	}

	cs.reportProgress(ProgressStartingSessionAuthentication)

	// Step 4: Build and execute authentication method queue.
	// Try methods in order, filtering by server-suggested methods after each failure.
	// serverSuggested tracks methods the server will accept (from AuthenticationFailureMessage).
	var serverSuggested []string

	// Try public keys first, then password, then none/interactive.
	if len(creds.PublicKeys) > 0 {
		for _, key := range creds.PublicKeys {
			if key == nil {
				continue
			}

			// If the key doesn't have private material, try the provider.
			authKey := key
			if !key.HasPrivateKey() {
				if creds.PrivateKeyProvider == nil {
					continue
				}
				resolved, err := creds.PrivateKeyProvider(ctx, key)
				if err != nil || resolved == nil || !resolved.HasPrivateKey() {
					continue
				}
				authKey = resolved
			}

			// Check if server has suggested methods that exclude publickey.
			if len(serverSuggested) > 0 && !containsMethod(serverSuggested, AuthMethodPublicKey) {
				continue
			}
			result, err := cs.authenticateWithPublicKeyResult(ctx, authSvc, creds.Username, authKey)
			if err != nil {
				return false, err
			}
			if result.success {
				return true, nil
			}
			if len(result.suggestedMethods) > 0 {
				serverSuggested = result.suggestedMethods
			}
		}
	}

	// Determine password credentials: use PasswordProvider if set, else static fields.
	passwordUsername := creds.Username
	passwordValue := creds.Password
	hasPassword := creds.Password != ""

	if creds.PasswordProvider != nil {
		provUser, provPass, provErr := creds.PasswordProvider(ctx)
		if provErr != nil {
			// Provider returned an error — close the session (matching C#'s AuthCancelledByUser).
			cs.CloseWithReason(ctx, messages.DisconnectAuthCancelledByUser,
				"Authentication cancelled by user.")
			return false, provErr
		}
		if provUser == "" && provPass == "" {
			// Provider returned empty credentials — skip password auth.
			hasPassword = false
		} else {
			passwordUsername = provUser
			passwordValue = provPass
			hasPassword = true
		}
	}

	if hasPassword {
		// Skip password auth if server doesn't suggest it.
		if len(serverSuggested) > 0 && !containsMethod(serverSuggested, AuthMethodPassword) {
			return false, nil
		}
		return cs.authenticateWithMethod(ctx, authSvc, &messages.AuthenticationRequestMessage{
			Username:    passwordUsername,
			ServiceName: ConnectionServiceName,
			MethodName:  AuthMethodPassword,
			Password:    passwordValue,
		})
	}

	// No public keys and no password — try "none" method first.
	if len(creds.PublicKeys) == 0 {
		// Skip none if server suggested specific methods that exclude it.
		if len(serverSuggested) == 0 || containsMethod(serverSuggested, AuthMethodNone) {
			result, err := cs.authenticateWithMethodResult(ctx, authSvc, &messages.AuthenticationRequestMessage{
				Username:    creds.Username,
				ServiceName: ConnectionServiceName,
				MethodName:  AuthMethodNone,
			})
			if err != nil {
				return false, err
			}
			if result.success {
				return true, nil
			}
			if len(result.suggestedMethods) > 0 {
				serverSuggested = result.suggestedMethods
			}
		}
	}

	// Fall back to keyboard-interactive if configured and server suggests it.
	for _, m := range cs.Config.AuthenticationMethods {
		if m == AuthMethodKeyboardInteractive {
			if len(serverSuggested) > 0 && !containsMethod(serverSuggested, AuthMethodKeyboardInteractive) {
				continue
			}
			return cs.authenticateWithMethod(ctx, authSvc, &messages.AuthenticationRequestMessage{
				Username:    creds.Username,
				ServiceName: ConnectionServiceName,
				MethodName:  AuthMethodKeyboardInteractive,
			})
		}
	}

	return false, nil
}

// authenticateWithMethod sends an auth request and waits for the result.
func (cs *ClientSession) authenticateWithMethod(ctx context.Context, authSvc *authenticationService, msg *messages.AuthenticationRequestMessage) (bool, error) {
	result, err := cs.authenticateWithMethodResult(ctx, authSvc, msg)
	if err != nil {
		return false, err
	}
	return result.success, nil
}

// authenticateWithMethodResult sends an auth request and waits for the full result,
// including server-suggested methods on failure.
func (cs *ClientSession) authenticateWithMethodResult(ctx context.Context, authSvc *authenticationService, msg *messages.AuthenticationRequestMessage) (*authResult, error) {
	authSvc.currentMethodName = msg.MethodName
	if err := cs.SendMessage(msg); err != nil {
		return nil, err
	}

	select {
	case result := <-authSvc.authComplete:
		return result, nil
	case <-cs.done:
		return nil, &ConnectionError{
			Reason: messages.DisconnectConnectionLost,
			Msg:    "session closed during authentication",
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// authenticateWithPublicKeyResult creates a signed public key authentication request
// and returns the full authResult including server-suggested methods on failure.
func (cs *ClientSession) authenticateWithPublicKeyResult(ctx context.Context, authSvc *authenticationService, username string, key KeyPair) (*authResult, error) {
	publicKeyBytes, err := key.GetPublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key bytes: %w", err)
	}

	keyAlgoName := key.KeyAlgorithmName()
	signingAlgoName := keyAlgoName

	if keyAlgoName == AlgoKeyRsa {
		if rsaKey, ok := key.(*RsaKeyPair); ok {
			signingAlgoName = rsaSigningAlgorithm(rsaKey)
		} else {
			signingAlgoName = AlgoPKRsaSha256
		}
	}

	sessionID := cs.SessionID
	if sessionID == nil {
		sessionID = []byte{}
	}

	signedDataWriter := sshio.NewSSHDataWriter(make([]byte, 0, 256))
	signedDataWriter.WriteBinary(sessionID)
	_ = signedDataWriter.WriteByte(messages.MsgNumAuthenticationRequest)
	signedDataWriter.WriteString(username)
	signedDataWriter.WriteString(ConnectionServiceName)
	signedDataWriter.WriteString(AuthMethodPublicKey)
	signedDataWriter.WriteBoolean(true)
	signedDataWriter.WriteString(signingAlgoName)
	signedDataWriter.WriteBinary(publicKeyBytes)
	signedData := signedDataWriter.ToBuffer()

	rawSignature, err := signData(key, signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign authentication data: %w", err)
	}

	wrappedSignature := wrapSignatureData(signingAlgoName, rawSignature)

	authMsg := &messages.AuthenticationRequestMessage{
		Username:         username,
		ServiceName:      ConnectionServiceName,
		MethodName:       AuthMethodPublicKey,
		HasSignature:     true,
		KeyAlgorithmName: signingAlgoName,
		PublicKey:        publicKeyBytes,
		Signature:        wrappedSignature,
	}

	return cs.authenticateWithMethodResult(ctx, authSvc, authMsg)
}

// containsMethod checks if a method name is in the given list.
func containsMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

// AuthenticatePublicKeyQuery sends a public key query to check if the server
// would accept the given key, without proving possession of the private key.
func (cs *ClientSession) AuthenticatePublicKeyQuery(ctx context.Context, username string, key KeyPair) (bool, error) {
	svc := cs.GetService(AuthServiceName)
	if svc == nil {
		// Need to set up auth service first.
		if err := cs.RequestService(AuthServiceName); err != nil {
			return false, err
		}
		svc = cs.ActivateService(AuthServiceName)
		if svc == nil {
			return false, fmt.Errorf("authentication service not registered")
		}
	}
	authSvc, ok := svc.(*authenticationService)
	if !ok {
		return false, fmt.Errorf("invalid authentication service type")
	}

	publicKeyBytes, err := key.GetPublicKeyBytes()
	if err != nil {
		return false, fmt.Errorf("failed to get public key bytes: %w", err)
	}

	// Determine the algorithm name.
	keyAlgoName := key.KeyAlgorithmName()
	if keyAlgoName == AlgoKeyRsa {
		if rsaKey, ok := key.(*RsaKeyPair); ok {
			keyAlgoName = rsaSigningAlgorithm(rsaKey)
		} else {
			keyAlgoName = AlgoPKRsaSha256
		}
	}

	queryMsg := &messages.AuthenticationRequestMessage{
		Username:         username,
		ServiceName:      ConnectionServiceName,
		MethodName:       AuthMethodPublicKey,
		HasSignature:     false,
		KeyAlgorithmName: keyAlgoName,
		PublicKey:        publicKeyBytes,
	}

	return cs.authenticateWithMethod(ctx, authSvc, queryMsg)
}

// authenticateServer verifies the server's host key (if any).
// Returns true if the server is verified or if there's no host key (no-security mode).
func (cs *ClientSession) authenticateServer() bool {
	// In no-security mode (kex:none), there's no host key to verify.
	if cs.kexService == nil {
		return true
	}

	hostKey := cs.kexService.getHostKey()
	if hostKey == nil {
		return true // No host key = no key exchange, auto-approve.
	}

	if cs.OnAuthenticating != nil {
		args := &AuthenticatingEventArgs{
			AuthenticationType: AuthServerPublicKey,
			PublicKey:           hostKey,
		}
		cs.OnAuthenticating(args)
		return args.AuthenticationResult != nil
	}

	// No handler set and there's a host key — reject.
	return false
}
