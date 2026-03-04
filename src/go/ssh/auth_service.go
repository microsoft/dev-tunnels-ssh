// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"crypto"
	"fmt"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// AuthServiceName is the SSH service name for user authentication.
const AuthServiceName = "ssh-userauth"

// ConnectionServiceName is the service name requested during auth.
const ConnectionServiceName = "ssh-connection"

// authResult is the result from a client-side authentication attempt.
type authResult struct {
	success          bool
	suggestedMethods []string // server-suggested methods from AuthenticationFailureMessage
}

// authenticationService handles SSH authentication protocol messages.
// It is activated on the server side by a service request for "ssh-userauth",
// and on the client side explicitly when Authenticate() is called.
type authenticationService struct {
	session      *Session
	failureCount int

	// Client-side state
	authComplete chan *authResult // signals auth result to the client

	// Current auth method context (used to disambiguate message type 60).
	currentMethodName string

	// Current username for the ongoing authentication (preserved for multi-round interactive).
	currentUsername string

	// Current service name from the authentication request (usually "ssh-connection").
	// Activated on the server side after auth success, matching C#/TS behavior.
	currentServiceName string
}

// newAuthenticationService creates a new authentication service.
func newAuthenticationService(session *Session, _ interface{}) Service {
	return &authenticationService{
		session:      session,
		authComplete: make(chan *authResult, 1),
	}
}

// Service interface implementation (no-ops for non-auth hooks).
func (s *authenticationService) OnSessionRequest(args *RequestEventArgs)              {}
func (s *authenticationService) OnChannelOpening(args *ChannelOpeningEventArgs)       {}
func (s *authenticationService) OnChannelRequest(ch *Channel, args *RequestEventArgs) {}
func (s *authenticationService) Close() error                                         { return nil }

// handleMessage routes an authentication message to the appropriate handler.
func (s *authenticationService) handleMessage(msgType byte, payload []byte) error {
	switch msgType {
	case messages.MsgNumAuthenticationRequest:
		return s.handleAuthRequest(payload)
	case messages.MsgNumAuthenticationSuccess:
		return s.handleAuthSuccess()
	case messages.MsgNumAuthenticationFailure:
		return s.handleAuthFailure(payload)
	case messages.MsgNumPublicKeyOk: // type 60 — PublicKeyOk or AuthInfoRequest
		return s.handleMessage60(payload)
	case messages.MsgNumAuthInfoResponse: // type 61
		return s.handleAuthInfoResponse(payload)
	default:
		return nil
	}
}

// handleMessage60 handles message type 60 which is overloaded:
// PublicKeyOk when current method is "publickey", AuthInfoRequest when "keyboard-interactive".
func (s *authenticationService) handleMessage60(payload []byte) error {
	if s.currentMethodName == AuthMethodPublicKey {
		return s.handlePublicKeyOk(payload)
	}
	if s.currentMethodName == AuthMethodKeyboardInteractive {
		return s.handleAuthInfoRequest(payload)
	}
	return nil
}

// handleAuthRequest processes an incoming authentication request (server side).
func (s *authenticationService) handleAuthRequest(payload []byte) error {
	msg := &messages.AuthenticationRequestMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read auth request: %w", err)
	}

	// Track the current method, username, and service name for multi-round flows.
	s.currentMethodName = msg.MethodName
	s.currentUsername = msg.Username
	s.currentServiceName = msg.ServiceName

	// Check if the method is enabled.
	methodEnabled := false
	for _, m := range s.session.Config.AuthenticationMethods {
		if m == msg.MethodName {
			methodEnabled = true
			break
		}
	}

	if !methodEnabled {
		s.currentMethodName = ""
		return s.sendAuthFailure()
	}

	switch msg.MethodName {
	case AuthMethodNone:
		return s.handleAuthenticating(&AuthenticatingEventArgs{
			AuthenticationType: AuthClientNone,
			Username:           msg.Username,
		})

	case AuthMethodPassword:
		return s.handleAuthenticating(&AuthenticatingEventArgs{
			AuthenticationType: AuthClientPassword,
			Username:           msg.Username,
			Password:           msg.Password,
		})

	case AuthMethodPublicKey:
		return s.handlePublicKeyAuth(msg)

	case AuthMethodKeyboardInteractive:
		return s.handleAuthenticating(&AuthenticatingEventArgs{
			AuthenticationType: AuthClientInteractive,
			Username:           msg.Username,
		})

	case AuthMethodHostBased:
		return s.handleHostBasedAuth(msg)

	default:
		s.currentMethodName = ""
		return s.sendAuthFailure()
	}
}

// handlePublicKeyAuth processes a public key authentication request.
// It handles both the query (no signature) and full auth (with signature) flows.
func (s *authenticationService) handlePublicKeyAuth(msg *messages.AuthenticationRequestMessage) error {
	// Create a public-key-only KeyPair from the presented public key bytes.
	publicKey, err := importPublicKey(msg.KeyAlgorithmName, msg.PublicKey)
	if err != nil {
		return s.sendAuthFailure()
	}

	if !msg.HasSignature {
		// Public key query: check if the server would accept this key.
		return s.handleAuthenticating(&AuthenticatingEventArgs{
			AuthenticationType: AuthClientPublicKeyQuery,
			Username:           msg.Username,
			PublicKey:           publicKey,
		})
	}

	// Full public key authentication: verify the signature.
	sessionID := s.session.SessionID
	if sessionID == nil {
		sessionID = []byte{}
	}

	// Build the signed data: sessionId || msgType || username || serviceName || "publickey" || true || keyAlgo || publicKey
	signedDataWriter := sshio.NewSSHDataWriter(make([]byte, 0, 256))
	signedDataWriter.WriteBinary(sessionID)
	_ = signedDataWriter.WriteByte(messages.MsgNumAuthenticationRequest)
	signedDataWriter.WriteString(msg.Username)
	signedDataWriter.WriteString(msg.ServiceName)
	signedDataWriter.WriteString(AuthMethodPublicKey)
	signedDataWriter.WriteBoolean(true)
	signedDataWriter.WriteString(msg.KeyAlgorithmName)
	signedDataWriter.WriteBinary(msg.PublicKey)
	signedData := signedDataWriter.ToBuffer()

	// Unwrap the signature data: [string algorithmName][binary rawSignature]
	rawSignature, err := unwrapSignatureData(msg.Signature)
	if err != nil {
		return s.sendAuthFailure()
	}

	// Verify the signature.
	verified, err := verifySignature(publicKey, signedData, rawSignature)
	if err != nil || !verified {
		return s.sendAuthFailure()
	}

	return s.handleAuthenticating(&AuthenticatingEventArgs{
		AuthenticationType: AuthClientPublicKey,
		Username:           msg.Username,
		PublicKey:           publicKey,
	})
}

// handleHostBasedAuth processes a host-based authentication request (RFC 4252 Section 9).
// It verifies the signature over session-id + message fields and fires the Authenticating event.
func (s *authenticationService) handleHostBasedAuth(msg *messages.AuthenticationRequestMessage) error {
	// Import the host's public key from the wire format.
	publicKey, err := importPublicKey(msg.KeyAlgorithmName, msg.PublicKey)
	if err != nil {
		return s.sendAuthFailure()
	}

	// Build the signed data per RFC 4252 Section 9:
	// session-id || SSH_MSG_USERAUTH_REQUEST || username || serviceName || "hostbased"
	// || key-algorithm || public-key || client-hostname || client-username
	sessionID := s.session.SessionID
	if sessionID == nil {
		sessionID = []byte{}
	}

	signedDataWriter := sshio.NewSSHDataWriter(make([]byte, 0, 256))
	signedDataWriter.WriteBinary(sessionID)
	_ = signedDataWriter.WriteByte(messages.MsgNumAuthenticationRequest)
	signedDataWriter.WriteString(msg.Username)
	signedDataWriter.WriteString(msg.ServiceName)
	signedDataWriter.WriteString(AuthMethodHostBased)
	signedDataWriter.WriteString(msg.KeyAlgorithmName)
	signedDataWriter.WriteBinary(msg.PublicKey)
	signedDataWriter.WriteString(msg.ClientHostname)
	signedDataWriter.WriteString(msg.ClientUsername)
	signedData := signedDataWriter.ToBuffer()

	// Unwrap and verify the signature.
	rawSignature, err := unwrapSignatureData(msg.Signature)
	if err != nil {
		return s.sendAuthFailure()
	}

	verified, err := verifySignature(publicKey, signedData, rawSignature)
	if err != nil || !verified {
		return s.sendAuthFailure()
	}

	return s.handleAuthenticating(&AuthenticatingEventArgs{
		AuthenticationType: AuthClientHostBased,
		Username:           msg.Username,
		PublicKey:           publicKey,
		ClientHostname:     msg.ClientHostname,
		ClientUsername:     msg.ClientUsername,
	})
}

// handleAuthenticating invokes the session's OnAuthenticating callback
// and sends the appropriate response.
func (s *authenticationService) handleAuthenticating(args *AuthenticatingEventArgs) error {
	s.session.reportProgress(ProgressStartingSessionAuthentication)
	s.session.trace(TraceLevelInfo, TraceEventSessionAuthenticating,
		fmt.Sprintf("Authenticating: method=%d username=%s", args.AuthenticationType, args.Username))

	// Snapshot callback under lock to avoid data race with concurrent setter.
	s.session.mu.Lock()
	onAuthenticating := s.session.OnAuthenticating
	s.session.mu.Unlock()

	if onAuthenticating != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Callback panicked — treat as auth failure.
					args.AuthenticationResult = nil
				}
			}()
			onAuthenticating(args)
		}()
	}

	if args.AuthenticationResult != nil {
		if args.AuthenticationType == AuthClientPublicKeyQuery {
			// Public key query succeeded — send PublicKeyOk.
			s.currentMethodName = ""
			okMsg := &messages.PublicKeyOkMessage{}
			if args.PublicKey != nil {
				pubBytes, _ := args.PublicKey.GetPublicKeyBytes()
				okMsg.KeyAlgorithmName = args.PublicKey.KeyAlgorithmName()
				okMsg.PublicKey = pubBytes
			}
			return s.session.SendMessage(okMsg)
		}

		// Authentication succeeded.
		s.currentMethodName = ""

		// Mark session as authenticated and store the principal.
		s.session.mu.Lock()
		s.session.isAuthenticated = true
		s.session.Principal = args.AuthenticationResult
		s.session.mu.Unlock()

		// Activate the service named in the auth request (usually "ssh-connection")
		// on the server side, matching C#/TS behavior. This must happen before
		// sending SSH_MSG_USERAUTH_SUCCESS.
		if !s.session.isClient && s.currentServiceName != "" {
			s.session.ActivateService(s.currentServiceName)
		}

		s.session.reportProgress(ProgressCompletedSessionAuthentication)
		s.session.trace(TraceLevelInfo, TraceEventSessionAuthenticated,
			fmt.Sprintf("Authentication succeeded: username=%s", args.Username))

		if err := s.session.SendMessage(&messages.AuthenticationSuccessMessage{}); err != nil {
			return err
		}

		// Fire OnClientAuthenticated on the server session.
		// Snapshot callback under lock to avoid data race with concurrent setter.
		if serverSession, ok := s.session.serverSession(); ok {
			s.session.mu.Lock()
			onClientAuthenticated := serverSession.OnClientAuthenticated
			s.session.mu.Unlock()

			if onClientAuthenticated != nil {
				onClientAuthenticated()
			}
		}

		return nil
	}

	// Authentication not yet complete.
	// Check for interactive prompts to send (server side).
	if args.AuthenticationType == AuthClientInteractive && !s.session.isClient && args.InfoRequest != nil {
		// Server handler set InfoRequest with prompts — send to client.
		return s.session.SendMessage(args.InfoRequest)
	}

	// Check for interactive response to send (client side).
	if args.AuthenticationType == AuthClientInteractive && s.session.isClient && args.InfoResponse != nil {
		// Client handler set InfoResponse — send to server.
		return s.session.SendMessage(args.InfoResponse)
	}

	// Authentication failed.
	s.currentMethodName = ""
	return s.sendAuthFailure()
}

// handleAuthInfoResponse processes an AuthenticationInfoResponse from the client (server side).
func (s *authenticationService) handleAuthInfoResponse(payload []byte) error {
	msg := &messages.AuthenticationInfoResponseMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read auth info response: %w", err)
	}

	// Raise OnAuthenticating with the response so the server can process it.
	return s.handleAuthenticating(&AuthenticatingEventArgs{
		AuthenticationType: AuthClientInteractive,
		Username:           s.currentUsername,
		InfoResponse:       msg,
	})
}

// handlePublicKeyOk processes a PublicKeyOk message from the server (client side).
func (s *authenticationService) handlePublicKeyOk(payload []byte) error {
	// PublicKeyOk means the server accepts this key — signal success for the query.
	select {
	case s.authComplete <- &authResult{success: true}:
	default:
	}
	return nil
}

// handleAuthInfoRequest processes an AuthenticationInfoRequest from the server (client side).
func (s *authenticationService) handleAuthInfoRequest(payload []byte) error {
	msg := &messages.AuthenticationInfoRequestMessage{}
	if err := messages.ReadMessage(msg, payload); err != nil {
		return fmt.Errorf("failed to read auth info request: %w", err)
	}

	// Raise OnAuthenticating on the client side so the handler can provide responses.
	// Snapshot callback under lock to avoid data race with concurrent setter.
	s.session.mu.Lock()
	onAuthenticating := s.session.OnAuthenticating
	s.session.mu.Unlock()

	if onAuthenticating != nil {
		args := &AuthenticatingEventArgs{
			AuthenticationType: AuthClientInteractive,
			InfoRequest:        msg,
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					args.InfoResponse = nil
				}
			}()
			onAuthenticating(args)
		}()

		if args.InfoResponse != nil {
			// Client handler provided responses — send them to the server.
			return s.session.SendMessage(args.InfoResponse)
		}
	}

	return nil
}

// sendAuthFailure sends an authentication failure message and checks max attempts.
func (s *authenticationService) sendAuthFailure() error {
	s.failureCount++
	s.session.trace(TraceLevelVerbose, TraceEventClientAuthenticationFailed,
		fmt.Sprintf("Authentication failed: attempt=%d", s.failureCount))

	failMsg := &messages.AuthenticationFailureMessage{
		MethodNames: s.session.Config.AuthenticationMethods,
	}
	if err := s.session.SendMessage(failMsg); err != nil {
		return err
	}

	// Check max attempts.
	maxAttempts := s.session.Config.MaxClientAuthenticationAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if s.failureCount >= maxAttempts {
		s.session.close(messages.DisconnectNoMoreAuthMethodsAvailable,
			"Authentication failed.", true, true)
	}

	return nil
}

// handleAuthSuccess processes an authentication success message (client side).
func (s *authenticationService) handleAuthSuccess() error {
	// Mark session as authenticated.
	s.session.mu.Lock()
	s.session.isAuthenticated = true
	s.session.mu.Unlock()

	s.session.reportProgress(ProgressCompletedSessionAuthentication)
	s.session.trace(TraceLevelInfo, TraceEventSessionAuthenticated,
		"Client authentication succeeded.")

	select {
	case s.authComplete <- &authResult{success: true}:
	default:
	}
	return nil
}

// handleAuthFailure processes an authentication failure message (client side).
func (s *authenticationService) handleAuthFailure(payload []byte) error {
	// Parse the failure message to extract server-suggested methods.
	msg := &messages.AuthenticationFailureMessage{}
	var suggested []string
	if err := messages.ReadMessage(msg, payload); err == nil {
		suggested = msg.MethodNames
	}

	select {
	case s.authComplete <- &authResult{success: false, suggestedMethods: suggested}:
	default:
	}
	return nil
}

// connectionService is a minimal service activated when the "ssh-connection"
// service request is received (either explicitly or automatically after auth success).
// In Go, channel management is handled directly by the session, so this service
// is a no-op placeholder that matches the C#/TS service activation behavior.
type connectionService struct{}

func newConnectionService(_ *Session, _ interface{}) Service { return &connectionService{} }
func (s *connectionService) OnSessionRequest(*RequestEventArgs)              {}
func (s *connectionService) OnChannelOpening(*ChannelOpeningEventArgs)       {}
func (s *connectionService) OnChannelRequest(*Channel, *RequestEventArgs)    {}
func (s *connectionService) Close() error                                    { return nil }

// rsaSigningAlgorithm returns the SSH signing algorithm name for an RSA key pair
// based on its configured hash algorithm.
func rsaSigningAlgorithm(key *RsaKeyPair) string {
	if key.hashAlgo == crypto.SHA512 {
		return AlgoPKRsaSha512
	}
	return AlgoPKRsaSha256
}

// importPublicKey creates a KeyPair from SSH wire format public key bytes.
func importPublicKey(algorithmName string, publicKeyBytes []byte) (KeyPair, error) {
	switch algorithmName {
	case AlgoPKRsaSha256, AlgoPKRsaSha512, AlgoKeyRsa:
		kp := &RsaKeyPair{}
		if err := kp.SetPublicKeyBytes(publicKeyBytes); err != nil {
			return nil, err
		}
		// Set the hash algorithm based on the algorithm name.
		if algorithmName == AlgoPKRsaSha512 {
			kp.hashAlgo = crypto.SHA512
		} else {
			kp.hashAlgo = crypto.SHA256
		}
		return kp, nil
	case AlgoPKEcdsaSha2P256, AlgoPKEcdsaSha2P384, AlgoPKEcdsaSha2P521:
		kp := &EcdsaKeyPair{}
		if err := kp.SetPublicKeyBytes(publicKeyBytes); err != nil {
			return nil, err
		}
		return kp, nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algorithmName)
	}
}

// unwrapSignatureData extracts the raw signature bytes from the SSH signature wrapper.
// Format: [string algorithmName][binary rawSignature]
func unwrapSignatureData(signatureData []byte) ([]byte, error) {
	reader := sshio.NewSSHDataReader(signatureData)
	_, err := reader.ReadString() // algorithm name
	if err != nil {
		return nil, fmt.Errorf("failed to read signature algorithm: %w", err)
	}
	rawSig, err := reader.ReadBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to read raw signature: %w", err)
	}
	return rawSig, nil
}

// wrapSignatureData wraps raw signature bytes in the SSH signature format.
// Format: [string algorithmName][binary rawSignature]
func wrapSignatureData(algorithmName string, rawSignature []byte) []byte {
	writer := sshio.NewSSHDataWriter(make([]byte, 0, len(rawSignature)+len(algorithmName)+8))
	writer.WriteString(algorithmName)
	writer.WriteBinary(rawSignature)
	return writer.ToBuffer()
}

// verifySignature verifies a signature using the appropriate key pair type.
func verifySignature(publicKey KeyPair, signedData, rawSignature []byte) (bool, error) {
	switch kp := publicKey.(type) {
	case *RsaKeyPair:
		return kp.Verify(signedData, rawSignature)
	case *EcdsaKeyPair:
		return kp.Verify(signedData, rawSignature)
	default:
		return false, fmt.Errorf("unsupported key pair type for verification")
	}
}

// signData signs data using the appropriate key pair type.
func signData(key KeyPair, data []byte) ([]byte, error) {
	switch kp := key.(type) {
	case *RsaKeyPair:
		return kp.Sign(data)
	case *EcdsaKeyPair:
		return kp.Sign(data)
	default:
		return nil, fmt.Errorf("unsupported key pair type for signing")
	}
}
