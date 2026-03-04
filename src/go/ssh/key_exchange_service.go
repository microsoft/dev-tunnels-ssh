// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"sync"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/algorithms"
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

const (
	// Extension info signal pseudo-algorithms per RFC 8308.
	serverExtensionInfoSignal = "ext-info-s"
	clientExtensionInfoSignal = "ext-info-c"
)

// exchangeContext holds all state during an active key exchange.
type exchangeContext struct {
	kexAlgorithmName           string
	publicKeyAlgorithmName     string
	clientEncryptionName       string
	serverEncryptionName       string
	clientHmacName             string
	serverHmacName             string
	clientCompressionName      string
	serverCompressionName      string
	clientKexInitPayload       []byte
	serverKexInitPayload       []byte
	exchangeValue              []byte // client's ephemeral public value
	exchange                   algorithms.KeyExchange
	isExtensionInfoRequested   bool
	discardGuessedInit         bool
	newAlgorithms              *sessionAlgorithms
	isInitialExchange          bool
}

// sessionAlgorithms holds the negotiated algorithm instances for a session.
type sessionAlgorithms struct {
	PublicKeyAlgorithmName string
	Cipher                 algorithms.Cipher
	Decipher               algorithms.Cipher
	Signer                 algorithms.MessageSigner
	Verifier               algorithms.MessageVerifier
	IsExtensionInfoRequested bool

	// ReconnectSigner and ReconnectVerifier are dedicated HMAC instances for
	// reconnect token creation/verification. These are always proper HMAC-based
	// signers (never GCM cipher aliases), which makes them safe for concurrent use
	// with the dispatch loop's packet operations. When GCM is the encryption cipher,
	// Signer/Verifier are aliases to the GCM cipher (which has mutable state), so
	// we cannot use them concurrently from the reconnect code path.
	ReconnectSigner   algorithms.MessageSigner
	ReconnectVerifier algorithms.MessageVerifier
}

// keyExchangeService manages the key exchange protocol for a session.
type keyExchangeService struct {
	mu          sync.Mutex
	session     *Session
	ctx         *exchangeContext
	exchanging  bool

	// newKeysSent is closed after our NewKeys message has been sent on the wire.
	// This ensures we don't activate send encryption before NewKeys is sent.
	newKeysSent chan struct{}

	// hostKey stores the server's host key after verification (client side only).
	hostKeyValue KeyPair

	// Algorithm lookup maps built from known algorithms.
	kexAlgorithms        map[string]*algorithms.KeyExchangeAlgorithm
	encryptionAlgorithms map[string]*algorithms.EncryptionAlgorithm
	hmacAlgorithms       map[string]*algorithms.HmacAlgorithm
}

// getHostKey returns the server's host key, or nil if no key exchange occurred.
func (svc *keyExchangeService) getHostKey() KeyPair {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return svc.hostKeyValue
}

// newKeyExchangeService creates a new key exchange service for the given session.
func newKeyExchangeService(session *Session) *keyExchangeService {
	svc := &keyExchangeService{
		session: session,
	}
	svc.initAlgorithmMaps()
	return svc
}

// initAlgorithmMaps populates the algorithm lookup maps.
func (svc *keyExchangeService) initAlgorithmMaps() {
	svc.kexAlgorithms = map[string]*algorithms.KeyExchangeAlgorithm{
		AlgoKexEcdhNistp521: algorithms.NewECDHP521SHA512(),
		AlgoKexEcdhNistp384: algorithms.NewECDHP384SHA384(),
		AlgoKexEcdhNistp256: algorithms.NewECDHP256SHA256(),
		AlgoKexDHGroup16:    algorithms.NewDHGroup16SHA512(),
		AlgoKexDHGroup14:    algorithms.NewDHGroup14SHA256(),
	}

	svc.encryptionAlgorithms = map[string]*algorithms.EncryptionAlgorithm{
		AlgoEncAes256Gcm: algorithms.NewAes256Gcm(),
		AlgoEncAes256Cbc: algorithms.NewAes256Cbc(),
		AlgoEncAes256Ctr: algorithms.NewAes256Ctr(),
	}

	svc.hmacAlgorithms = map[string]*algorithms.HmacAlgorithm{
		AlgoHmacSha512Etm: algorithms.NewHmacSha512Etm(),
		AlgoHmacSha256Etm: algorithms.NewHmacSha256Etm(),
		AlgoHmacSha512:    algorithms.NewHmacSha512(),
		AlgoHmacSha256:    algorithms.NewHmacSha256(),
	}
}

// startKeyExchange begins a new key exchange. Returns the serialized KexInit payload
// and an optional serialized guess message payload (DhInit sent before server prefs).
// Returning serialized bytes avoids races with the dispatch loop re-serializing the message.
func (svc *keyExchangeService) startKeyExchange(isInitialExchange bool) (kexInitPayload []byte, guessPayload []byte) {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	svc.ctx = &exchangeContext{
		isInitialExchange: isInitialExchange,
	}
	svc.exchanging = true

	kexInit := svc.session.buildKexInitMessage()

	// Add extension info signal to kex algorithms list.
	// Use a copy to avoid modifying the config's slice.
	if isInitialExchange {
		algosCopy := make([]string, len(kexInit.KeyExchangeAlgorithms)+1)
		copy(algosCopy, kexInit.KeyExchangeAlgorithms)
		if svc.session.isClient {
			algosCopy[len(kexInit.KeyExchangeAlgorithms)] = clientExtensionInfoSignal
		} else {
			algosCopy[len(kexInit.KeyExchangeAlgorithms)] = serverExtensionInfoSignal
		}
		kexInit.KeyExchangeAlgorithms = algosCopy
	}

	// Key exchange guess: client sends DhInit before receiving server prefs.
	if svc.session.isClient && isInitialExchange && svc.session.Config.EnableKeyExchangeGuess {
		algoList := svc.session.Config.KeyExchangeAlgorithms
		if len(algoList) > 0 && algoList[0] != AlgoKexNone {
			kexAlg := svc.kexAlgorithms[algoList[0]]
			if kexAlg != nil {
				exchange, err := kexAlg.CreateKeyExchange()
				if err == nil {
					exchangeValue, err := exchange.StartKeyExchange()
					if err == nil {
						svc.ctx.exchange = exchange
						svc.ctx.exchangeValue = exchangeValue
						kexInit.FirstKexPacketFollows = true

						e := sshio.SSHBytesToBigInt(exchangeValue)
						guessMsg := &messages.KeyExchangeDhInitMessage{E: e}
						guessPayload = guessMsg.ToBuffer()
					}
				}
			}
		}
	}

	// Serialize the KexInit ONCE and store for exchange hash computation.
	kexInitPayload = kexInit.ToBuffer()
	if svc.session.isClient {
		svc.ctx.clientKexInitPayload = kexInitPayload
	} else {
		svc.ctx.serverKexInitPayload = kexInitPayload
	}

	return kexInitPayload, guessPayload
}

// finishKeyExchange completes the exchange and returns the negotiated algorithms.
// Called from activateNewKeys in the dispatch loop. Both finishKeyExchange and
// considerReExchange are only called from the dispatch loop (single-threaded),
// so no mutex is needed for the exchanging flag. The caller (activateNewKeys)
// is responsible for holding s.mu when storing the returned algorithms.
func (svc *keyExchangeService) finishKeyExchange() *sessionAlgorithms {
	svc.exchanging = false
	algs := svc.ctx.newAlgorithms
	return algs
}

// abortKeyExchange cancels an in-progress key exchange.
func (svc *keyExchangeService) abortKeyExchange() {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	svc.exchanging = false
	svc.ctx = nil
}

// handleKexInit processes a received KeyExchangeInitMessage.
func (svc *keyExchangeService) handleKexInit(msg *messages.KeyExchangeInitMessage, payload []byte) error {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	if svc.ctx == nil {
		// Remote side initiated key exchange before us; create context.
		svc.ctx = &exchangeContext{
			isInitialExchange: svc.session.SessionID == nil,
		}
		svc.exchanging = true

		// Build our own KexInit.
		ourKexInit := svc.session.buildKexInitMessage()
		if svc.ctx.isInitialExchange {
			// Use a copy to avoid modifying the config's shared slice.
			algosCopy := make([]string, len(ourKexInit.KeyExchangeAlgorithms)+1)
			copy(algosCopy, ourKexInit.KeyExchangeAlgorithms)
			if svc.session.isClient {
				algosCopy[len(ourKexInit.KeyExchangeAlgorithms)] = clientExtensionInfoSignal
			} else {
				algosCopy[len(ourKexInit.KeyExchangeAlgorithms)] = serverExtensionInfoSignal
			}
			ourKexInit.KeyExchangeAlgorithms = algosCopy
		}

		if svc.session.isClient {
			svc.ctx.clientKexInitPayload = ourKexInit.ToBuffer()
		} else {
			svc.ctx.serverKexInitPayload = ourKexInit.ToBuffer()
		}

		// Send our KexInit.
		if err := svc.session.protocol.sendMessage(ourKexInit.ToBuffer()); err != nil {
			return err
		}
	}

	// Store remote side's payload.
	if svc.session.isClient {
		svc.ctx.serverKexInitPayload = payload
	} else {
		svc.ctx.clientKexInitPayload = payload
	}

	// Negotiate algorithms.
	var clientKexInit, serverKexInit *messages.KeyExchangeInitMessage
	if svc.session.isClient {
		clientKexInit = svc.parseKexInit(svc.ctx.clientKexInitPayload)
		serverKexInit = msg
	} else {
		clientKexInit = msg
		serverKexInit = svc.parseKexInit(svc.ctx.serverKexInitPayload)
	}

	var err error
	svc.ctx.kexAlgorithmName, err = chooseAlgorithm("key exchange",
		clientKexInit.KeyExchangeAlgorithms, serverKexInit.KeyExchangeAlgorithms)
	if err != nil {
		return err
	}

	svc.ctx.publicKeyAlgorithmName, err = chooseAlgorithm("public key",
		clientKexInit.ServerHostKeyAlgorithms, serverKexInit.ServerHostKeyAlgorithms)
	if err != nil {
		return err
	}

	svc.ctx.clientEncryptionName, err = chooseAlgorithm("client encryption",
		clientKexInit.EncryptionAlgorithmsClientToServer, serverKexInit.EncryptionAlgorithmsClientToServer)
	if err != nil {
		return err
	}

	svc.ctx.serverEncryptionName, err = chooseAlgorithm("server encryption",
		clientKexInit.EncryptionAlgorithmsServerToClient, serverKexInit.EncryptionAlgorithmsServerToClient)
	if err != nil {
		return err
	}

	svc.ctx.clientHmacName, err = chooseAlgorithm("client HMAC",
		clientKexInit.MacAlgorithmsClientToServer, serverKexInit.MacAlgorithmsClientToServer)
	if err != nil {
		return err
	}

	svc.ctx.serverHmacName, err = chooseAlgorithm("server HMAC",
		clientKexInit.MacAlgorithmsServerToClient, serverKexInit.MacAlgorithmsServerToClient)
	if err != nil {
		return err
	}

	svc.ctx.clientCompressionName, err = chooseAlgorithm("client compression",
		clientKexInit.CompressionAlgorithmsClientToServer, serverKexInit.CompressionAlgorithmsClientToServer)
	if err != nil {
		return err
	}

	svc.ctx.serverCompressionName, err = chooseAlgorithm("server compression",
		clientKexInit.CompressionAlgorithmsServerToClient, serverKexInit.CompressionAlgorithmsServerToClient)
	if err != nil {
		return err
	}

	svc.session.trace(TraceLevelVerbose, TraceEventAlgorithmNegotiation,
		fmt.Sprintf("Negotiated algorithms: kex=%s pk=%s enc=%s/%s hmac=%s/%s",
			svc.ctx.kexAlgorithmName, svc.ctx.publicKeyAlgorithmName,
			svc.ctx.clientEncryptionName, svc.ctx.serverEncryptionName,
			svc.ctx.clientHmacName, svc.ctx.serverHmacName))

	// Detect extension info signal from remote side.
	if svc.ctx.isInitialExchange {
		if svc.session.isClient {
			svc.ctx.isExtensionInfoRequested = containsString(
				serverKexInit.KeyExchangeAlgorithms, serverExtensionInfoSignal)
		} else {
			svc.ctx.isExtensionInfoRequested = containsString(
				clientKexInit.KeyExchangeAlgorithms, clientExtensionInfoSignal)
		}
	}

	// Handle kex:none specially: no wire messages, just locally activate empty algorithms.
	// Extension info is not sent for kex:none (no security, no algorithms to advertise).
	if svc.ctx.kexAlgorithmName == AlgoKexNone {
		svc.ctx.newAlgorithms = &sessionAlgorithms{}
		// Locally activate empty algorithms (no NewKeys sent on wire).
		return svc.session.activateNewKeys()
	}

	// Check if client sent a guess and whether it matches the negotiated algorithm.
	if !svc.session.isClient && msg.FirstKexPacketFollows {
		// Server: check if client's preferred algorithm matches negotiated.
		if len(clientKexInit.KeyExchangeAlgorithms) > 0 &&
			clientKexInit.KeyExchangeAlgorithms[0] != svc.ctx.kexAlgorithmName {
			svc.ctx.discardGuessedInit = true
		}
	}

	// Client: if we sent a guess, check if it was correct.
	if svc.session.isClient && svc.ctx.exchange != nil {
		algoList := svc.session.Config.KeyExchangeAlgorithms
		if len(algoList) > 0 && algoList[0] == svc.ctx.kexAlgorithmName {
			// Guess was correct, no need to resend.
		} else {
			// Guess was wrong, discard and create new exchange.
			svc.ctx.exchange = nil
			svc.ctx.exchangeValue = nil
		}
	}

	// Client: if no exchange started yet (no guess or wrong guess), start one now.
	if svc.session.isClient && svc.ctx.exchange == nil {
		return svc.sendClientDhInit()
	}

	return nil
}

// sendClientDhInit creates and sends the client's DH/ECDH init message.
func (svc *keyExchangeService) sendClientDhInit() error {
	kexAlg := svc.kexAlgorithms[svc.ctx.kexAlgorithmName]
	if kexAlg == nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("unsupported key exchange algorithm: %s", svc.ctx.kexAlgorithmName),
		}
	}

	exchange, err := kexAlg.CreateKeyExchange()
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to create key exchange: %v", err),
			Err:    err,
		}
	}

	exchangeValue, err := exchange.StartKeyExchange()
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to start key exchange: %v", err),
			Err:    err,
		}
	}

	svc.ctx.exchange = exchange
	svc.ctx.exchangeValue = exchangeValue

	e := sshio.SSHBytesToBigInt(exchangeValue)
	dhInit := &messages.KeyExchangeDhInitMessage{E: e}
	return svc.session.protocol.sendMessage(dhInit.ToBuffer())
}

// handleDhInit processes the client's DH/ECDH init (server side).
func (svc *keyExchangeService) handleDhInit(msg *messages.KeyExchangeDhInitMessage) error {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	if svc.ctx == nil {
		return &ConnectionError{
			Reason: messages.DisconnectProtocolError,
			Msg:    "received DH init without key exchange in progress",
		}
	}

	// Discard incorrect guess.
	if svc.ctx.discardGuessedInit {
		svc.ctx.discardGuessedInit = false
		return nil
	}

	// Get the client's exchange value.
	clientExchangeValue := sshio.BigIntToSSHBytes(msg.E)

	// Create server's key exchange.
	kexAlg := svc.kexAlgorithms[svc.ctx.kexAlgorithmName]
	if kexAlg == nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("unsupported key exchange algorithm: %s", svc.ctx.kexAlgorithmName),
		}
	}

	exchange, err := kexAlg.CreateKeyExchange()
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to create key exchange: %v", err),
			Err:    err,
		}
	}

	serverExchangeValue, err := exchange.StartKeyExchange()
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to start key exchange: %v", err),
			Err:    err,
		}
	}

	sharedSecret, err := exchange.DecryptKeyExchange(clientExchangeValue)
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to compute shared secret: %v", err),
			Err:    err,
		}
	}

	// Get server's host key.
	serverSession, ok := svc.session.serverSession()
	if !ok {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    "server session required for key exchange",
		}
	}

	hostKey, err := svc.getServerHostKey(serverSession)
	if err != nil {
		return err
	}

	hostKeyBytes, err := hostKey.GetPublicKeyBytes()
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to get host key bytes: %v", err),
			Err:    err,
		}
	}

	// Compute exchange hash.
	exchangeHash, err := svc.computeExchangeHash(
		exchange, hostKeyBytes,
		clientExchangeValue, serverExchangeValue, sharedSecret)
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to compute exchange hash: %v", err),
			Err:    err,
		}
	}

	// Set session ID from first exchange.
	if svc.session.SessionID == nil {
		svc.session.SessionID = make([]byte, len(exchangeHash))
		copy(svc.session.SessionID, exchangeHash)
	}

	// Derive keys and create algorithm instances.
	algs, err := svc.computeKeys(exchange, sharedSecret, exchangeHash)
	// Wipe shared secret after key derivation — it is no longer needed.
	zeroBytes(sharedSecret)
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to derive keys: %v", err),
			Err:    err,
		}
	}
	algs.PublicKeyAlgorithmName = svc.ctx.publicKeyAlgorithmName
	algs.IsExtensionInfoRequested = svc.ctx.isExtensionInfoRequested
	svc.ctx.newAlgorithms = algs

	// Sign the exchange hash with the server's host key.
	signature, err := svc.signExchangeHash(hostKey, exchangeHash)
	if err != nil {
		return err
	}

	// Prepare DH reply message.
	f := sshio.SSHBytesToBigInt(serverExchangeValue)
	replyMsg := &messages.KeyExchangeDhReplyMessage{
		HostKey:   hostKeyBytes,
		F:         f,
		Signature: signature,
	}
	replyPayload := replyMsg.ToBuffer()
	newKeysPayload := (&messages.NewKeysMessage{}).ToBuffer()

	// Send DhReply + NewKeys in a goroutine to avoid deadlock with io.Pipe.
	// Both sides' dispatch loops try to send NewKeys simultaneously;
	// using a goroutine lets the dispatch loop continue reading.
	svc.newKeysSent = make(chan struct{})
	session := svc.session
	go func() {
		defer close(svc.newKeysSent)
		if err := session.protocol.sendMessage(replyPayload); err != nil {
			session.close(messages.DisconnectProtocolError, err.Error(), false, false)
			return
		}
		if err := session.protocol.sendMessage(newKeysPayload); err != nil {
			session.close(messages.DisconnectProtocolError, err.Error(), false, false)
			return
		}
	}()

	return nil
}

// handleDhReply processes the server's DH/ECDH reply (client side).
func (svc *keyExchangeService) handleDhReply(msg *messages.KeyExchangeDhReplyMessage) error {
	svc.mu.Lock()
	defer svc.mu.Unlock()

	if svc.ctx == nil || svc.ctx.exchange == nil {
		return &ConnectionError{
			Reason: messages.DisconnectProtocolError,
			Msg:    "received DH reply without key exchange in progress",
		}
	}

	serverExchangeValue := sshio.BigIntToSSHBytes(msg.F)

	// Compute shared secret.
	sharedSecret, err := svc.ctx.exchange.DecryptKeyExchange(serverExchangeValue)
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to compute shared secret: %v", err),
			Err:    err,
		}
	}

	// Compute exchange hash.
	exchangeHash, err := svc.computeExchangeHash(
		svc.ctx.exchange, msg.HostKey,
		svc.ctx.exchangeValue, serverExchangeValue, sharedSecret)
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to compute exchange hash: %v", err),
			Err:    err,
		}
	}

	// Verify server's host key signature.
	if err := svc.verifyHostKeySignature(msg.HostKey, exchangeHash, msg.Signature); err != nil {
		return err
	}

	// Set session ID from first exchange.
	if svc.session.SessionID == nil {
		svc.session.SessionID = make([]byte, len(exchangeHash))
		copy(svc.session.SessionID, exchangeHash)
	}

	// Derive keys and create algorithm instances.
	algs, err := svc.computeKeys(svc.ctx.exchange, sharedSecret, exchangeHash)
	// Wipe shared secret after key derivation — it is no longer needed.
	zeroBytes(sharedSecret)
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to derive keys: %v", err),
			Err:    err,
		}
	}
	algs.PublicKeyAlgorithmName = svc.ctx.publicKeyAlgorithmName
	algs.IsExtensionInfoRequested = svc.ctx.isExtensionInfoRequested
	svc.ctx.newAlgorithms = algs

	// Send NewKeys in a goroutine to avoid deadlock with io.Pipe.
	// Both sides' dispatch loops try to send NewKeys simultaneously;
	// using a goroutine lets the dispatch loop continue reading.
	newKeysPayload := (&messages.NewKeysMessage{}).ToBuffer()
	svc.newKeysSent = make(chan struct{})
	session := svc.session
	go func() {
		defer close(svc.newKeysSent)
		if err := session.protocol.sendMessage(newKeysPayload); err != nil {
			session.close(messages.DisconnectProtocolError, err.Error(), false, false)
			return
		}
	}()

	return nil
}

// computeExchangeHash computes the exchange hash per RFC 4253 §8.
func (svc *keyExchangeService) computeExchangeHash(
	exchange algorithms.KeyExchange,
	hostKeyBytes []byte,
	clientExchangeValue, serverExchangeValue, sharedSecret []byte,
) ([]byte, error) {
	var clientVersion, serverVersion string
	if svc.session.isClient {
		clientVersion = GetLocalVersion().String()
		serverVersion = svc.session.RemoteVersion.String()
	} else {
		clientVersion = svc.session.RemoteVersion.String()
		serverVersion = GetLocalVersion().String()
	}

	writer := sshio.NewSSHDataWriter(make([]byte, 0))

	// Write version strings (as SSH strings with length prefix).
	writer.WriteString(clientVersion)
	writer.WriteString(serverVersion)

	// Write KexInit payloads (as binary with length prefix).
	writer.WriteBinary(svc.ctx.clientKexInitPayload)
	writer.WriteBinary(svc.ctx.serverKexInitPayload)

	// Write host key (as binary with length prefix).
	writer.WriteBinary(hostKeyBytes)

	// Write exchange values as big integers (mpint format).
	e := sshio.SSHBytesToBigInt(clientExchangeValue)
	f := sshio.SSHBytesToBigInt(serverExchangeValue)
	k := sshio.SSHBytesToBigInt(sharedSecret)
	writer.WriteBigInt(e)
	writer.WriteBigInt(f)
	writer.WriteBigInt(k)

	// Hash with the key exchange algorithm's hash function.
	return exchange.Sign(writer.ToBuffer())
}

// computeKeys derives all encryption/HMAC keys from the shared secret and exchange hash.
// RFC 4253 §7.2.
func (svc *keyExchangeService) computeKeys(
	exchange algorithms.KeyExchange,
	sharedSecret, exchangeHash []byte,
) (*sessionAlgorithms, error) {
	// Get algorithm descriptors for negotiated algorithms.
	clientEncAlg := svc.encryptionAlgorithms[svc.ctx.clientEncryptionName]
	serverEncAlg := svc.encryptionAlgorithms[svc.ctx.serverEncryptionName]
	clientHmacAlg := svc.hmacAlgorithms[svc.ctx.clientHmacName]
	serverHmacAlg := svc.hmacAlgorithms[svc.ctx.serverHmacName]

	// Derive IV length from encryption algorithm.
	clientIVLen := 0
	clientKeyLen := 0
	if clientEncAlg != nil {
		clientIVLen = clientEncAlg.IVLength()
		clientKeyLen = clientEncAlg.KeyLength
	}
	serverIVLen := 0
	serverKeyLen := 0
	if serverEncAlg != nil {
		serverIVLen = serverEncAlg.IVLength()
		serverKeyLen = serverEncAlg.KeyLength
	}
	clientHmacKeyLen := 0
	if clientHmacAlg != nil {
		clientHmacKeyLen = clientHmacAlg.KeyLength
	}
	serverHmacKeyLen := 0
	if serverHmacAlg != nil {
		serverHmacKeyLen = serverHmacAlg.KeyLength
	}

	// Compute keys A-F per RFC 4253 §7.2.
	clientCipherIV, err := svc.computeKey(exchange, sharedSecret, exchangeHash, 'A', clientIVLen)
	if err != nil {
		return nil, err
	}
	serverCipherIV, err := svc.computeKey(exchange, sharedSecret, exchangeHash, 'B', serverIVLen)
	if err != nil {
		return nil, err
	}
	clientCipherKey, err := svc.computeKey(exchange, sharedSecret, exchangeHash, 'C', clientKeyLen)
	if err != nil {
		return nil, err
	}
	serverCipherKey, err := svc.computeKey(exchange, sharedSecret, exchangeHash, 'D', serverKeyLen)
	if err != nil {
		return nil, err
	}
	clientHmacKey, err := svc.computeKey(exchange, sharedSecret, exchangeHash, 'E', clientHmacKeyLen)
	if err != nil {
		return nil, err
	}
	serverHmacKey, err := svc.computeKey(exchange, sharedSecret, exchangeHash, 'F', serverHmacKeyLen)
	if err != nil {
		return nil, err
	}

	algs := &sessionAlgorithms{}

	// Wipe all derived key material after use, regardless of success or failure path.
	defer func() {
		zeroBytes(clientCipherIV)
		zeroBytes(serverCipherIV)
		zeroBytes(clientCipherKey)
		zeroBytes(serverCipherKey)
		zeroBytes(clientHmacKey)
		zeroBytes(serverHmacKey)
	}()

	// Create cipher and decipher based on perspective (client vs server).
	if svc.session.isClient {
		// Client sends with client keys, receives with server keys.
		if clientEncAlg != nil {
			algs.Cipher, err = clientEncAlg.CreateCipher(true, clientCipherKey, clientCipherIV)
			if err != nil {
				return nil, err
			}
		}
		if serverEncAlg != nil {
			algs.Decipher, err = serverEncAlg.CreateCipher(false, serverCipherKey, serverCipherIV)
			if err != nil {
				return nil, err
			}
		}
		// HMAC: for GCM, the cipher itself is the signer/verifier.
		if gcmSigner, ok := algs.Cipher.(*algorithms.AesGcmCipher); ok {
			algs.Signer = gcmSigner
		} else if clientHmacAlg != nil {
			algs.Signer = clientHmacAlg.CreateSigner(clientHmacKey)
		}
		if gcmVerifier, ok := algs.Decipher.(*algorithms.AesGcmCipher); ok {
			algs.Verifier = gcmVerifier
		} else if serverHmacAlg != nil {
			algs.Verifier = serverHmacAlg.CreateVerifier(serverHmacKey)
		}
		// Dedicated reconnect token HMAC (always real HMAC, never GCM aliases).
		if clientHmacAlg != nil {
			algs.ReconnectSigner = clientHmacAlg.CreateSigner(clientHmacKey)
		}
		if serverHmacAlg != nil {
			algs.ReconnectVerifier = serverHmacAlg.CreateVerifier(serverHmacKey)
		}
	} else {
		// Server sends with server keys, receives with client keys.
		if serverEncAlg != nil {
			algs.Cipher, err = serverEncAlg.CreateCipher(true, serverCipherKey, serverCipherIV)
			if err != nil {
				return nil, err
			}
		}
		if clientEncAlg != nil {
			algs.Decipher, err = clientEncAlg.CreateCipher(false, clientCipherKey, clientCipherIV)
			if err != nil {
				return nil, err
			}
		}
		if gcmSigner, ok := algs.Cipher.(*algorithms.AesGcmCipher); ok {
			algs.Signer = gcmSigner
		} else if serverHmacAlg != nil {
			algs.Signer = serverHmacAlg.CreateSigner(serverHmacKey)
		}
		if gcmVerifier, ok := algs.Decipher.(*algorithms.AesGcmCipher); ok {
			algs.Verifier = gcmVerifier
		} else if clientHmacAlg != nil {
			algs.Verifier = clientHmacAlg.CreateVerifier(clientHmacKey)
		}
		// Dedicated reconnect token HMAC (always real HMAC, never GCM aliases).
		if serverHmacAlg != nil {
			algs.ReconnectSigner = serverHmacAlg.CreateSigner(serverHmacKey)
		}
		if clientHmacAlg != nil {
			algs.ReconnectVerifier = clientHmacAlg.CreateVerifier(clientHmacKey)
		}
	}

	return algs, nil
}

// computeKey derives one key using the SSH KDF (RFC 4253 §7.2).
func (svc *keyExchangeService) computeKey(
	exchange algorithms.KeyExchange,
	sharedSecret, exchangeHash []byte,
	letter byte,
	keyLength int,
) ([]byte, error) {
	if keyLength == 0 {
		return nil, nil
	}

	keyBuffer := make([]byte, 0, keyLength)
	var currentHash []byte

	// Build the base data: shared_secret (mpint) || exchange_hash
	k := sshio.SSHBytesToBigInt(sharedSecret)
	baseWriter := sshio.NewSSHDataWriter(make([]byte, 0))
	baseWriter.WriteBigInt(k)
	baseWriter.Write(exchangeHash)
	baseOffset := baseWriter.Position

	for len(keyBuffer) < keyLength {
		baseWriter.Position = baseOffset

		if currentHash == nil {
			// First iteration: append letter + session_id
			_ = baseWriter.WriteByte(letter)
			if svc.session.SessionID != nil {
				baseWriter.Write(svc.session.SessionID)
			}
		} else {
			// Subsequent iterations: append previous hash
			baseWriter.Write(currentHash)
		}

		var err error
		currentHash, err = exchange.Sign(baseWriter.ToBuffer())
		if err != nil {
			return nil, err
		}

		remaining := keyLength - len(keyBuffer)
		if remaining > len(currentHash) {
			remaining = len(currentHash)
		}
		keyBuffer = append(keyBuffer, currentHash[:remaining]...)
	}

	return keyBuffer, nil
}

// getServerHostKey gets the server's host key matching the negotiated public key algorithm.
// If a matching key lacks private material but a PrivateKeyProvider is configured,
// the provider is called to resolve the full key pair.
func (svc *keyExchangeService) getServerHostKey(server *ServerSession) (KeyPair, error) {
	if server.Credentials == nil || len(server.Credentials.PublicKeys) == 0 {
		return nil, &ConnectionError{
			Reason: messages.DisconnectHostKeyNotVerifiable,
			Msg:    "server has no host keys configured",
		}
	}

	for _, key := range server.Credentials.PublicKeys {
		if !svc.keyMatchesAlgorithm(key, svc.ctx.publicKeyAlgorithmName) {
			continue
		}
		if key.HasPrivateKey() {
			return key, nil
		}
		// Key matches but lacks private material — try the provider.
		if server.Credentials.PrivateKeyProvider != nil {
			resolved, err := server.Credentials.PrivateKeyProvider(context.Background(), key)
			if err == nil && resolved != nil && resolved.HasPrivateKey() {
				return resolved, nil
			}
		}
	}

	return nil, &ConnectionError{
		Reason: messages.DisconnectHostKeyNotVerifiable,
		Msg:    fmt.Sprintf("no server host key for algorithm: %s", svc.ctx.publicKeyAlgorithmName),
	}
}

// keyMatchesAlgorithm checks if a key pair's algorithm matches the negotiated algorithm name.
func (svc *keyExchangeService) keyMatchesAlgorithm(key KeyPair, algorithmName string) bool {
	keyAlgo := key.KeyAlgorithmName()
	if keyAlgo == algorithmName {
		return true
	}
	// RSA keys use "ssh-rsa" as key algorithm but negotiate as rsa-sha2-256 or rsa-sha2-512.
	if keyAlgo == AlgoKeyRsa && (algorithmName == AlgoPKRsaSha256 || algorithmName == AlgoPKRsaSha512) {
		return true
	}
	return false
}

// signExchangeHash signs the exchange hash with the host key.
func (svc *keyExchangeService) signExchangeHash(hostKey KeyPair, exchangeHash []byte) ([]byte, error) {
	type signer interface {
		Sign([]byte) ([]byte, error)
	}

	s, ok := hostKey.(signer)
	if !ok {
		return nil, &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    "host key does not support signing",
		}
	}

	rawSig, err := s.Sign(exchangeHash)
	if err != nil {
		return nil, &ConnectionError{
			Reason: messages.DisconnectKeyExchangeFailed,
			Msg:    fmt.Sprintf("failed to sign exchange hash: %v", err),
			Err:    err,
		}
	}

	// Wrap in SSH signature format: [string algorithm-name][binary signature]
	sigWriter := sshio.NewSSHDataWriter(make([]byte, 0))
	sigWriter.WriteString(svc.ctx.publicKeyAlgorithmName)
	sigWriter.WriteBinary(rawSig)
	return sigWriter.ToBuffer(), nil
}

// verifyHostKeySignature verifies the server's host key and its signature of the exchange hash.
func (svc *keyExchangeService) verifyHostKeySignature(hostKeyBytes, exchangeHash, signature []byte) error {
	// Create a key pair from the host key bytes.
	hostKey, err := svc.createKeyPairFromPublicKeyBytes(hostKeyBytes)
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectHostKeyNotVerifiable,
			Msg:    fmt.Sprintf("failed to parse host key: %v", err),
			Err:    err,
		}
	}

	// Parse the signature: [string algorithm-name][binary raw-signature]
	sigReader := sshio.NewSSHDataReader(signature)
	_, err = sigReader.ReadString() // algorithm name
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectHostKeyNotVerifiable,
			Msg:    "failed to parse signature format",
			Err:    err,
		}
	}
	rawSig, err := sigReader.ReadBinary()
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectHostKeyNotVerifiable,
			Msg:    "failed to parse signature data",
			Err:    err,
		}
	}

	type verifier interface {
		Verify([]byte, []byte) (bool, error)
	}

	v, ok := hostKey.(verifier)
	if !ok {
		return &ConnectionError{
			Reason: messages.DisconnectHostKeyNotVerifiable,
			Msg:    "host key does not support verification",
		}
	}

	valid, err := v.Verify(exchangeHash, rawSig)
	if err != nil {
		return &ConnectionError{
			Reason: messages.DisconnectHostKeyNotVerifiable,
			Msg:    fmt.Sprintf("signature verification error: %v", err),
			Err:    err,
		}
	}
	if !valid {
		return &ConnectionError{
			Reason: messages.DisconnectHostKeyNotVerifiable,
			Msg:    "host key signature verification failed",
		}
	}

	// Store the host key for later use in server authentication.
	svc.hostKeyValue = hostKey

	return nil
}

// createKeyPairFromPublicKeyBytes creates a KeyPair from SSH public key wire format bytes.
func (svc *keyExchangeService) createKeyPairFromPublicKeyBytes(data []byte) (KeyPair, error) {
	// Peek at the algorithm name.
	reader := sshio.NewSSHDataReader(data)
	algorithmName, err := reader.ReadString()
	if err != nil {
		return nil, fmt.Errorf("failed to read key algorithm: %w", err)
	}

	switch algorithmName {
	case AlgoKeyRsa, AlgoPKRsaSha256, AlgoPKRsaSha512:
		hashAlgo, hashErr := rsaHashAlgorithm(svc.ctx.publicKeyAlgorithmName)
		if hashErr != nil {
			hashAlgo = 5 // crypto.SHA256 fallback
		}
		kp := &RsaKeyPair{hashAlgo: hashAlgo}
		if err := kp.SetPublicKeyBytes(data); err != nil {
			return nil, err
		}
		return kp, nil
	case AlgoPKEcdsaSha2P256, AlgoPKEcdsaSha2P384, AlgoPKEcdsaSha2P521:
		kp := &EcdsaKeyPair{}
		if err := kp.SetPublicKeyBytes(data); err != nil {
			return nil, err
		}
		return kp, nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algorithmName)
	}
}

// parseKexInit deserializes a KexInit payload back into a message.
func (svc *keyExchangeService) parseKexInit(payload []byte) *messages.KeyExchangeInitMessage {
	msg := &messages.KeyExchangeInitMessage{}
	_ = messages.ReadMessage(msg, payload)
	return msg
}

// chooseAlgorithm performs SSH algorithm negotiation per RFC 4253 §7.1.
// Iterates through client algorithms; for each, checks if it's in the server list.
// Returns the first match. Ignores extension info signal pseudo-algorithms.
func chooseAlgorithm(label string, clientAlgorithms, serverAlgorithms []string) (string, error) {
	for _, clientAlgo := range clientAlgorithms {
		if clientAlgo == serverExtensionInfoSignal || clientAlgo == clientExtensionInfoSignal {
			continue
		}
		for _, serverAlgo := range serverAlgorithms {
			if serverAlgo == serverExtensionInfoSignal || serverAlgo == clientExtensionInfoSignal {
				continue
			}
			if clientAlgo == serverAlgo {
				return clientAlgo, nil
			}
		}
	}

	return "", &ConnectionError{
		Reason: messages.DisconnectKeyExchangeFailed,
		Msg:    fmt.Sprintf("failed %s negotiation: no common algorithm", label),
	}
}

// containsString checks if a string slice contains a specific string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// ConsiderReExchange checks if key rotation is needed and starts re-exchange if so.
func (svc *keyExchangeService) considerReExchange(bytesSent, bytesReceived uint64) error {
	svc.mu.Lock()
	if svc.exchanging {
		svc.mu.Unlock()
		return nil
	}
	svc.mu.Unlock()

	threshold := svc.session.Config.KeyRotationThreshold
	if threshold <= 0 {
		return nil
	}

	if int(bytesSent+bytesReceived) > threshold {
		kexInitPayload, guessPayload := svc.startKeyExchange(false)
		if err := svc.session.protocol.sendMessage(kexInitPayload); err != nil {
			return err
		}
		if guessPayload != nil {
			if err := svc.session.protocol.sendMessage(guessPayload); err != nil {
				return err
			}
		}
	}

	return nil
}

// sendExtensionInfo sends the extension info message after key exchange.
func (svc *keyExchangeService) sendExtensionInfo() error {
	extensions := svc.session.Config.ProtocolExtensions
	if len(extensions) == 0 {
		return nil
	}

	msg := &messages.ExtensionInfoMessage{
		Extensions: make(map[string]string),
	}

	for _, ext := range extensions {
		msg.Extensions[ext] = ""
	}

	return svc.session.protocol.sendMessage(msg.ToBuffer())
}

// zeroBytes overwrites a byte slice with zeros, used to clear sensitive key material
// (shared secrets, derived encryption keys, HMAC keys) from memory after use.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

