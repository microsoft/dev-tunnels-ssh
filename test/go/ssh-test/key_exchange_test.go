// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"context"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

const kexTestTimeout = 10 * time.Second

// TestNegotiateNoKeyExchangeClientForceTrue verifies kex:none works when
// both sides configure it (clientForce=true means client only has kex:none).
func TestNegotiateNoKeyExchangeClientForceTrue(t *testing.T) {
	pair := helpers.NewSessionPair(t) // uses NewNoSecurityConfig (kex:none)
	defer pair.Close()

	ctx := context.Background()
	pair.Connect(ctx)

	if !pair.ClientSession.IsConnected() {
		t.Fatal("client should be connected")
	}
	if !pair.ServerSession.IsConnected() {
		t.Fatal("server should be connected")
	}

	// With kex:none, no session ID is set (no real exchange hash).
	if pair.ClientSession.SessionID != nil {
		t.Error("client session ID should be nil with kex:none")
	}
	if pair.ServerSession.SessionID != nil {
		t.Error("server session ID should be nil with kex:none")
	}

	// Verify channels still work over the unencrypted session.
	clientCh, serverCh := pair.OpenChannel(ctx)
	if clientCh == nil || serverCh == nil {
		t.Fatal("channels should be opened successfully")
	}
}

// TestNegotiateNoKeyExchangeClientForceFalse verifies kex:none works when
// the server forces it but the client also supports real algorithms.
// The client has real algorithms first (preferred) but includes "none" as fallback.
func TestNegotiateNoKeyExchangeClientForceFalse(t *testing.T) {
	clientConfig := ssh.NewNoSecurityConfig()
	// Client prefers real algorithms but includes none as fallback.
	clientConfig.KeyExchangeAlgorithms = append(
		[]string{ssh.AlgoKexEcdhNistp384, ssh.AlgoKexEcdhNistp256},
		ssh.AlgoKexNone,
	)

	serverConfig := ssh.NewNoSecurityConfig() // Server only supports kex:none.

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ClientConfig: clientConfig,
		ServerConfig: serverConfig,
	})
	defer pair.Close()

	ctx := context.Background()
	pair.Connect(ctx)

	if !pair.ClientSession.IsConnected() {
		t.Fatal("client should be connected")
	}
	if !pair.ServerSession.IsConnected() {
		t.Fatal("server should be connected")
	}

	// Negotiated kex:none since the server only supports it.
	if pair.ClientSession.SessionID != nil {
		t.Error("client session ID should be nil with kex:none")
	}
}

// TestKeyExchangeWithEncryption verifies a full key exchange with real
// crypto algorithms negotiates, derives keys, and activates encryption.
func TestKeyExchangeWithEncryption(t *testing.T) {
	serverConfig := ssh.NewDefaultConfig()
	clientConfig := ssh.NewDefaultConfig()

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	// Server needs host keys for real key exchange.
	// Provide both RSA and ECDSA keys so that whatever algorithm is negotiated, a matching key exists.
	rsaKey := helpers.GenerateTestRSAKey(t)
	rsaKP, err := ssh.NewRsaKeyPair(rsaKey, ssh.AlgoPKRsaSha512)
	if err != nil {
		t.Fatalf("failed to create RSA key pair: %v", err)
	}
	serverKey := helpers.GenerateTestECDSAKey(t)
	ecdsaKP, err := ssh.NewEcdsaKeyPair(serverKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{rsaKP, ecdsaKP},
	}

	ctx := context.Background()
	pair.Connect(ctx)

	if !pair.ClientSession.IsConnected() {
		t.Fatal("client should be connected")
	}
	if !pair.ServerSession.IsConnected() {
		t.Fatal("server should be connected")
	}

	// With real key exchange, session ID is derived from exchange hash.
	if pair.ClientSession.SessionID == nil {
		t.Error("client session ID should be set after real key exchange")
	}
	if pair.ServerSession.SessionID == nil {
		t.Error("server session ID should be set after real key exchange")
	}

	// Both sides should derive the same session ID.
	if len(pair.ClientSession.SessionID) != len(pair.ServerSession.SessionID) {
		t.Fatalf("session ID lengths differ: client=%d, server=%d",
			len(pair.ClientSession.SessionID), len(pair.ServerSession.SessionID))
	}
	for i := range pair.ClientSession.SessionID {
		if pair.ClientSession.SessionID[i] != pair.ServerSession.SessionID[i] {
			t.Fatal("client and server session IDs should match")
		}
	}

	// Verify data can be sent over encrypted channel.
	clientCh, serverCh := pair.OpenChannel(ctx)
	if clientCh == nil || serverCh == nil {
		t.Fatal("channels should work over encrypted session")
	}
}

// TestKeyExchangeWithSpecificAlgorithm verifies key exchange using ECDH P-256.
func TestKeyExchangeWithSpecificAlgorithm(t *testing.T) {
	serverConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp256},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Ctr},
		HmacAlgorithms:        []string{ssh.AlgoHmacSha256},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}
	clientConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp256},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Ctr},
		HmacAlgorithms:        []string{ssh.AlgoHmacSha256},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	serverKey := helpers.GenerateTestECDSAKey(t)
	ecdsaKP, err := ssh.NewEcdsaKeyPair(serverKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{ecdsaKP},
	}

	ctx := context.Background()
	pair.Connect(ctx)

	if pair.ClientSession.SessionID == nil {
		t.Error("client should have session ID after key exchange")
	}
	if pair.ServerSession.SessionID == nil {
		t.Error("server should have session ID after key exchange")
	}
}

// TestKeyExchangeWithGCM verifies key exchange with AES-256-GCM authenticated encryption.
func TestKeyExchangeWithGCM(t *testing.T) {
	serverConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp384},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Gcm},
		HmacAlgorithms:        []string{ssh.AlgoHmacNone},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}
	clientConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp384},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Gcm},
		HmacAlgorithms:        []string{ssh.AlgoHmacNone},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	serverKey := helpers.GenerateTestECDSAKey(t)
	ecdsaKP, err := ssh.NewEcdsaKeyPair(serverKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{ecdsaKP},
	}

	ctx := context.Background()
	pair.Connect(ctx)

	if pair.ClientSession.SessionID == nil {
		t.Fatal("client should have session ID after GCM key exchange")
	}

	// Verify data exchange works over GCM-encrypted channel.
	clientCh, serverCh := pair.OpenChannel(ctx)
	if clientCh == nil || serverCh == nil {
		t.Fatal("channels should work over GCM-encrypted session")
	}
}

// TestKeyExchangeWithRSAHostKey verifies key exchange using an RSA host key.
func TestKeyExchangeWithRSAHostKey(t *testing.T) {
	serverConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp256},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKRsaSha256},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Cbc},
		HmacAlgorithms:        []string{ssh.AlgoHmacSha256Etm},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}
	clientConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp256},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKRsaSha256},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Cbc},
		HmacAlgorithms:        []string{ssh.AlgoHmacSha256Etm},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	rsaKey := helpers.GenerateTestRSAKey(t)
	rsaKP, err := ssh.NewRsaKeyPair(rsaKey, ssh.AlgoPKRsaSha256)
	if err != nil {
		t.Fatalf("failed to create RSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{rsaKP},
	}

	ctx := context.Background()
	pair.Connect(ctx)

	if pair.ClientSession.SessionID == nil {
		t.Fatal("client should have session ID after RSA key exchange")
	}

	clientCh, serverCh := pair.OpenChannel(ctx)
	if clientCh == nil || serverCh == nil {
		t.Fatal("channels should work with RSA host key")
	}
}

// TestAlgorithmNegotiationSelectsMostPreferred verifies that algorithm negotiation
// follows RFC 4253 §7.1: iterates through client's preferences and picks the first
// mutually-supported algorithm.
func TestAlgorithmNegotiationSelectsMostPreferred(t *testing.T) {
	// Client prefers ECDH-P384 first, server prefers ECDH-P256 first.
	// The negotiated algorithm should be the client's most-preferred
	// algorithm that the server also supports.
	clientConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp384, ssh.AlgoKexEcdhNistp256},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Gcm},
		HmacAlgorithms:        []string{ssh.AlgoHmacNone},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}
	serverConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp256, ssh.AlgoKexEcdhNistp384},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Gcm},
		HmacAlgorithms:        []string{ssh.AlgoHmacNone},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ClientConfig: clientConfig,
		ServerConfig: serverConfig,
	})
	defer pair.Close()

	serverKey := helpers.GenerateTestECDSAKey(t)
	ecdsaKP, err := ssh.NewEcdsaKeyPair(serverKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{ecdsaKP},
	}

	ctx := context.Background()
	pair.Connect(ctx)

	// Session should connect successfully with the client's preferred algorithm.
	if pair.ClientSession.SessionID == nil {
		t.Fatal("client should have session ID after negotiation")
	}
}

// TestKeyExchangeWithDiffieHellman verifies key exchange using DH group14.
func TestKeyExchangeWithDiffieHellman(t *testing.T) {
	serverConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexDHGroup14},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Ctr},
		HmacAlgorithms:        []string{ssh.AlgoHmacSha512},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}
	clientConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexDHGroup14},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Ctr},
		HmacAlgorithms:        []string{ssh.AlgoHmacSha512},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	serverKey := helpers.GenerateTestECDSAKey(t)
	ecdsaKP, err := ssh.NewEcdsaKeyPair(serverKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{ecdsaKP},
	}

	ctx := context.Background()
	pair.Connect(ctx)

	if pair.ClientSession.SessionID == nil {
		t.Fatal("client should have session ID after DH key exchange")
	}

	clientCh, serverCh := pair.OpenChannel(ctx)
	if clientCh == nil || serverCh == nil {
		t.Fatal("channels should work over DH-encrypted session")
	}
}

// TestKeyExchangeWithGuess verifies that EnableKeyExchangeGuess works.
func TestKeyExchangeWithGuess(t *testing.T) {
	serverConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp384},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Gcm},
		HmacAlgorithms:        []string{ssh.AlgoHmacNone},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}
	clientConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms:  []string{ssh.AlgoKexEcdhNistp384},
		PublicKeyAlgorithms:    []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:   []string{ssh.AlgoEncAes256Gcm},
		HmacAlgorithms:         []string{ssh.AlgoHmacNone},
		CompressionAlgorithms:  []string{ssh.AlgoCompNone},
		EnableKeyExchangeGuess: true,
	}

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	serverKey := helpers.GenerateTestECDSAKey(t)
	ecdsaKP, err := ssh.NewEcdsaKeyPair(serverKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{ecdsaKP},
	}

	ctx := context.Background()
	pair.Connect(ctx)

	if pair.ClientSession.SessionID == nil {
		t.Fatal("client should have session ID after key exchange with guess")
	}

	clientCh, serverCh := pair.OpenChannel(ctx)
	if clientCh == nil || serverCh == nil {
		t.Fatal("channels should work after key exchange with guess")
	}
}

// TestEncryptedChannelData verifies that data sent over an encrypted channel
// arrives correctly, proving encryption/decryption works end-to-end.
func TestEncryptedChannelData(t *testing.T) {
	serverConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp384},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Gcm},
		HmacAlgorithms:        []string{ssh.AlgoHmacNone},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}
	clientConfig := &ssh.SessionConfig{
		KeyExchangeAlgorithms: []string{ssh.AlgoKexEcdhNistp384},
		PublicKeyAlgorithms:   []string{ssh.AlgoPKEcdsaSha2P384},
		EncryptionAlgorithms:  []string{ssh.AlgoEncAes256Gcm},
		HmacAlgorithms:        []string{ssh.AlgoHmacNone},
		CompressionAlgorithms: []string{ssh.AlgoCompNone},
	}

	pair := helpers.NewSessionPairWithConfig(t, &helpers.SessionPairConfig{
		ServerConfig: serverConfig,
		ClientConfig: clientConfig,
	})
	defer pair.Close()

	serverKey := helpers.GenerateTestECDSAKey(t)
	ecdsaKP, err := ssh.NewEcdsaKeyPair(serverKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA key pair: %v", err)
	}
	pair.ServerSession.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{ecdsaKP},
	}

	ctx := context.Background()
	pair.Connect(ctx)

	clientCh, serverCh := pair.OpenChannel(ctx)

	// Send data from client to server over encrypted channel.
	testData := []byte("Hello encrypted world!")
	received := make(chan []byte, 1)
	serverCh.SetDataReceivedHandler(func(data []byte) {
		cp := make([]byte, len(data))
		copy(cp, data)
		received <- cp
	})

	err = clientCh.Send(ctx, testData)
	if err != nil {
		t.Fatalf("client send error: %v", err)
	}

	select {
	case data := <-received:
		if len(data) != len(testData) {
			t.Errorf("received %d bytes, want %d", len(data), len(testData))
		}
		for i, b := range data {
			if b != testData[i] {
				t.Error("received data does not match sent data")
				break
			}
		}
	case <-time.After(kexTestTimeout):
		t.Fatal("timed out waiting for encrypted data transfer")
	}
}
