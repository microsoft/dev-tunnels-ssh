// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

// TestSecureStreamServerAuth verifies that the client's OnAuthenticating callback
// receives the server's host key for verification, matching C#/TS SecureStreamTests.
func TestSecureStreamServerAuth(t *testing.T) {
	serverKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	serverPubBytes, err := serverKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("failed to get server public key bytes: %v", err)
	}

	s1, s2 := helpers.CreateDuplexStreams()

	clientCreds := &ssh.ClientCredentials{Username: "testuser"}
	serverCreds := &ssh.ServerCredentials{PublicKeys: []ssh.KeyPair{serverKey}}

	client := ssh.NewSecureStreamClient(s1, clientCreds, false)
	server := ssh.NewSecureStreamServer(s2, serverCreds, nil)

	var receivedAuthType ssh.AuthenticationType
	var receivedPubKeyBytes []byte
	var mu sync.Mutex

	client.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		mu.Lock()
		defer mu.Unlock()
		receivedAuthType = args.AuthenticationType
		if args.PublicKey != nil {
			receivedPubKeyBytes, _ = args.PublicKey.GetPublicKeyBytes()
		}
		args.AuthenticationResult = true
	}

	server.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	mu.Lock()
	defer mu.Unlock()

	if receivedAuthType != ssh.AuthServerPublicKey {
		t.Errorf("expected client auth type AuthServerPublicKey (%d), got %d",
			ssh.AuthServerPublicKey, receivedAuthType)
	}

	if receivedPubKeyBytes == nil {
		t.Fatal("client OnAuthenticating did not receive server public key")
	}

	if !bytes.Equal(receivedPubKeyBytes, serverPubBytes) {
		t.Error("client received different public key bytes than the server's host key")
	}
}

// TestSecureStreamClientAuth verifies that the server's OnAuthenticating callback
// receives the client's public key and auth succeeds, matching C#/TS SecureStreamTests.
func TestSecureStreamClientAuth(t *testing.T) {
	serverKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	clientKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	clientPubBytes, err := clientKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("failed to get client public key bytes: %v", err)
	}

	s1, s2 := helpers.CreateDuplexStreams()

	clientCreds := &ssh.ClientCredentials{
		Username:   "testuser",
		PublicKeys: []ssh.KeyPair{clientKey},
	}
	serverCreds := &ssh.ServerCredentials{PublicKeys: []ssh.KeyPair{serverKey}}

	client := ssh.NewSecureStreamClient(s1, clientCreds, false)
	server := ssh.NewSecureStreamServer(s2, serverCreds, nil)

	client.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	var receivedAuthType ssh.AuthenticationType
	var receivedPubKeyBytes []byte
	var mu sync.Mutex

	server.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		mu.Lock()
		defer mu.Unlock()
		receivedAuthType = args.AuthenticationType
		if args.PublicKey != nil {
			receivedPubKeyBytes, _ = args.PublicKey.GetPublicKeyBytes()
		}
		args.AuthenticationResult = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

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

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	mu.Lock()
	defer mu.Unlock()

	if receivedAuthType != ssh.AuthClientPublicKey {
		t.Errorf("expected server auth type AuthClientPublicKey (%d), got %d",
			ssh.AuthClientPublicKey, receivedAuthType)
	}

	if receivedPubKeyBytes == nil {
		t.Fatal("server OnAuthenticating did not receive client public key")
	}

	if !bytes.Equal(receivedPubKeyBytes, clientPubBytes) {
		t.Error("server received different public key bytes than the client's key")
	}
}

// TestSecureStreamReadWrite verifies bidirectional 1KB data exchange through
// SecureStream with data integrity checks, matching C#/TS SecureStreamTests.
func TestSecureStreamReadWriteParity(t *testing.T) {
	client, server := helpers.CreateSecureStreamPair(t)

	// Generate 1KB test data.
	const dataSize = 1024
	clientData := make([]byte, dataSize)
	for i := range clientData {
		clientData[i] = byte(i % 256)
	}

	// Client writes 1KB, server reads.
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(clientData)
		writeDone <- err
	}()

	serverBuf := make([]byte, dataSize)
	_, err := io.ReadFull(server, serverBuf)
	if err != nil {
		t.Fatalf("server read failed: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if !bytes.Equal(serverBuf, clientData) {
		t.Error("server received data does not match client sent data")
	}

	// Server writes response, client reads.
	serverData := make([]byte, dataSize)
	for i := range serverData {
		serverData[i] = byte((i + 128) % 256)
	}

	go func() {
		_, err := server.Write(serverData)
		writeDone <- err
	}()

	clientBuf := make([]byte, dataSize)
	_, err = io.ReadFull(client, clientBuf)
	if err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("server write failed: %v", err)
	}
	if !bytes.Equal(clientBuf, serverData) {
		t.Error("client received data does not match server sent data")
	}
}

// TestSecureStreamCloseFiresEvent verifies that closing one side fires OnClosed
// on both sides, matching C#/TS SecureStreamTests.
func TestSecureStreamCloseFiresEvent(t *testing.T) {
	client, server := helpers.CreateSecureStreamPair(t)

	clientClosedCh := make(chan *ssh.SessionClosedEventArgs, 1)
	serverClosedCh := make(chan *ssh.SessionClosedEventArgs, 1)

	client.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		clientClosedCh <- args
	}
	server.OnClosed = func(args *ssh.SessionClosedEventArgs) {
		serverClosedCh <- args
	}

	// Close one side.
	client.Close()

	// Verify OnClosed fires on the client side.
	select {
	case args := <-clientClosedCh:
		if args == nil {
			t.Error("client OnClosed args should not be nil")
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for client OnClosed")
	}

	// Verify OnClosed fires on the server side (triggered by disconnect).
	select {
	case args := <-serverClosedCh:
		if args == nil {
			t.Error("server OnClosed args should not be nil")
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for server OnClosed")
	}

	// Verify both report closed state.
	if !client.IsClosed() {
		t.Error("client should be closed")
	}
	if !server.IsClosed() {
		t.Error("server should be closed")
	}
}
