// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// pipeRWC wraps two pipe endpoints into a ReadWriteCloser.
type pipeRWC struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipeRWC) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeRWC) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeRWC) Close() error {
	p.r.Close()
	return p.w.Close()
}

// newDuplexPipe creates a pair of connected ReadWriteClosers for in-process sessions.
func newDuplexPipe() (io.ReadWriteCloser, io.ReadWriteCloser) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &pipeRWC{r: r1, w: w2}, &pipeRWC{r: r2, w: w1}
}

// latencyStream wraps a stream and adds a delay to each read and write.
type latencyStream struct {
	stream io.ReadWriteCloser
	delay  time.Duration
}

func (s *latencyStream) Read(b []byte) (int, error) {
	time.Sleep(s.delay / 2)
	return s.stream.Read(b)
}

func (s *latencyStream) Write(b []byte) (int, error) {
	time.Sleep(s.delay / 2)
	return s.stream.Write(b)
}

func (s *latencyStream) Close() error { return s.stream.Close() }

// createSessionPair creates a connected client+server session pair via in-process pipes.
func createSessionPair(encrypted bool) (*ssh.ClientSession, *ssh.ServerSession, error) {
	clientStream, serverStream := newDuplexPipe()
	return createSessionPairWithStreams(clientStream, serverStream, encrypted)
}

// createSessionPairWithStreams creates a connected session pair using provided streams.
func createSessionPairWithStreams(clientStream, serverStream io.ReadWriteCloser, encrypted bool) (*ssh.ClientSession, *ssh.ServerSession, error) {
	var clientConfig, serverConfig *ssh.SessionConfig
	if encrypted {
		clientConfig = ssh.NewDefaultConfig()
		serverConfig = ssh.NewDefaultConfig()
	} else {
		clientConfig = ssh.NewNoSecurityConfig()
		serverConfig = ssh.NewNoSecurityConfig()
	}
	clientConfig.KeyRotationThreshold = 0
	serverConfig.KeyRotationThreshold = 0

	client := ssh.NewClientSession(clientConfig)
	client.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	server := ssh.NewServerSession(serverConfig)
	server.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = true
	}

	if encrypted {
		hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
		if err != nil {
			return nil, nil, fmt.Errorf("generate host key: %w", err)
		}
		server.Credentials = &ssh.ServerCredentials{
			PublicKeys: []ssh.KeyPair{hostKey},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
		return nil, nil, fmt.Errorf("client connect: %w", clientErr)
	}
	if serverErr != nil {
		return nil, nil, fmt.Errorf("server connect: %w", serverErr)
	}

	return client, server, nil
}

// openChannel opens a channel between client and server sessions.
func openChannel(client *ssh.Session, server *ssh.Session) (*ssh.Channel, *ssh.Channel, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var clientCh, serverCh *ssh.Channel
	var openErr, acceptErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		clientCh, openErr = client.OpenChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		serverCh, acceptErr = server.AcceptChannel(ctx)
	}()
	wg.Wait()

	if openErr != nil {
		return nil, nil, fmt.Errorf("open channel: %w", openErr)
	}
	if acceptErr != nil {
		return nil, nil, fmt.Errorf("accept channel: %w", acceptErr)
	}

	return clientCh, serverCh, nil
}
