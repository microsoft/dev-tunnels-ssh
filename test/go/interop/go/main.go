// Copyright (c) Microsoft Corporation. All rights reserved.
// Minimal SSH server/client helper for Go interop testing.
// Usage: go-ssh-interop <server|client> <port> <kex> <pk> <enc> <hmac> [mode] [extra]
//
// Modes (optional 7th arg):
//   (none)          — default echo test
//   large           — 1 MB large data transfer with SHA-256 verification
//   multi           — multi-channel isolation test
//   pkauth          — public key authentication test
//   portfwd         — port forwarding test (client requires echo_port as 8th arg)
//   reconnect       — reconnection test over TCP
//   pipe-request    — channel request forwarding through piped sessions
//
// Protocol:
//   Server prints "LISTENING" when ready, "ECHOED <n>" when echoing data.
//   Client prints "AUTHENTICATED", "CHANNEL_OPEN", "ECHO_OK", "DONE".

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
	"github.com/microsoft/dev-tunnels-ssh/src/go/tcp"
)

func main() {
	if len(os.Args) < 7 {
		fmt.Fprintf(os.Stderr,
			"Usage: go-ssh-interop <server|client> <port> <kex> <pk> <enc> <hmac> [mode]\n")
		os.Exit(1)
	}

	role := os.Args[1]
	port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: invalid port: %s\n", os.Args[2])
		os.Exit(1)
	}
	kex := os.Args[3]
	pk := os.Args[4]
	enc := os.Args[5]
	hmac := os.Args[6]

	testMode := ""
	if len(os.Args) >= 8 {
		testMode = os.Args[7]
	}

	// Use reconnect-enabled config for reconnect mode, default config otherwise.
	var config *ssh.SessionConfig
	if testMode == "reconnect" {
		config = createReconnectConfig(kex, pk, enc, hmac)
	} else {
		config = createConfig(kex, pk, enc, hmac)
	}

	var exitCode int
	switch role {
	case "server":
		switch testMode {
		case "portfwd":
			exitCode = runServerPortFwd(config, port, pk)
		case "reconnect":
			exitCode = runServerReconnect(config, port, pk)
		case "concurrent-requests":
			exitCode = runServerConcurrentRequests(config, port, pk)
		case "pipe-request":
			exitCode = runServerPipeRequest(config, port, pk)
		default:
			exitCode = runServer(config, port, pk, testMode)
		}
	case "client":
		switch testMode {
		case "":
			exitCode = runClient(config, port)
		case "large":
			exitCode = runClientLarge(config, port)
		case "multi":
			exitCode = runClientMulti(config, port)
		case "pkauth":
			exitCode = runClientPkAuth(config, port, pk)
		case "portfwd":
			if len(os.Args) < 9 {
				fmt.Fprintf(os.Stderr, "portfwd mode requires echo port as 8th argument\n")
				exitCode = 1
			} else {
				echoPort, err := strconv.Atoi(os.Args[8])
				if err != nil {
					fmt.Fprintf(os.Stderr, "ERROR: invalid echo port: %s\n", os.Args[8])
					exitCode = 1
				} else {
					exitCode = runClientPortFwd(config, port, echoPort)
				}
			}
		case "reconnect":
			exitCode = runClientReconnect(config, port)
		case "concurrent-requests":
			exitCode = runClientConcurrentRequests(config, port)
		case "pipe-request":
			exitCode = runClientPipeRequest(config, port)
		default:
			fmt.Fprintf(os.Stderr, "Unknown test mode: %s\n", testMode)
			exitCode = 1
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown role: %s\n", role)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func createConfig(kex, pk, enc, hmac string) *ssh.SessionConfig {
	config := ssh.NewDefaultConfig()
	config.KeyExchangeAlgorithms = []string{kex}
	config.PublicKeyAlgorithms = []string{pk}
	config.EncryptionAlgorithms = []string{enc}
	config.HmacAlgorithms = []string{hmac}
	return config
}

func createReconnectConfig(kex, pk, enc, hmac string) *ssh.SessionConfig {
	config := ssh.NewDefaultConfigWithReconnect()
	config.KeyExchangeAlgorithms = []string{kex}
	config.PublicKeyAlgorithms = []string{pk}
	config.EncryptionAlgorithms = []string{enc}
	config.HmacAlgorithms = []string{hmac}
	return config
}

func runServer(config *ssh.SessionConfig, port int, pkName string, testMode string) int {
	hostKey, err := ssh.GenerateKeyPair(pkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to generate host key: %v\n", err)
		return 1
	}

	server := tcp.NewServer(config)
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	sessionDone := make(chan struct{}, 1)

	if testMode == "pkauth" {
		server.OnSessionAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
			// Only accept public key authentication with verified signatures.
			// The library verifies the signature before calling this callback,
			// so we just need to check the auth type.
			switch e.AuthenticationType {
			case ssh.AuthClientPublicKeyQuery:
				// Accept query: yes, this public key would be accepted.
				e.AuthenticationResult = true
			case ssh.AuthClientPublicKey:
				// Full PK auth — signature already verified by the library.
				e.AuthenticationResult = true
				fmt.Println("PK_AUTH_VERIFIED")
			default:
				// Reject non-PK auth methods.
				e.AuthenticationResult = false
			}
		}
	} else {
		server.OnSessionAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
			// Accept all authentication.
			e.AuthenticationResult = true
		}
	}

	server.OnSessionOpened = func(session *ssh.ServerSession) {
		session.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
			ch := e.Channel
			ch.SetDataReceivedHandler(func(data []byte) {
				buf := append([]byte(nil), data...)
				sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if sendErr := ch.Send(sendCtx, buf); sendErr != nil {
					fmt.Fprintf(os.Stderr, "Echo error: %v\n", sendErr)
					return
				}
				fmt.Printf("ECHOED %d\n", len(buf))
			})
		}

		session.OnClosed = func(e *ssh.SessionClosedEventArgs) {
			select {
			case sessionDone <- struct{}{}:
			default:
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start accepting in background.
	acceptErr := make(chan error, 1)
	go func() {
		acceptErr <- server.AcceptSessions(ctx, port, "127.0.0.1")
	}()

	// Give the listener a moment to start, then verify it is listening.
	time.Sleep(50 * time.Millisecond)
	if server.ListenPort() == 0 {
		// Wait a bit more.
		time.Sleep(200 * time.Millisecond)
	}

	fmt.Println("LISTENING")

	// Wait for session completion or timeout.
	select {
	case <-sessionDone:
	case <-ctx.Done():
	case err := <-acceptErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
		}
	}

	server.Close()
	return 0
}

func connectAndAuth(config *ssh.SessionConfig, port int) (*ssh.ClientSession, context.Context, context.CancelFunc, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)

	client := tcp.NewClient(config)
	session, err := client.OpenSession(ctx, "127.0.0.1", port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to open session: %v\n", err)
		cancel()
		return nil, nil, nil, 1
	}

	session.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	authenticated, err := session.Authenticate(ctx, &ssh.ClientCredentials{
		Username: "testuser",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: authentication error: %v\n", err)
		cancel()
		return nil, nil, nil, 1
	}
	if !authenticated {
		fmt.Fprintf(os.Stderr, "Authentication failed\n")
		cancel()
		return nil, nil, nil, 1
	}

	fmt.Println("AUTHENTICATED")
	return session, ctx, cancel, 0
}

func runClient(config *ssh.SessionConfig, port int) int {
	session, ctx, cancel, code := connectAndAuth(config, port)
	if code != 0 {
		return code
	}
	defer cancel()

	ch, err := session.OpenChannel(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to open channel: %v\n", err)
		return 1
	}

	fmt.Println("CHANNEL_OPEN")

	// Send test data.
	testData := []byte("INTEROP_TEST_DATA")
	echoCh := make(chan []byte, 1)

	ch.SetDataReceivedHandler(func(data []byte) {
		received := append([]byte(nil), data...)
		select {
		case echoCh <- received:
		default:
		}
	})

	if err := ch.Send(ctx, testData); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to send data: %v\n", err)
		return 1
	}

	// Wait for echo.
	echoCtx, echoCancel := context.WithTimeout(ctx, 10*time.Second)
	defer echoCancel()

	select {
	case echoed := <-echoCh:
		if string(echoed) == "INTEROP_TEST_DATA" {
			fmt.Println("ECHO_OK")
		} else {
			fmt.Fprintf(os.Stderr, "Echo mismatch: got %q\n", string(echoed))
			return 1
		}
	case <-echoCtx.Done():
		fmt.Fprintf(os.Stderr, "Echo timeout\n")
		return 1
	}

	fmt.Println("DONE")
	ch.Close()
	session.Close()
	return 0
}

const largeDataSize = 1048576 // 1 MB

func runClientLarge(config *ssh.SessionConfig, port int) int {
	session, ctx, cancel, code := connectAndAuth(config, port)
	if code != 0 {
		return code
	}
	defer cancel()

	ch, err := session.OpenChannel(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to open channel: %v\n", err)
		return 1
	}

	fmt.Println("CHANNEL_OPEN")

	// Generate 1 MB deterministic data: byte[i] = byte(i % 256).
	sendData := make([]byte, largeDataSize)
	for i := range sendData {
		sendData[i] = byte(i % 256)
	}
	sendHash := sha256.Sum256(sendData)

	// Accumulate echoed data.
	var mu sync.Mutex
	received := make([]byte, 0, largeDataSize)
	done := make(chan struct{})

	ch.SetDataReceivedHandler(func(data []byte) {
		mu.Lock()
		received = append(received, data...)
		total := len(received)
		mu.Unlock()
		if total >= largeDataSize {
			select {
			case done <- struct{}{}:
			default:
			}
		}
	})

	// Send all data (Channel.Send handles chunking internally).
	if err := ch.Send(ctx, sendData); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to send data: %v\n", err)
		return 1
	}

	// Wait for all echoed data.
	echoCtx, echoCancel := context.WithTimeout(ctx, 20*time.Second)
	defer echoCancel()

	select {
	case <-done:
	case <-echoCtx.Done():
		mu.Lock()
		got := len(received)
		mu.Unlock()
		fmt.Fprintf(os.Stderr, "Echo timeout: received %d/%d bytes\n", got, largeDataSize)
		fmt.Println("LARGE_DATA_FAIL")
		ch.Close()
		session.Close()
		return 1
	}

	mu.Lock()
	recvHash := sha256.Sum256(received[:largeDataSize])
	mu.Unlock()

	if sendHash == recvHash {
		fmt.Println("LARGE_DATA_OK")
	} else {
		fmt.Fprintf(os.Stderr, "Hash mismatch: sent %x, received %x\n", sendHash, recvHash)
		fmt.Println("LARGE_DATA_FAIL")
		ch.Close()
		session.Close()
		return 1
	}

	fmt.Println("DONE")
	ch.Close()
	session.Close()
	return 0
}

func runClientMulti(config *ssh.SessionConfig, port int) int {
	session, ctx, cancel, code := connectAndAuth(config, port)
	if code != 0 {
		return code
	}
	defer cancel()

	type chanResult struct {
		index int
		ok    bool
	}

	channelData := []string{"CH1_DATA", "CH2_DATA", "CH3_DATA"}
	results := make(chan chanResult, 3)

	for i, data := range channelData {
		ch, err := session.OpenChannel(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: failed to open channel %d: %v\n", i+1, err)
			fmt.Println("MULTI_CHANNEL_FAIL")
			session.Close()
			return 1
		}

		echoCh := make(chan []byte, 1)
		ch.SetDataReceivedHandler(func(d []byte) {
			received := append([]byte(nil), d...)
			select {
			case echoCh <- received:
			default:
			}
		})

		idx := i
		expected := data
		go func() {
			sendCtx, sendCancel := context.WithTimeout(ctx, 10*time.Second)
			defer sendCancel()

			if sendErr := ch.Send(sendCtx, []byte(expected)); sendErr != nil {
				fmt.Fprintf(os.Stderr, "ERROR: failed to send on channel %d: %v\n", idx+1, sendErr)
				results <- chanResult{idx, false}
				return
			}

			select {
			case echoed := <-echoCh:
				if string(echoed) == expected {
					results <- chanResult{idx, true}
				} else {
					fmt.Fprintf(os.Stderr, "Channel %d echo mismatch: got %q, expected %q\n",
						idx+1, string(echoed), expected)
					results <- chanResult{idx, false}
				}
			case <-sendCtx.Done():
				fmt.Fprintf(os.Stderr, "Channel %d echo timeout\n", idx+1)
				results <- chanResult{idx, false}
			}
		}()
	}

	allOK := true
	for range channelData {
		r := <-results
		if !r.ok {
			allOK = false
		}
	}

	if allOK {
		fmt.Println("MULTI_CHANNEL_OK")
	} else {
		fmt.Println("MULTI_CHANNEL_FAIL")
		session.Close()
		return 1
	}

	fmt.Println("DONE")
	session.Close()
	return 0
}

func runClientPkAuth(config *ssh.SessionConfig, port int, pkAlgorithm string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// Generate a client key pair for public key authentication.
	clientKey, err := ssh.GenerateKeyPair(pkAlgorithm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to generate client key: %v\n", err)
		return 1
	}

	client := tcp.NewClient(config)
	session, err := client.OpenSession(ctx, "127.0.0.1", port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to open session: %v\n", err)
		return 1
	}

	session.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	// Authenticate with public key (not password).
	authenticated, err := session.Authenticate(ctx, &ssh.ClientCredentials{
		Username:   "testuser",
		PublicKeys: []ssh.KeyPair{clientKey},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: authentication error: %v\n", err)
		return 1
	}
	if !authenticated {
		fmt.Fprintf(os.Stderr, "Public key authentication failed\n")
		return 1
	}

	fmt.Println("PK_AUTH_OK")
	fmt.Println("AUTHENTICATED")

	// Also do an echo test to verify the session is fully functional.
	ch, err := session.OpenChannel(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to open channel: %v\n", err)
		return 1
	}

	fmt.Println("CHANNEL_OPEN")

	testData := []byte("PKAUTH_ECHO_TEST")
	echoCh := make(chan []byte, 1)

	ch.SetDataReceivedHandler(func(data []byte) {
		received := append([]byte(nil), data...)
		select {
		case echoCh <- received:
		default:
		}
	})

	if err := ch.Send(ctx, testData); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to send data: %v\n", err)
		return 1
	}

	echoCtx, echoCancel := context.WithTimeout(ctx, 10*time.Second)
	defer echoCancel()

	select {
	case echoed := <-echoCh:
		if string(echoed) == "PKAUTH_ECHO_TEST" {
			fmt.Println("ECHO_OK")
		} else {
			fmt.Fprintf(os.Stderr, "Echo mismatch: got %q\n", string(echoed))
			return 1
		}
	case <-echoCtx.Done():
		fmt.Fprintf(os.Stderr, "Echo timeout\n")
		return 1
	}

	fmt.Println("DONE")
	ch.Close()
	session.Close()
	return 0
}

func runServerPortFwd(config *ssh.SessionConfig, port int, pkName string) int {
	hostKey, err := ssh.GenerateKeyPair(pkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to generate host key: %v\n", err)
		return 1
	}

	// Register port forwarding service so the server handles direct-tcpip channels.
	tcp.AddPortForwardingService(config)

	// Start a TCP echo server on a random port.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to start echo server: %v\n", err)
		return 1
	}
	echoPort := echoLn.Addr().(*net.TCPAddr).Port
	go runTCPEcho(echoLn)
	defer echoLn.Close()

	server := tcp.NewServer(config)
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	server.OnSessionAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	sessionDone := make(chan struct{}, 1)
	server.OnSessionOpened = func(session *ssh.ServerSession) {
		session.OnClosed = func(e *ssh.SessionClosedEventArgs) {
			select {
			case sessionDone <- struct{}{}:
			default:
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	acceptErr := make(chan error, 1)
	go func() {
		acceptErr <- server.AcceptSessions(ctx, port, "127.0.0.1")
	}()

	time.Sleep(50 * time.Millisecond)
	if server.ListenPort() == 0 {
		time.Sleep(200 * time.Millisecond)
	}

	fmt.Printf("LISTENING %d %d\n", server.ListenPort(), echoPort)

	select {
	case <-sessionDone:
	case <-ctx.Done():
	case err := <-acceptErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
		}
	}

	server.Close()
	return 0
}

// runTCPEcho accepts TCP connections and echoes all received data back.
func runTCPEcho(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 8192)
			for {
				n, readErr := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n])
				}
				if readErr != nil {
					return
				}
			}
		}(conn)
	}
}

func runClientPortFwd(config *ssh.SessionConfig, port int, echoPort int) int {
	// Register port forwarding service for direct-tcpip channel support.
	tcp.AddPortForwardingService(config)

	session, ctx, cancel, code := connectAndAuth(config, port)
	if code != 0 {
		return code
	}
	defer cancel()

	pfs := tcp.GetPortForwardingService(&session.Session)
	if pfs == nil {
		fmt.Fprintf(os.Stderr, "ERROR: port forwarding service not available\n")
		return 1
	}

	// Open a direct-tcpip channel to the echo server port.
	stream, err := pfs.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to stream to remote port: %v\n", err)
		return 1
	}

	testData := []byte("PORT_FORWARD_TEST_DATA")
	if _, err := stream.Write(testData); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to write to forwarded stream: %v\n", err)
		stream.Close()
		return 1
	}

	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(stream, buf); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to read from forwarded stream: %v\n", err)
		stream.Close()
		return 1
	}

	if string(buf) == string(testData) {
		fmt.Println("PORT_FORWARD_OK")
	} else {
		fmt.Fprintf(os.Stderr, "Port forward echo mismatch: got %q, expected %q\n",
			string(buf), string(testData))
		stream.Close()
		session.Close()
		return 1
	}

	fmt.Println("DONE")
	stream.Close()
	session.Close()
	return 0
}

func runServerReconnect(config *ssh.SessionConfig, port int, pkName string) int {
	hostKey, err := ssh.GenerateKeyPair(pkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to generate host key: %v\n", err)
		return 1
	}

	server := tcp.NewServer(config)
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	server.OnSessionAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	reconnected := make(chan struct{}, 1)
	done := make(chan struct{}, 1)

	server.OnSessionOpened = func(session *ssh.ServerSession) {
		// Install echo handler on all channels.
		session.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
			ch := e.Channel
			ch.SetDataReceivedHandler(func(data []byte) {
				buf := append([]byte(nil), data...)
				sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if sendErr := ch.Send(sendCtx, buf); sendErr != nil {
					fmt.Fprintf(os.Stderr, "Echo error: %v\n", sendErr)
					return
				}
				fmt.Printf("ECHOED %d\n", len(buf))
			})
		}

		// Set up OnReconnected callback — fires on the original session
		// when a client reconnects to it.
		session.OnReconnected = func() {
			fmt.Println("RECONNECTED")
			select {
			case reconnected <- struct{}{}:
			default:
			}
		}

		session.OnClosed = func(e *ssh.SessionClosedEventArgs) {
			select {
			case done <- struct{}{}:
			default:
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	acceptErr := make(chan error, 1)
	go func() {
		acceptErr <- server.AcceptSessions(ctx, port, "127.0.0.1")
	}()

	time.Sleep(50 * time.Millisecond)
	if server.ListenPort() == 0 {
		time.Sleep(200 * time.Millisecond)
	}

	fmt.Println("LISTENING")

	// Wait for reconnection, then for session close or timeout.
	select {
	case <-reconnected:
		// Wait for done or timeout after reconnection.
		select {
		case <-done:
		case <-ctx.Done():
		}
	case <-done:
	case <-ctx.Done():
	case err := <-acceptErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
		}
	}

	server.Close()
	return 0
}

func runClientReconnect(config *ssh.SessionConfig, port int) int {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// Dial raw TCP connection (we need to close it later to simulate disconnect).
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to dial: %v\n", err)
		return 1
	}

	session := ssh.NewClientSession(config)

	session.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	// Track disconnect.
	disconnected := make(chan struct{}, 1)
	session.OnDisconnected = func() {
		select {
		case disconnected <- struct{}{}:
		default:
		}
	}

	if err := session.Connect(ctx, rawConn); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to connect: %v\n", err)
		return 1
	}

	authenticated, err := session.Authenticate(ctx, &ssh.ClientCredentials{
		Username: "testuser",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: authentication error: %v\n", err)
		return 1
	}
	if !authenticated {
		fmt.Fprintf(os.Stderr, "Authentication failed\n")
		return 1
	}
	fmt.Println("AUTHENTICATED")

	// Wait for reconnect to be enabled before opening channels.
	enableCtx, enableCancel := context.WithTimeout(ctx, 5*time.Second)
	defer enableCancel()
	if err := ssh.WaitUntilReconnectEnabled(enableCtx, &session.Session); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reconnect not enabled: %v\n", err)
		return 1
	}

	// Open channel and send data.
	ch, err := session.OpenChannel(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to open channel: %v\n", err)
		return 1
	}
	fmt.Println("CHANNEL_OPEN")

	echoCh := make(chan []byte, 10)
	ch.SetDataReceivedHandler(func(data []byte) {
		received := append([]byte(nil), data...)
		select {
		case echoCh <- received:
		default:
		}
	})

	// Send data and verify echo (pre-reconnect).
	testData1 := []byte("BEFORE_RECONNECT")
	if err := ch.Send(ctx, testData1); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to send data: %v\n", err)
		return 1
	}

	echoCtx1, echoCancel1 := context.WithTimeout(ctx, 10*time.Second)
	defer echoCancel1()
	select {
	case echoed := <-echoCh:
		if string(echoed) == string(testData1) {
			fmt.Println("ECHO_OK")
		} else {
			fmt.Fprintf(os.Stderr, "Echo mismatch: got %q, expected %q\n", string(echoed), string(testData1))
			return 1
		}
	case <-echoCtx1.Done():
		fmt.Fprintf(os.Stderr, "Echo timeout (pre-reconnect)\n")
		return 1
	}

	// Simulate network failure: close the raw TCP connection.
	rawConn.Close()
	fmt.Println("DISCONNECTED")

	// Wait for session to detect disconnect.
	disconnectCtx, disconnectCancel := context.WithTimeout(ctx, 5*time.Second)
	defer disconnectCancel()
	select {
	case <-disconnected:
	case <-disconnectCtx.Done():
		fmt.Fprintf(os.Stderr, "ERROR: disconnect not detected\n")
		return 1
	}

	// Dial new TCP connection for reconnect.
	newConn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to dial for reconnect: %v\n", err)
		return 1
	}

	if err := session.Reconnect(ctx, newConn); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reconnect failed: %v\n", err)
		return 1
	}
	fmt.Println("RECONNECT_OK")

	// Drain any retransmitted echo data.
drainLoop:
	for {
		select {
		case <-echoCh:
		default:
			break drainLoop
		}
	}

	// Send data on the same channel after reconnect and verify echo.
	testData2 := []byte("AFTER_RECONNECT")
	if err := ch.Send(ctx, testData2); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to send data after reconnect: %v\n", err)
		return 1
	}

	echoCtx2, echoCancel2 := context.WithTimeout(ctx, 10*time.Second)
	defer echoCancel2()
	select {
	case echoed := <-echoCh:
		if string(echoed) == string(testData2) {
			fmt.Println("ECHO_AFTER_RECONNECT_OK")
		} else {
			fmt.Fprintf(os.Stderr, "Echo mismatch after reconnect: got %q, expected %q\n",
				string(echoed), string(testData2))
			return 1
		}
	case <-echoCtx2.Done():
		fmt.Fprintf(os.Stderr, "Echo timeout (post-reconnect)\n")
		return 1
	}

	fmt.Println("DONE")
	ch.Close()
	session.Close()
	return 0
}

func runServerConcurrentRequests(config *ssh.SessionConfig, port int, pkName string) int {
	hostKey, err := ssh.GenerateKeyPair(pkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to generate host key: %v\n", err)
		return 1
	}

	server := tcp.NewServer(config)
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	server.OnSessionAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	sessionDone := make(chan struct{}, 1)

	server.OnSessionOpened = func(session *ssh.ServerSession) {
		channelCount := 0

		session.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
			ch := e.Channel
			channelCount++
			chNum := channelCount

			// Channel 1: request handler blocks for 1 second.
			// Channel 2: echo handler responds immediately.
			if chNum == 1 {
				ch.OnRequest = func(args *ssh.RequestEventArgs) {
					fmt.Println("CH1_REQUEST_RECEIVED")
					time.Sleep(1 * time.Second)
					args.IsAuthorized = true
					fmt.Println("CH1_REQUEST_DONE")
				}
				// Also set up echo on channel 1 for completeness.
				ch.SetDataReceivedHandler(func(data []byte) {
					buf := append([]byte(nil), data...)
					sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					ch.Send(sendCtx, buf)
				})
			} else {
				ch.SetDataReceivedHandler(func(data []byte) {
					buf := append([]byte(nil), data...)
					sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if sendErr := ch.Send(sendCtx, buf); sendErr != nil {
						fmt.Fprintf(os.Stderr, "Echo error on ch2: %v\n", sendErr)
						return
					}
					fmt.Println("CH2_ECHOED")
				})
			}
		}

		session.OnClosed = func(e *ssh.SessionClosedEventArgs) {
			select {
			case sessionDone <- struct{}{}:
			default:
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	acceptErr := make(chan error, 1)
	go func() {
		acceptErr <- server.AcceptSessions(ctx, port, "127.0.0.1")
	}()

	time.Sleep(50 * time.Millisecond)
	if server.ListenPort() == 0 {
		time.Sleep(200 * time.Millisecond)
	}

	fmt.Println("LISTENING")

	select {
	case <-sessionDone:
	case <-ctx.Done():
	case err := <-acceptErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
		}
	}

	server.Close()
	return 0
}

func runClientConcurrentRequests(config *ssh.SessionConfig, port int) int {
	session, ctx, cancel, code := connectAndAuth(config, port)
	if code != 0 {
		return code
	}
	defer cancel()

	// Open channel 1 (will have a blocking request handler on the server).
	ch1, err := session.OpenChannel(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to open channel 1: %v\n", err)
		return 1
	}
	fmt.Println("CHANNEL1_OPEN")

	// Open channel 2 (echo channel).
	ch2, err := session.OpenChannel(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to open channel 2: %v\n", err)
		return 1
	}
	fmt.Println("CHANNEL2_OPEN")

	// Set up echo receiver on channel 2.
	echoCh := make(chan []byte, 1)
	ch2.SetDataReceivedHandler(func(data []byte) {
		received := append([]byte(nil), data...)
		select {
		case echoCh <- received:
		default:
		}
	})

	// Send a blocking request on channel 1 (runs in goroutine since it waits for reply).
	reqDone := make(chan bool, 1)
	go func() {
		success, reqErr := ch1.Request(ctx, &messages.ChannelRequestMessage{
			RequestType: "blocking-test",
			WantReply:   true,
		})
		if reqErr != nil {
			fmt.Fprintf(os.Stderr, "ERROR: channel 1 request error: %v\n", reqErr)
			reqDone <- false
			return
		}
		reqDone <- success
	}()

	// Give a tiny moment for the request to reach the server.
	time.Sleep(50 * time.Millisecond)

	// Now send data on channel 2 — this should echo back quickly if dispatch is non-blocking.
	testData := []byte("CONCURRENT_TEST_DATA")
	if err := ch2.Send(ctx, testData); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to send data on channel 2: %v\n", err)
		return 1
	}

	// Wait for echo on channel 2 (should arrive within 500ms if non-blocking).
	echoCtx, echoCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer echoCancel()

	select {
	case echoed := <-echoCh:
		if string(echoed) == string(testData) {
			fmt.Println("CONCURRENT_REQUEST_OK")
		} else {
			fmt.Fprintf(os.Stderr, "Echo mismatch on channel 2: got %q\n", string(echoed))
			return 1
		}
	case <-echoCtx.Done():
		fmt.Fprintf(os.Stderr, "Channel 2 echo timeout — dispatch loop may be blocked by channel 1 request handler\n")
		return 1
	}

	// Wait for channel 1 request to complete.
	reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
	defer reqCancel()

	select {
	case success := <-reqDone:
		if success {
			fmt.Println("CH1_REQUEST_OK")
		} else {
			fmt.Fprintf(os.Stderr, "Channel 1 request was rejected\n")
			return 1
		}
	case <-reqCtx.Done():
		fmt.Fprintf(os.Stderr, "Channel 1 request timeout\n")
		return 1
	}

	fmt.Println("DONE")
	ch1.Close()
	ch2.Close()
	session.Close()
	return 0
}

// pipeRWC wraps an io.PipeReader and io.PipeWriter into an io.ReadWriteCloser.
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

// runServerPipeRequest runs a relay server that pipes the external client's
// session to an internal echo server (server B) via PipeSession. Server B
// handles channel requests and echoes data. This verifies that Channel.Pipe
// request forwarding works end-to-end over real TCP.
func runServerPipeRequest(config *ssh.SessionConfig, port int, pkName string) int {
	hostKey, err := ssh.GenerateKeyPair(pkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to generate host key: %v\n", err)
		return 1
	}

	server := tcp.NewServer(config)
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	server.OnSessionAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
		e.AuthenticationResult = true
	}

	sessionDone := make(chan struct{}, 1)

	server.OnSessionOpened = func(session *ssh.ServerSession) {
		go func() {
			pipeCtx, pipeCancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer pipeCancel()

			// Create an internal pipe pair for server B.
			r1, w1 := io.Pipe()
			r2, w2 := io.Pipe()
			internalClientConn := &pipeRWC{r: r1, w: w2}
			internalServerConn := &pipeRWC{r: r2, w: w1}

			// Server B: no-security, handles channel requests + echoes data.
			serverB := ssh.NewServerSession(nil)
			serverB.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
				e.AuthenticationResult = true
			}
			serverB.OnChannelOpening = func(e *ssh.ChannelOpeningEventArgs) {
				ch := e.Channel
				ch.OnRequest = func(args *ssh.RequestEventArgs) {
					fmt.Printf("SERVER_B_REQUEST: %s\n", args.RequestType)
					args.IsAuthorized = true
				}
				ch.SetDataReceivedHandler(func(data []byte) {
					buf := append([]byte(nil), data...)
					sendCtx, cancel := context.WithTimeout(pipeCtx, 10*time.Second)
					defer cancel()
					if sendErr := ch.Send(sendCtx, buf); sendErr != nil {
						fmt.Fprintf(os.Stderr, "ServerB echo error: %v\n", sendErr)
					}
				})
			}

			// Internal client: no-security, connects to server B.
			internalClient := ssh.NewClientSession(nil)
			internalClient.OnAuthenticating = func(e *ssh.AuthenticatingEventArgs) {
				e.AuthenticationResult = true
			}

			// Connect both internal sides concurrently (io.Pipe is synchronous).
			var wg sync.WaitGroup
			var serverBErr, clientErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				serverBErr = serverB.Connect(pipeCtx, internalServerConn)
			}()
			go func() {
				defer wg.Done()
				clientErr = internalClient.Connect(pipeCtx, internalClientConn)
			}()
			wg.Wait()

			if serverBErr != nil {
				fmt.Fprintf(os.Stderr, "ERROR: serverB connect failed: %v\n", serverBErr)
				select {
				case sessionDone <- struct{}{}:
				default:
				}
				return
			}
			if clientErr != nil {
				fmt.Fprintf(os.Stderr, "ERROR: internal client connect failed: %v\n", clientErr)
				select {
				case sessionDone <- struct{}{}:
				default:
				}
				return
			}

			// Pipe external server A session to internal client session.
			// PipeSession blocks until one session closes.
			_ = ssh.PipeSession(pipeCtx, &session.Session, &internalClient.Session)

			select {
			case sessionDone <- struct{}{}:
			default:
			}
		}()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	acceptErr := make(chan error, 1)
	go func() {
		acceptErr <- server.AcceptSessions(ctx, port, "127.0.0.1")
	}()

	time.Sleep(50 * time.Millisecond)
	if server.ListenPort() == 0 {
		time.Sleep(200 * time.Millisecond)
	}

	fmt.Println("LISTENING")

	select {
	case <-sessionDone:
	case <-ctx.Done():
	case err := <-acceptErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
		}
	}

	server.Close()
	return 0
}

// runClientPipeRequest connects to a relay server, opens a channel, sends a
// custom channel request through the piped session, verifies the reply, then
// sends data and verifies echo.
func runClientPipeRequest(config *ssh.SessionConfig, port int) int {
	session, ctx, cancel, code := connectAndAuth(config, port)
	if code != 0 {
		return code
	}
	defer cancel()

	ch, err := session.OpenChannel(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to open channel: %v\n", err)
		return 1
	}

	fmt.Println("CHANNEL_OPEN")

	// Send a custom channel request ("test-request") with want_reply=true.
	// This request travels: client -> server A -> (pipe) -> internal client -> server B.
	success, err := ch.Request(ctx, &messages.ChannelRequestMessage{
		RequestType: "test-request",
		WantReply:   true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: channel request failed: %v\n", err)
		return 1
	}
	if !success {
		fmt.Fprintf(os.Stderr, "ERROR: channel request was rejected\n")
		return 1
	}

	fmt.Println("PIPE_REQUEST_FORWARDED")

	// Send data and verify echo through the pipe.
	testData := []byte("PIPE_ECHO_TEST")
	echoCh := make(chan []byte, 1)

	ch.SetDataReceivedHandler(func(data []byte) {
		received := append([]byte(nil), data...)
		select {
		case echoCh <- received:
		default:
		}
	})

	if err := ch.Send(ctx, testData); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to send data: %v\n", err)
		return 1
	}

	echoCtx, echoCancel := context.WithTimeout(ctx, 10*time.Second)
	defer echoCancel()

	select {
	case echoed := <-echoCh:
		if string(echoed) == string(testData) {
			fmt.Println("ECHO_OK")
		} else {
			fmt.Fprintf(os.Stderr, "Echo mismatch: got %q, expected %q\n",
				string(echoed), string(testData))
			return 1
		}
	case <-echoCtx.Done():
		fmt.Fprintf(os.Stderr, "Echo timeout\n")
		return 1
	}

	fmt.Println("DONE")
	ch.Close()
	session.Close()
	return 0
}
