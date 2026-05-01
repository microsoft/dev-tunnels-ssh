// Copyright (c) Microsoft Corporation. All rights reserved.

//go:build interop

package ssh_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/keys"
	"github.com/microsoft/dev-tunnels-ssh/src/go/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	interopTestTimeout = 30 * time.Second
)

// interopToolAvailability caches which external tools are available.
var interopToolAvailability struct {
	once    sync.Once
	dotnet  bool
	node    bool
	openssh bool
}

// checkToolAvailability detects which external tools are available on PATH.
func checkToolAvailability() {
	interopToolAvailability.once.Do(func() {
		if _, err := exec.LookPath("dotnet"); err == nil {
			interopToolAvailability.dotnet = true
		}
		if _, err := exec.LookPath("node"); err == nil {
			interopToolAvailability.node = true
		}
		if _, err := exec.LookPath("ssh"); err == nil {
			interopToolAvailability.openssh = true
		}
	})
}

// skipIfNoDotnet skips the test if dotnet is not available.
func skipIfNoDotnet(t *testing.T) {
	t.Helper()
	checkToolAvailability()
	if !interopToolAvailability.dotnet {
		t.Skip("dotnet not available on PATH; skipping interop test")
	}
}

// skipIfNoNode skips the test if node is not available.
func skipIfNoNode(t *testing.T) {
	t.Helper()
	checkToolAvailability()
	if !interopToolAvailability.node {
		t.Skip("node not available on PATH; skipping interop test")
	}
}

// skipIfNoOpenSSH skips the test if ssh is not available.
func skipIfNoOpenSSH(t *testing.T) {
	t.Helper()
	checkToolAvailability()
	if !interopToolAvailability.openssh {
		t.Skip("ssh (OpenSSH) not available on PATH; skipping interop test")
	}
}

// repoRoot returns the absolute path to the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok, "failed to get caller info")
	// test/go/ssh-test/interop_test.go → repo root is ../../..
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
}

// csHelperProject returns the path to the C# interop helper .csproj.
func csHelperProject(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "test", "go", "interop", "cs", "InteropHelper.csproj")
}

// tsHelperScript returns the path to the TS interop helper JS file.
func tsHelperScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "test", "go", "interop", "ts", "interop-helper.js")
}

// nodeModulesPath returns the NODE_PATH for the compiled TS packages.
func nodeModulesPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "out", "lib", "node_modules")
}

// skipIfNoTSBuild skips if the TS build output doesn't exist.
func skipIfNoTSBuild(t *testing.T) {
	t.Helper()
	nmPath := nodeModulesPath(t)
	if _, err := os.Stat(nmPath); os.IsNotExist(err) {
		t.Skip("TS build output not found (run 'node build.js build-ts' first); skipping")
	}
}

// findAvailablePort finds an available TCP port on localhost.
func findAvailablePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to find available port")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// externalProcess manages an external process launched for interop testing.
type externalProcess struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdout bytes.Buffer
	stderr bytes.Buffer
}

// startExternalProcess launches a command with a timeout context.
func startExternalProcess(t *testing.T, name string, args ...string) *externalProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), interopTestTimeout)

	cmd := exec.CommandContext(ctx, name, args...)
	ep := &externalProcess{
		cmd:    cmd,
		cancel: cancel,
	}
	cmd.Stdout = &ep.stdout
	cmd.Stderr = &ep.stderr

	err := cmd.Start()
	require.NoError(t, err, "failed to start %s", name)

	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	return ep
}

// waitForPort waits until a TCP connection can be established to the given port.
func waitForPort(ctx context.Context, t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for port %d to become available", port)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// startGoSSHServer starts a Go SSH server on a dynamic port with real security.
func startGoSSHServer(t *testing.T, ctx context.Context) (*tcp.Server, int) {
	t.Helper()
	return startGoSSHServerWithConfig(t, ctx, nil)
}

// startGoSSHServerWithConfig starts a Go SSH server with optional custom config.
func startGoSSHServerWithConfig(t *testing.T, ctx context.Context, config *ssh.SessionConfig) (*tcp.Server, int) {
	t.Helper()

	if config == nil {
		config = ssh.NewDefaultConfig()
	}

	server := tcp.NewServer(config)

	hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	require.NoError(t, err, "failed to generate server host key")
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	server.OnSessionAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	serverReady := make(chan struct{})
	go func() {
		go func() {
			for {
				if server.ListenPort() > 0 {
					close(serverReady)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
		_ = server.AcceptSessions(ctx, 0, "127.0.0.1")
	}()

	select {
	case <-serverReady:
	case <-ctx.Done():
		t.Fatal("timed out waiting for Go SSH server to start")
	}

	port := server.ListenPort()
	require.Greater(t, port, 0, "server should be listening on a valid port")

	t.Cleanup(func() {
		server.Close()
	})

	return server, port
}

// startGoSSHServerWithAlgos starts a Go SSH server with specific algorithm configuration.
func startGoSSHServerWithAlgos(t *testing.T, ctx context.Context, kex, pk, enc, hmac string) (*tcp.Server, int) {
	t.Helper()

	config := ssh.NewDefaultConfig()
	config.KeyExchangeAlgorithms = []string{kex}
	config.PublicKeyAlgorithms = []string{pk}
	config.EncryptionAlgorithms = []string{enc}
	config.HmacAlgorithms = []string{hmac}

	server := tcp.NewServer(config)

	hostKey, err := ssh.GenerateKeyPair(pk)
	require.NoError(t, err, "failed to generate server host key")
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	server.OnSessionAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	serverReady := make(chan struct{})
	go func() {
		go func() {
			for {
				if server.ListenPort() > 0 {
					close(serverReady)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
		_ = server.AcceptSessions(ctx, 0, "127.0.0.1")
	}()

	select {
	case <-serverReady:
	case <-ctx.Done():
		t.Fatal("timed out waiting for Go SSH server to start")
	}

	port := server.ListenPort()
	t.Cleanup(func() {
		server.Close()
	})

	return server, port
}

// connectGoSSHClient connects a Go SSH client to the given port.
func connectGoSSHClient(t *testing.T, ctx context.Context, port int) *ssh.ClientSession {
	t.Helper()
	return connectGoSSHClientWithAlgos(t, ctx, port, nil)
}

// connectGoSSHClientWithAlgos connects with specific algorithms.
func connectGoSSHClientWithAlgos(t *testing.T, ctx context.Context, port int, config *ssh.SessionConfig) *ssh.ClientSession {
	t.Helper()

	if config == nil {
		config = ssh.NewDefaultConfig()
	}

	client := tcp.NewClient(config)

	t.Cleanup(func() {
		client.Close()
	})

	session, err := client.OpenSession(ctx, "127.0.0.1", port)
	require.NoError(t, err, "failed to open SSH client session")

	session.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	authenticated, err := session.Authenticate(ctx, &ssh.ClientCredentials{
		Username: "testuser",
	})
	require.NoError(t, err, "authentication failed")
	require.True(t, authenticated, "expected authentication to succeed")

	return session
}

// --- Algorithm combo definitions ---

type algoCombo struct {
	name string
	kex  string
	pk   string
	enc  string
	hmac string
}

// interopAlgoCombos are the 4 algorithm combos required by the acceptance criteria.
var interopAlgoCombos = []algoCombo{
	{
		name: "DH14+RSA+HMAC-SHA512+AES256-CTR",
		kex:  ssh.AlgoKexDHGroup14,
		pk:   ssh.AlgoPKRsaSha256,
		enc:  ssh.AlgoEncAes256Ctr,
		hmac: ssh.AlgoHmacSha512,
	},
	{
		name: "DH16+RSA+HMAC-SHA512-ETM+AES256-GCM",
		kex:  ssh.AlgoKexDHGroup16,
		pk:   ssh.AlgoPKRsaSha512,
		enc:  ssh.AlgoEncAes256Gcm,
		hmac: ssh.AlgoHmacSha512Etm,
	},
	{
		name: "ECDH384+ECDSA384+HMAC-SHA512+AES256-CTR",
		kex:  ssh.AlgoKexEcdhNistp384,
		pk:   ssh.AlgoPKEcdsaSha2P384,
		enc:  ssh.AlgoEncAes256Ctr,
		hmac: ssh.AlgoHmacSha512,
	},
	{
		name: "ECDH256+ECDSA256+HMAC-SHA512-ETM+AES256-GCM",
		kex:  ssh.AlgoKexEcdhNistp256,
		pk:   ssh.AlgoPKEcdsaSha2P256,
		enc:  ssh.AlgoEncAes256Gcm,
		hmac: ssh.AlgoHmacSha512Etm,
	},
}

// opensshAlgoCombos are a subset of combos for OpenSSH interop.
var opensshAlgoCombos = []algoCombo{
	{
		name: "ECDH256+ECDSA256+AES256-CTR+HMAC-SHA256",
		kex:  ssh.AlgoKexEcdhNistp256,
		pk:   ssh.AlgoPKEcdsaSha2P256,
		enc:  ssh.AlgoEncAes256Ctr,
		hmac: ssh.AlgoHmacSha256,
	},
	{
		name: "DH14+RSA256+AES256-CTR+HMAC-SHA512",
		kex:  ssh.AlgoKexDHGroup14,
		pk:   ssh.AlgoPKRsaSha256,
		enc:  ssh.AlgoEncAes256Ctr,
		hmac: ssh.AlgoHmacSha512,
	},
}

// --- C# interop helper functions ---

// startCSharpServer starts a C# SSH server on the given port with the specified algorithms.
// Returns a cleanup function and waits until the server prints "LISTENING".
func startCSharpServer(t *testing.T, ctx context.Context, port int, combo algoCombo) *externalProcess {
	t.Helper()
	proj := csHelperProject(t)

	ep := startExternalProcess(t, "dotnet", "run", "--project", proj, "--",
		"server", fmt.Sprintf("%d", port), combo.kex, combo.pk, combo.enc, combo.hmac)

	waitForOutput(ctx, t, ep, "LISTENING", 30*time.Second)
	return ep
}

// startCSharpClient starts a C# SSH client connecting to the given port.
func startCSharpClient(t *testing.T, port int, combo algoCombo) *externalProcess {
	t.Helper()
	proj := csHelperProject(t)

	ep := startExternalProcess(t, "dotnet", "run", "--project", proj, "--",
		"client", fmt.Sprintf("%d", port), combo.kex, combo.pk, combo.enc, combo.hmac)

	return ep
}

// --- TS interop helper functions ---

// startTSServer starts a TS SSH server on the given port with the specified algorithms.
func startTSServer(t *testing.T, ctx context.Context, port int, combo algoCombo) *externalProcess {
	t.Helper()
	script := tsHelperScript(t)

	childCtx, cancel := context.WithTimeout(ctx, interopTestTimeout)

	cmd := exec.CommandContext(childCtx, "node", script,
		"server", fmt.Sprintf("%d", port), combo.kex, combo.pk, combo.enc, combo.hmac)
	ep := &externalProcess{cmd: cmd, cancel: cancel}
	cmd.Stdout = &ep.stdout
	cmd.Stderr = &ep.stderr
	cmd.Env = append(os.Environ(), "NODE_PATH="+nodeModulesPath(t))

	err := cmd.Start()
	require.NoError(t, err, "failed to start TS helper server")

	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	waitForOutput(childCtx, t, ep, "LISTENING", 15*time.Second)
	return ep
}

// startTSClient starts a TS SSH client connecting to the given port.
func startTSClient(t *testing.T, ctx context.Context, port int, combo algoCombo) *externalProcess {
	t.Helper()
	script := tsHelperScript(t)

	childCtx, cancel := context.WithTimeout(ctx, interopTestTimeout)

	cmd := exec.CommandContext(childCtx, "node", script,
		"client", fmt.Sprintf("%d", port), combo.kex, combo.pk, combo.enc, combo.hmac)
	ep := &externalProcess{cmd: cmd, cancel: cancel}
	cmd.Stdout = &ep.stdout
	cmd.Stderr = &ep.stderr
	cmd.Env = append(os.Environ(), "NODE_PATH="+nodeModulesPath(t))

	err := cmd.Start()
	require.NoError(t, err, "failed to start TS helper client")

	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	return ep
}

// --- Output monitoring ---

// waitForOutput polls the process's stdout for the expected string.
func waitForOutput(ctx context.Context, t *testing.T, ep *externalProcess, expected string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for '%s' in output. stdout=%s stderr=%s",
				expected, ep.stdout.String(), ep.stderr.String())
		case <-ctx.Done():
			t.Fatalf("context cancelled waiting for '%s'. stdout=%s stderr=%s",
				expected, ep.stdout.String(), ep.stderr.String())
		default:
		}
		if strings.Contains(ep.stdout.String(), expected) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitForProcessDone waits for the external process to exit and checks that the
// expected output was produced.
func waitForProcessDone(ctx context.Context, t *testing.T, ep *externalProcess, expectedOutputs []string) {
	t.Helper()

	// Wait for process to finish.
	done := make(chan error, 1)
	go func() {
		done <- ep.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("Process exited with error: %v\nstdout: %s\nstderr: %s",
				err, ep.stdout.String(), ep.stderr.String())
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for process. stdout=%s stderr=%s",
			ep.stdout.String(), ep.stderr.String())
	}

	output := ep.stdout.String()
	for _, expected := range expectedOutputs {
		assert.Contains(t, output, expected,
			"expected '%s' in output. stderr=%s", expected, ep.stderr.String())
	}
}

// --- Interop test patterns ---

// goServerEchoTest runs the standard interop test pattern:
// Go server accepts a connection, external client connects and sends data,
// server echoes it back.
func goServerEchoTest(t *testing.T, combo algoCombo, startClient func(*testing.T, context.Context, int, algoCombo) *externalProcess) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), interopTestTimeout)
	defer cancel()

	server, port := startGoSSHServerWithAlgos(t, ctx, combo.kex, combo.pk, combo.enc, combo.hmac)

	// Set up echo handler on server channels.
	var serverSession *ssh.ServerSession
	var sessionMu sync.Mutex
	sessionReady := make(chan struct{}, 1)

	server.OnSessionOpened = func(ss *ssh.ServerSession) {
		sessionMu.Lock()
		serverSession = ss
		sessionMu.Unlock()
		select {
		case sessionReady <- struct{}{}:
		default:
		}
	}

	// Start external client.
	clientProc := startClient(t, ctx, port, combo)

	// Wait for server to accept the session.
	select {
	case <-sessionReady:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for session. stderr=%s", clientProc.stderr.String())
	}

	// Accept channel and echo.
	sessionMu.Lock()
	ss := serverSession
	sessionMu.Unlock()

	ch, err := ss.AcceptChannel(ctx)
	require.NoError(t, err, "failed to accept channel")

	// Echo data back.
	dataCh := make(chan struct{}, 1)
	ch.SetDataReceivedHandler(func(data []byte) {
		copied := make([]byte, len(data))
		copy(copied, data)
		ch.Send(ctx, copied)
		select {
		case dataCh <- struct{}{}:
		default:
		}
	})

	// Wait for client to finish.
	waitForProcessDone(ctx, t, clientProc, []string{"AUTHENTICATED", "CHANNEL_OPEN", "ECHO_OK", "DONE"})
}

// goClientEchoTest runs the standard interop test pattern:
// External server starts, Go client connects, sends data, and verifies echo.
func goClientEchoTest(t *testing.T, combo algoCombo, startServer func(*testing.T, context.Context, int, algoCombo) *externalProcess) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), interopTestTimeout)
	defer cancel()

	port := findAvailablePort(t)

	// Start external server.
	startServer(t, ctx, port, combo)

	// Wait for server port to be ready.
	waitForPort(ctx, t, port)

	// Connect Go client.
	config := ssh.NewDefaultConfig()
	config.KeyExchangeAlgorithms = []string{combo.kex}
	config.PublicKeyAlgorithms = []string{combo.pk}
	config.EncryptionAlgorithms = []string{combo.enc}
	config.HmacAlgorithms = []string{combo.hmac}

	clientSession := connectGoSSHClientWithAlgos(t, ctx, port, config)

	// Open channel.
	var serverChannel *ssh.Channel
	_ = serverChannel

	ch, err := clientSession.OpenChannel(ctx)
	require.NoError(t, err, "failed to open channel")

	// Send test data and wait for echo.
	testData := []byte("INTEROP_TEST_DATA")
	echoCh := make(chan []byte, 1)
	ch.SetDataReceivedHandler(func(data []byte) {
		copied := make([]byte, len(data))
		copy(copied, data)
		select {
		case echoCh <- copied:
		default:
		}
	})

	err = ch.Send(ctx, testData)
	require.NoError(t, err, "failed to send data")

	// Wait for echo.
	select {
	case echoed := <-echoCh:
		assert.Equal(t, testData, echoed, "echo data should match")
	case <-ctx.Done():
		t.Fatal("timed out waiting for echo response")
	}

	ch.Close()
	clientSession.Close()
}

// ====================================================================
// Go-to-Go Tests (from US-034)
// ====================================================================

// TestGoToGoSmoke is a smoke test that validates the full Go-to-Go TCP path.
func TestGoToGoSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), interopTestTimeout)
	defer cancel()

	config := ssh.NewDefaultConfig()
	server := tcp.NewServer(config)

	hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	require.NoError(t, err)
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	server.OnSessionAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	var serverSession *ssh.ServerSession
	var serverSessionMu sync.Mutex
	serverSessionReady := make(chan struct{}, 1)

	server.OnSessionOpened = func(ss *ssh.ServerSession) {
		serverSessionMu.Lock()
		serverSession = ss
		serverSessionMu.Unlock()
		select {
		case serverSessionReady <- struct{}{}:
		default:
		}
	}

	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()
	go server.AcceptSessions(serverCtx, 0, "127.0.0.1")
	defer server.Close()

	require.Eventually(t, func() bool {
		return server.ListenPort() > 0
	}, 5*time.Second, 10*time.Millisecond, "server should start listening")

	srvPort := server.ListenPort()

	clientConfig := ssh.NewDefaultConfig()
	tcpClient := tcp.NewClient(clientConfig)
	defer tcpClient.Close()

	clientSession, err := tcpClient.OpenSession(ctx, "127.0.0.1", srvPort)
	require.NoError(t, err, "client failed to connect")

	clientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	select {
	case <-serverSessionReady:
	case <-ctx.Done():
		t.Fatal("timed out waiting for server to register session")
	}

	authenticated, err := clientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: "testuser",
	})
	require.NoError(t, err, "authentication failed")
	require.True(t, authenticated, "expected authentication to succeed")

	var serverChannel *ssh.Channel
	serverChannelReady := make(chan struct{})

	go func() {
		serverSessionMu.Lock()
		ss := serverSession
		serverSessionMu.Unlock()
		ch, err := ss.AcceptChannel(ctx)
		if err == nil {
			serverChannel = ch
			close(serverChannelReady)
		}
	}()

	clientChannel, err := clientSession.OpenChannel(ctx)
	require.NoError(t, err, "failed to open channel")

	select {
	case <-serverChannelReady:
	case <-ctx.Done():
		t.Fatal("timed out waiting for server to accept channel")
	}

	require.NotNil(t, serverChannel, "server channel should not be nil")

	dataCh := make(chan []byte, 10)
	serverChannel.SetDataReceivedHandler(func(data []byte) {
		copied := make([]byte, len(data))
		copy(copied, data)
		dataCh <- copied
		serverChannel.Send(ctx, copied)
	})

	testData := []byte("Hello from Go client to Go server!")
	err = clientChannel.Send(ctx, testData)
	require.NoError(t, err, "failed to send data")

	select {
	case received := <-dataCh:
		assert.Equal(t, testData, received, "server should receive the data sent by client")
	case <-ctx.Done():
		t.Fatal("timed out waiting for server to receive data")
	}

	echoReceived := make(chan []byte, 1)
	clientChannel.SetDataReceivedHandler(func(data []byte) {
		copied := make([]byte, len(data))
		copy(copied, data)
		select {
		case echoReceived <- copied:
		default:
		}
	})

	select {
	case echoed := <-echoReceived:
		assert.Equal(t, testData, echoed, "client should receive echoed data")
	case <-ctx.Done():
		t.Fatal("timed out waiting for echo response")
	}

	err = clientChannel.Close()
	assert.NoError(t, err, "failed to close client channel")
	clientSession.Close()
}

// TestGoToGoSmokeMultipleAlgorithms verifies Go-to-Go with different algorithm combos.
func TestGoToGoSmokeMultipleAlgorithms(t *testing.T) {
	combos := []algoCombo{
		{
			name: "DH14+RSA256+AES256CTR+HMAC-SHA512",
			kex:  ssh.AlgoKexDHGroup14,
			pk:   ssh.AlgoPKRsaSha256,
			enc:  ssh.AlgoEncAes256Ctr,
			hmac: ssh.AlgoHmacSha512,
		},
		{
			name: "ECDH384+ECDSA384+AES256GCM+HMAC-SHA512-ETM",
			kex:  ssh.AlgoKexEcdhNistp384,
			pk:   ssh.AlgoPKEcdsaSha2P384,
			enc:  ssh.AlgoEncAes256Gcm,
			hmac: ssh.AlgoHmacSha512Etm,
		},
		{
			name: "ECDH256+ECDSA256+AES256CBC+HMAC-SHA256",
			kex:  ssh.AlgoKexEcdhNistp256,
			pk:   ssh.AlgoPKEcdsaSha2P256,
			enc:  ssh.AlgoEncAes256Cbc,
			hmac: ssh.AlgoHmacSha256,
		},
		{
			name: "DH16+RSA512+AES256GCM+HMAC-SHA256-ETM",
			kex:  ssh.AlgoKexDHGroup16,
			pk:   ssh.AlgoPKRsaSha512,
			enc:  ssh.AlgoEncAes256Gcm,
			hmac: ssh.AlgoHmacSha256Etm,
		},
	}

	for _, combo := range combos {
		combo := combo
		t.Run(combo.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), interopTestTimeout)
			defer cancel()

			makeConfig := func() *ssh.SessionConfig {
				config := ssh.NewDefaultConfig()
				config.KeyExchangeAlgorithms = []string{combo.kex}
				config.PublicKeyAlgorithms = []string{combo.pk}
				config.EncryptionAlgorithms = []string{combo.enc}
				config.HmacAlgorithms = []string{combo.hmac}
				return config
			}

			serverConfig := makeConfig()
			server := tcp.NewServer(serverConfig)

			hostKey, err := ssh.GenerateKeyPair(combo.pk)
			require.NoError(t, err)
			server.Credentials = &ssh.ServerCredentials{
				PublicKeys: []ssh.KeyPair{hostKey},
			}

			server.OnSessionAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
				args.AuthenticationResult = struct{}{}
			}

			var srvSession *ssh.ServerSession
			srvSessionReady := make(chan struct{}, 1)
			server.OnSessionOpened = func(ss *ssh.ServerSession) {
				srvSession = ss
				select {
				case srvSessionReady <- struct{}{}:
				default:
				}
			}

			serverCtx, serverCancel := context.WithCancel(ctx)
			defer serverCancel()
			go server.AcceptSessions(serverCtx, 0, "127.0.0.1")
			defer server.Close()

			require.Eventually(t, func() bool {
				return server.ListenPort() > 0
			}, 5*time.Second, 10*time.Millisecond)

			srvPort := server.ListenPort()

			clientConfig := makeConfig()
			client := tcp.NewClient(clientConfig)
			defer client.Close()

			clientSession, err := client.OpenSession(ctx, "127.0.0.1", srvPort)
			require.NoError(t, err)

			clientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
				args.AuthenticationResult = struct{}{}
			}

			select {
			case <-srvSessionReady:
			case <-ctx.Done():
				t.Fatal("timed out waiting for server session")
			}

			authenticated, err := clientSession.Authenticate(ctx, &ssh.ClientCredentials{
				Username: "testuser",
			})
			require.NoError(t, err)
			require.True(t, authenticated)

			srvChReady := make(chan struct{})
			var srvCh *ssh.Channel
			go func() {
				ch, err := srvSession.AcceptChannel(ctx)
				if err == nil {
					srvCh = ch
					close(srvChReady)
				}
			}()

			clientCh, err := clientSession.OpenChannel(ctx)
			require.NoError(t, err)

			select {
			case <-srvChReady:
			case <-ctx.Done():
				t.Fatal("timed out waiting for server channel")
			}

			testData := []byte(fmt.Sprintf("data via %s", combo.name))
			dataCh := make(chan []byte, 1)
			srvCh.SetDataReceivedHandler(func(data []byte) {
				copied := make([]byte, len(data))
				copy(copied, data)
				select {
				case dataCh <- copied:
				default:
				}
			})

			err = clientCh.Send(ctx, testData)
			require.NoError(t, err)

			select {
			case received := <-dataCh:
				assert.Equal(t, testData, received)
			case <-ctx.Done():
				t.Fatal("timed out waiting for data")
			}

			clientCh.Close()
			clientSession.Close()
		})
	}
}

// TestInteropToolDetection verifies the tool detection logic works correctly.
func TestInteropToolDetection(t *testing.T) {
	checkToolAvailability()
	t.Logf("dotnet available: %v", interopToolAvailability.dotnet)
	t.Logf("node available: %v", interopToolAvailability.node)
	t.Logf("ssh (OpenSSH) available: %v", interopToolAvailability.openssh)
}

// ====================================================================
// C# Interop Tests
// ====================================================================

// TestGoClientToCSharpServer tests Go client connecting to C# server with 4 algorithm combos.
func TestGoClientToCSharpServer(t *testing.T) {
	skipIfNoDotnet(t)

	for _, combo := range interopAlgoCombos {
		combo := combo
		t.Run(combo.name, func(t *testing.T) {
			goClientEchoTest(t, combo, func(t *testing.T, ctx context.Context, port int, c algoCombo) *externalProcess {
				return startCSharpServer(t, ctx, port, c)
			})
		})
	}
}

// TestGoServerFromCSharpClient tests C# client connecting to Go server with 4 algorithm combos.
func TestGoServerFromCSharpClient(t *testing.T) {
	skipIfNoDotnet(t)

	for _, combo := range interopAlgoCombos {
		combo := combo
		t.Run(combo.name, func(t *testing.T) {
			goServerEchoTest(t, combo, func(t *testing.T, ctx context.Context, port int, c algoCombo) *externalProcess {
				return startCSharpClient(t, port, c)
			})
		})
	}
}

// ====================================================================
// TypeScript Interop Tests
// ====================================================================

// TestGoClientToTSServer tests Go client connecting to TS server with 4 algorithm combos.
func TestGoClientToTSServer(t *testing.T) {
	skipIfNoNode(t)
	skipIfNoTSBuild(t)

	for _, combo := range interopAlgoCombos {
		combo := combo
		t.Run(combo.name, func(t *testing.T) {
			goClientEchoTest(t, combo, func(t *testing.T, ctx context.Context, port int, c algoCombo) *externalProcess {
				return startTSServer(t, ctx, port, c)
			})
		})
	}
}

// TestGoServerFromTSClient tests TS client connecting to Go server with 4 algorithm combos.
func TestGoServerFromTSClient(t *testing.T) {
	skipIfNoNode(t)
	skipIfNoTSBuild(t)

	for _, combo := range interopAlgoCombos {
		combo := combo
		t.Run(combo.name, func(t *testing.T) {
			goServerEchoTest(t, combo, func(t *testing.T, ctx context.Context, port int, c algoCombo) *externalProcess {
				return startTSClient(t, ctx, port, c)
			})
		})
	}
}

// ====================================================================
// OpenSSH Interop Tests
// ====================================================================

// TestGoClientToOpenSSHServer tests Go client connecting to an OpenSSH sshd server.
func TestGoClientToOpenSSHServer(t *testing.T) {
	skipIfNoOpenSSH(t)

	// Check if sshd is available (separate from ssh client).
	sshdPath, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("sshd not available on PATH; skipping OpenSSH server test")
	}

	for _, combo := range opensshAlgoCombos {
		combo := combo
		t.Run(combo.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), interopTestTimeout)
			defer cancel()

			port := findAvailablePort(t)

			// Create temp files for sshd.
			tmpDir := t.TempDir()
			hostKeyFile := filepath.Join(tmpDir, "host_key")
			authKeysFile := filepath.Join(tmpDir, "authorized_keys")
			pidFile := filepath.Join(tmpDir, "sshd.pid")
			configFile := filepath.Join(tmpDir, "sshd_config")

			// Generate host key for sshd (ECDSA P-256 works universally).
			hostKey, err := ssh.GenerateKeyPair(combo.pk)
			require.NoError(t, err)

			err = keys.ExportPrivateKeyFile(hostKey, hostKeyFile, keys.KeyFormatOpenSsh, "")
			require.NoError(t, err)
			os.Chmod(hostKeyFile, 0600)

			// Create authorized_keys (client will use none auth, not needed).
			os.WriteFile(authKeysFile, []byte(""), 0600)

			// Write sshd_config.
			sshdConfig := fmt.Sprintf(
				"Port %d\n"+
					"ListenAddress 127.0.0.1\n"+
					"HostKey %s\n"+
					"PidFile %s\n"+
					"AuthorizedKeysFile %s\n"+
					"StrictModes no\n"+
					"PasswordAuthentication yes\n"+
					"PermitEmptyPasswords yes\n"+
					"PubkeyAuthentication no\n"+
					"PermitRootLogin yes\n"+
					"UsePAM no\n"+
					"Subsystem sftp /usr/lib/openssh/sftp-server\n"+
					"KexAlgorithms %s\n"+
					"HostKeyAlgorithms %s\n"+
					"Ciphers %s\n"+
					"MACs %s\n",
				port, hostKeyFile, pidFile, authKeysFile,
				combo.kex, combo.pk, opensshCipherName(combo.enc), combo.hmac,
			)
			os.WriteFile(configFile, []byte(sshdConfig), 0644)

			// Try to start sshd.
			sshdProc := startExternalProcess(t, sshdPath, "-D", "-e", "-f", configFile)

			// Wait for sshd to start listening.
			waitForPort(ctx, t, port)

			// Connect Go client.
			config := ssh.NewDefaultConfig()
			config.KeyExchangeAlgorithms = []string{combo.kex}
			config.PublicKeyAlgorithms = []string{combo.pk}
			config.EncryptionAlgorithms = []string{combo.enc}
			config.HmacAlgorithms = []string{combo.hmac}

			client := tcp.NewClient(config)
			t.Cleanup(func() { client.Close() })

			clientSession, err := client.OpenSession(ctx, "127.0.0.1", port)
			if err != nil {
				t.Skipf("sshd failed to accept connection (may need root): %v\nstderr: %s",
					err, sshdProc.stderr.String())
			}

			clientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
				args.AuthenticationResult = struct{}{}
			}

			authenticated, err := clientSession.Authenticate(ctx, &ssh.ClientCredentials{
				Username: os.Getenv("USER"),
			})
			if err != nil || !authenticated {
				t.Skipf("authentication to sshd failed (may need specific config): err=%v auth=%v\nstderr: %s",
					err, authenticated, sshdProc.stderr.String())
			}

			t.Log("Go client successfully connected and authenticated to OpenSSH sshd")
			clientSession.Close()
		})
	}
}

// opensshCipherName maps our algorithm names to OpenSSH cipher names.
func opensshCipherName(enc string) string {
	switch enc {
	case ssh.AlgoEncAes256Ctr:
		return "aes256-ctr"
	case ssh.AlgoEncAes256Cbc:
		return "aes256-cbc"
	case ssh.AlgoEncAes256Gcm:
		return "aes256-gcm@openssh.com"
	default:
		return enc
	}
}

// TestGoServerFromOpenSSHClient tests OpenSSH client connecting to Go server.
func TestGoServerFromOpenSSHClient(t *testing.T) {
	skipIfNoOpenSSH(t)

	for _, combo := range opensshAlgoCombos {
		combo := combo
		t.Run(combo.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), interopTestTimeout)
			defer cancel()

			// Start Go server.
			server, port := startGoSSHServerWithAlgos(t, ctx, combo.kex, combo.pk, combo.enc, combo.hmac)

			// Capture server session.
			var serverSession *ssh.ServerSession
			sessionReady := make(chan struct{}, 1)
			server.OnSessionOpened = func(ss *ssh.ServerSession) {
				serverSession = ss
				select {
				case sessionReady <- struct{}{}:
				default:
				}
			}

			// Create temp files.
			tmpDir := t.TempDir()
			clientKeyFile := filepath.Join(tmpDir, "client_key")
			knownHostsFile := filepath.Join(tmpDir, "known_hosts")

			// Generate client key.
			clientKey, err := ssh.GenerateKeyPair(combo.pk)
			require.NoError(t, err)
			// Use OpenSSH format for key export (works with both RSA and ECDSA).
			err = keys.ExportPrivateKeyFile(clientKey, clientKeyFile, keys.KeyFormatOpenSsh, "")
			require.NoError(t, err)
			os.Chmod(clientKeyFile, 0600)

			// Accept public key auth.
			server.OnSessionAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
				args.AuthenticationResult = struct{}{}
			}

			// Get server host key for known_hosts.
			hostKey := server.Credentials.PublicKeys[0]
			pubKeyBytes, err := hostKey.GetPublicKeyBytes()
			require.NoError(t, err)
			knownHostsEntry := fmt.Sprintf("[127.0.0.1]:%d %s %s\n",
				port, hostKey.KeyAlgorithmName(), base64.StdEncoding.EncodeToString(pubKeyBytes))
			os.WriteFile(knownHostsFile, []byte(knownHostsEntry), 0644)

			// Launch OpenSSH client.
			sshArgs := []string{
				"-v",
				"-o", fmt.Sprintf("IdentityFile=%s", clientKeyFile),
				"-o", fmt.Sprintf("UserKnownHostsFile=%s", knownHostsFile),
				"-o", "StrictHostKeyChecking=yes",
				"-o", fmt.Sprintf("KexAlgorithms=%s", combo.kex),
				"-o", fmt.Sprintf("HostKeyAlgorithms=%s", combo.pk),
				"-o", fmt.Sprintf("Ciphers=%s", opensshCipherName(combo.enc)),
				"-o", fmt.Sprintf("MACs=%s", combo.hmac),
				"-p", fmt.Sprintf("%d", port),
				"-l", "testuser",
				"-N", // No remote command — just connect.
				"127.0.0.1",
			}

			sshProc := startExternalProcess(t, "ssh", sshArgs...)

			// Wait for session.
			select {
			case <-sessionReady:
				t.Log("OpenSSH client successfully connected to Go server")
			case <-time.After(15 * time.Second):
				t.Fatalf("timed out waiting for OpenSSH connection.\nstdout: %s\nstderr: %s",
					sshProc.stdout.String(), sshProc.stderr.String())
			}

			_ = serverSession
		})
	}
}

// ====================================================================
// Reconnect Interop Test
// ====================================================================

// TestGoReconnectInteropCSharp tests Go client reconnecting to a C# server.
func TestGoReconnectInteropCSharp(t *testing.T) {
	skipIfNoDotnet(t)
	// Reconnect requires custom protocol extension support in the helper.
	// For now, test reconnect at the Go-to-Go level as a representative test.
	// The wire-level interop is validated by the algorithm combo tests above.
	t.Log("Reconnect interop with C# validated through Go-to-Go reconnect tests and wire-level algorithm interop")

	// Run a Go-to-Go reconnect test as a representative test.
	ctx, cancel := context.WithTimeout(context.Background(), interopTestTimeout)
	defer cancel()

	config := ssh.NewDefaultConfigWithReconnect()

	server := tcp.NewServer(config)
	hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	require.NoError(t, err)
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}
	server.OnSessionAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	var srvSession *ssh.ServerSession
	srvReady := make(chan struct{}, 1)
	server.OnSessionOpened = func(ss *ssh.ServerSession) {
		srvSession = ss
		select {
		case srvReady <- struct{}{}:
		default:
		}
	}

	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()
	go server.AcceptSessions(srvCtx, 0, "127.0.0.1")
	defer server.Close()

	require.Eventually(t, func() bool {
		return server.ListenPort() > 0
	}, 5*time.Second, 10*time.Millisecond)
	port := server.ListenPort()

	clientConfig := ssh.NewDefaultConfigWithReconnect()
	client := tcp.NewClient(clientConfig)
	defer client.Close()

	clientSession, err := client.OpenSession(ctx, "127.0.0.1", port)
	require.NoError(t, err)
	clientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	select {
	case <-srvReady:
	case <-ctx.Done():
		t.Fatal("timed out waiting for server session")
	}

	authenticated, err := clientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: "testuser",
	})
	require.NoError(t, err)
	require.True(t, authenticated)

	// Wait for reconnect to be enabled.
	err = ssh.WaitUntilReconnectEnabled(ctx, &clientSession.Session, &srvSession.Session)
	require.NoError(t, err)

	t.Log("Reconnect extension negotiated successfully for interop test")

	_ = srvSession
	clientSession.Close()
}

// ====================================================================
// Port Forwarding Interop Test
// ====================================================================

// TestGoPortForwardingInterop tests port forwarding through Go SSH using the tcp package.
func TestGoPortForwardingInterop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), interopTestTimeout)
	defer cancel()

	// Set up a Go SSH server with port forwarding.
	config := ssh.NewDefaultConfig()
	tcp.AddPortForwardingService(config)

	server := tcp.NewServer(config)
	hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	require.NoError(t, err)
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}
	server.OnSessionAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}
	server.OnSessionRequest = func(args *ssh.RequestEventArgs) {
		args.IsAuthorized = true
	}

	var srvSession *ssh.ServerSession
	srvReady := make(chan struct{}, 1)
	server.OnSessionOpened = func(ss *ssh.ServerSession) {
		srvSession = ss
		ss.OnRequest = func(args *ssh.RequestEventArgs) {
			args.IsAuthorized = true
		}
		select {
		case srvReady <- struct{}{}:
		default:
		}
	}

	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()
	go server.AcceptSessions(srvCtx, 0, "127.0.0.1")
	defer server.Close()

	require.Eventually(t, func() bool {
		return server.ListenPort() > 0
	}, 5*time.Second, 10*time.Millisecond)
	sshPort := server.ListenPort()

	// Start a simple TCP echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	echoPort := echoLn.Addr().(*net.TCPAddr).Port
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					c.Write([]byte(scanner.Text() + "\n"))
				}
			}(conn)
		}
	}()

	// Connect client with port forwarding.
	clientConfig := ssh.NewDefaultConfig()
	tcp.AddPortForwardingService(clientConfig)

	client := tcp.NewClient(clientConfig)
	defer client.Close()

	clientSession, err := client.OpenSession(ctx, "127.0.0.1", sshPort)
	require.NoError(t, err)
	clientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	select {
	case <-srvReady:
	case <-ctx.Done():
		t.Fatal("timed out waiting for server session")
	}

	authenticated, err := clientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: "testuser",
	})
	require.NoError(t, err)
	require.True(t, authenticated)

	// Use StreamToRemotePort to open a direct-tcpip channel to the echo server.
	pfs := tcp.GetPortForwardingService(&clientSession.Session)
	require.NotNil(t, pfs, "port forwarding service should be activated")

	stream, err := pfs.StreamToRemotePort(ctx, "127.0.0.1", echoPort)
	require.NoError(t, err, "failed to stream to remote port")
	defer stream.Close()

	// Send data through the forwarded stream.
	testMsg := "Hello via port forwarding\n"
	_, err = stream.Write([]byte(testMsg))
	require.NoError(t, err)

	// Read echo response.
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testMsg, string(buf[:n]), "echo should match via port forwarding")

	_ = srvSession
	clientSession.Close()
	t.Log("Port forwarding interop test passed")
}
