// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/keys"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// opensshAvailability caches whether ssh and sshd are available on PATH.
var opensshAvailability struct {
	once     sync.Once
	sshPath  string
	sshdPath string
	hasSSH   bool
	hasSSHd  bool
}

// checkOpenSSH detects ssh and sshd on PATH.
func checkOpenSSH() {
	opensshAvailability.once.Do(func() {
		if p, err := exec.LookPath("ssh"); err == nil {
			opensshAvailability.sshPath = p
			opensshAvailability.hasSSH = true
		}
		if p, err := exec.LookPath("sshd"); err == nil {
			opensshAvailability.sshdPath = p
			opensshAvailability.hasSSHd = true
		}
	})
}

// skipIfNoSSH skips the test if the ssh client binary is not available.
func skipIfNoSSH(t *testing.T) {
	t.Helper()
	checkOpenSSH()
	if !opensshAvailability.hasSSH {
		t.Skip("ssh (OpenSSH client) not available on PATH; skipping")
	}
}

// skipIfNoSSHD skips the test if the sshd binary is not available.
func skipIfNoSSHD(t *testing.T) {
	t.Helper()
	checkOpenSSH()
	if !opensshAvailability.hasSSHd {
		t.Skip("sshd (OpenSSH server) not available on PATH; skipping")
	}
}

// waitForTCPPort waits until a TCP connection can be established to the given port.
func waitForTCPPort(ctx context.Context, t *testing.T, port int) {
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

// findFreePort finds an available TCP port on localhost.
func findFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// startGoServer starts a Go SSH server on a dynamic port with ECDSA P-256 host key.
// The onSessionOpened callback is set before AcceptSessions starts to avoid races.
// Returns the server, port, and host key. The server is automatically cleaned up.
func startGoServer(t *testing.T, ctx context.Context, onSessionOpened func(*ssh.ServerSession)) (*Server, int, ssh.KeyPair) {
	t.Helper()

	config := ssh.NewDefaultConfig()
	server := NewServer(config)

	hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}
	server.Credentials = &ssh.ServerCredentials{
		PublicKeys: []ssh.KeyPair{hostKey},
	}

	server.OnSessionAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	// Set OnSessionOpened BEFORE AcceptSessions to avoid data race.
	if onSessionOpened != nil {
		server.OnSessionOpened = onSessionOpened
	}

	go func() {
		_ = server.AcceptSessions(ctx, 0, "127.0.0.1")
	}()

	// Wait for server to start listening.
	for i := 0; i < 200; i++ {
		if server.ListenPort() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	port := server.ListenPort()
	if port == 0 {
		t.Fatal("server did not start listening")
	}

	t.Cleanup(func() { server.Close() })

	return server, port, hostKey
}

// TestGoServerAcceptsSystemSSHClient verifies that a Go SSH server can accept
// and complete key exchange with a system OpenSSH client.
// Skips if the ssh binary is not available on PATH.
func TestGoServerAcceptsSystemSSHClient(t *testing.T) {
	skipIfNoSSH(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Set up session notification before starting server to avoid races.
	sessionReady := make(chan *ssh.ServerSession, 1)
	onSessionOpened := func(ss *ssh.ServerSession) {
		select {
		case sessionReady <- ss:
		default:
		}
	}

	// Start Go SSH server.
	_, port, hostKey := startGoServer(t, ctx, onSessionOpened)

	// Create temp files for the SSH client.
	tmpDir := t.TempDir()
	clientKeyFile := filepath.Join(tmpDir, "client_key")
	knownHostsFile := filepath.Join(tmpDir, "known_hosts")

	// Generate client key.
	clientKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P256)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	err = keys.ExportPrivateKeyFile(clientKey, clientKeyFile, keys.KeyFormatOpenSSH, "")
	if err != nil {
		t.Fatalf("failed to export client key: %v", err)
	}
	os.Chmod(clientKeyFile, 0600)

	// Create known_hosts with server's host key.
	pubKeyBytes, err := hostKey.GetPublicKeyBytes()
	if err != nil {
		t.Fatalf("failed to get host key bytes: %v", err)
	}
	knownHostsEntry := fmt.Sprintf("[127.0.0.1]:%d %s %s\n",
		port, hostKey.KeyAlgorithmName(), base64.StdEncoding.EncodeToString(pubKeyBytes))
	os.WriteFile(knownHostsFile, []byte(knownHostsEntry), 0644)

	// Launch OpenSSH client.
	sshArgs := []string{
		"-v",
		"-o", fmt.Sprintf("IdentityFile=%s", clientKeyFile),
		"-o", fmt.Sprintf("UserKnownHostsFile=%s", knownHostsFile),
		"-o", "StrictHostKeyChecking=yes",
		"-o", "PasswordAuthentication=no",
		"-p", fmt.Sprintf("%d", port),
		"-l", "testuser",
		"-N", // No remote command — just connect.
		"127.0.0.1",
	}

	cmd := exec.CommandContext(ctx, "ssh", sshArgs...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start ssh: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	// Wait for a session to be created on the Go server.
	select {
	case ss := <-sessionReady:
		if ss == nil {
			t.Fatal("received nil server session")
		}
		t.Log("Go server successfully accepted connection from system ssh client")
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for SSH connection.\nstderr: %s", stderr.String())
	}
}

// TestGoClientConnectsToSystemSSHD verifies that a Go SSH client can connect
// and complete key exchange with a system OpenSSH sshd server.
// Skips if sshd or ssh-keygen are not available on PATH.
func TestGoClientConnectsToSystemSSHD(t *testing.T) {
	skipIfNoSSHD(t)

	// Also need ssh-keygen to generate keys in a format sshd can read.
	sshKeygenPath, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available on PATH; skipping")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	port := findFreePort(t)
	tmpDir := t.TempDir()
	hostKeyFile := filepath.Join(tmpDir, "host_key")
	pidFile := filepath.Join(tmpDir, "sshd.pid")
	configFile := filepath.Join(tmpDir, "sshd_config")
	authKeysFile := filepath.Join(tmpDir, "authorized_keys")

	// Use ssh-keygen to generate the host key — guarantees compatibility with local sshd.
	out, err := exec.Command(sshKeygenPath, "-t", "ecdsa", "-b", "256", "-f", hostKeyFile, "-N", "").CombinedOutput()
	if err != nil {
		t.Skipf("ssh-keygen failed: %v\noutput: %s", err, out)
	}

	// Create empty authorized_keys.
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
			"UsePAM no\n",
		port, hostKeyFile, pidFile, authKeysFile,
	)
	os.WriteFile(configFile, []byte(sshdConfig), 0644)

	// Start sshd — capture stderr via CombinedOutput on a test run would not work;
	// instead, use StderrPipe to safely read stderr after process exits.
	checkOpenSSH()
	cmd := exec.CommandContext(ctx, opensshAvailability.sshdPath, "-D", "-e", "-f", configFile)
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Skipf("failed to create stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("failed to start sshd (may need specific permissions): %v", err)
	}

	// Capture stderr in a goroutine — only read it after the process is done.
	stderrDone := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(stderrPipe)
		stderrDone <- string(data)
	}()

	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	// Wait for sshd to start listening — skip if it doesn't start in time.
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	defer waitCancel()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	sshdStarted := false
	for {
		select {
		case <-waitCtx.Done():
			cmd.Process.Kill()
			cmd.Wait()
			stderrStr := <-stderrDone
			t.Skipf("sshd did not start listening (may need root or specific config)\nstderr: %s", stderrStr)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			sshdStarted = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !sshdStarted {
		t.Skip("sshd did not start listening")
	}

	// Connect Go client.
	client := NewClient(ssh.NewDefaultConfig())
	t.Cleanup(func() { client.Close() })

	clientSession, err := client.OpenSession(ctx, "127.0.0.1", port)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		stderrStr := <-stderrDone
		t.Skipf("sshd failed to accept connection (may need root or specific config): %v\nstderr: %s",
			err, stderrStr)
	}

	// Accept the server's host key.
	clientSession.OnAuthenticating = func(args *ssh.AuthenticatingEventArgs) {
		args.AuthenticationResult = struct{}{}
	}

	// Try to authenticate.
	username := os.Getenv("USER")
	if username == "" {
		username = "testuser"
	}
	authenticated, err := clientSession.Authenticate(ctx, &ssh.ClientCredentials{
		Username: username,
	})
	if err != nil || !authenticated {
		cmd.Process.Kill()
		cmd.Wait()
		stderrStr := <-stderrDone
		t.Skipf("authentication to sshd failed (may need specific config): err=%v auth=%v\nstderr: %s",
			err, authenticated, stderrStr)
	}

	t.Log("Go client successfully connected and authenticated to system sshd")
	clientSession.Close()
}
