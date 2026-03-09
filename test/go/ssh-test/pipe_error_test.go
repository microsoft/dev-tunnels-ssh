// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh_test

import (
	"context"
	"sync"
	"testing"
	"time"

	ssh "github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test/helpers"
)

// TestPipeSendErrorClosesPipe verifies that a send failure during pipe relay
// closes the pipe (HIGH-04: errors must not be silently swallowed).
func TestPipeSendErrorClosesPipe(t *testing.T) {
	client1, server1 := helpers.CreateConnectedSessionPair(t, nil)
	client2, server2 := helpers.CreateConnectedSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open channels on both session pairs.
	var serverCh1, serverCh2 *ssh.Channel
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		serverCh1, _ = server1.AcceptChannel(ctx)
	}()
	go func() {
		defer wg.Done()
		serverCh2, _ = server2.AcceptChannel(ctx)
	}()

	clientCh1, err := client1.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 1 failed: %v", err)
	}
	_, err = client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 2 failed: %v", err)
	}
	wg.Wait()

	// Pipe the two server-side channels together.
	pipeDone := make(chan error, 1)
	go func() {
		pipeDone <- serverCh1.Pipe(ctx, serverCh2)
	}()

	// Close server2's session to make sends to serverCh2 fail.
	server2.Close()

	// Send data from client1 → serverCh1 → pipe → serverCh2 (which should fail).
	data := []byte("test data for pipe error")
	_ = clientCh1.Send(ctx, data)

	// The pipe should terminate (not hang forever) because the send error
	// closes it instead of silently swallowing the error.
	select {
	case <-pipeDone:
		// Pipe terminated as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not terminate after send error")
	}
}
