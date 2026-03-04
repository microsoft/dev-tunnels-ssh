// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestExtendedDataReceived verifies that sending extended data with
// ExtendedDataStderr fires OnExtendedDataReceived with the correct type code and data.
func TestExtendedDataReceived(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	if serverCh == nil {
		t.Fatal("server channel is nil")
	}

	// Set up extended data handler on server channel.
	receivedCh := make(chan struct{}, 1)
	var receivedType SSHExtendedDataType
	var receivedData []byte
	serverCh.SetExtendedDataReceivedHandler(func(dataType SSHExtendedDataType, data []byte) {
		receivedType = dataType
		receivedData = make([]byte, len(data))
		copy(receivedData, data)
		serverCh.AdjustWindow(uint32(len(data)))
		select {
		case receivedCh <- struct{}{}:
		default:
		}
	})

	// Send extended data from client to server.
	testData := []byte("stderr output here")
	if err := clientCh.SendExtendedData(ctx, ExtendedDataStderr, testData); err != nil {
		t.Fatalf("SendExtendedData failed: %v", err)
	}

	select {
	case <-receivedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for extended data")
	}

	if receivedType != ExtendedDataStderr {
		t.Errorf("received type = %d, want %d (ExtendedDataStderr)", receivedType, ExtendedDataStderr)
	}
	if !bytes.Equal(receivedData, testData) {
		t.Errorf("received data = %q, want %q", receivedData, testData)
	}
}

// TestExtendedDataFallbackToRegularHandler verifies that when
// OnExtendedDataReceived is nil, extended data falls through to OnDataReceived.
func TestExtendedDataFallbackToRegularHandler(t *testing.T) {
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var serverCh *Channel
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverCh, _ = server.AcceptChannel(ctx)
	}()

	clientCh, err := client.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel failed: %v", err)
	}
	wg.Wait()

	if serverCh == nil {
		t.Fatal("server channel is nil")
	}

	// Only set the regular data handler — do NOT set OnExtendedDataReceived.
	receivedCh := make(chan struct{}, 1)
	var receivedData []byte
	serverCh.SetDataReceivedHandler(func(data []byte) {
		receivedData = make([]byte, len(data))
		copy(receivedData, data)
		serverCh.AdjustWindow(uint32(len(data)))
		select {
		case receivedCh <- struct{}{}:
		default:
		}
	})

	// Send extended data from client.
	testData := []byte("falls through to regular handler")
	if err := clientCh.SendExtendedData(ctx, ExtendedDataStderr, testData); err != nil {
		t.Fatalf("SendExtendedData failed: %v", err)
	}

	select {
	case <-receivedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for data in regular handler")
	}

	if !bytes.Equal(receivedData, testData) {
		t.Errorf("received data = %q, want %q", receivedData, testData)
	}
}

// TestPipeExtendedDataPreservesTypeCode verifies that piping two channels
// forwards extended data with the type code preserved.
func TestPipeExtendedDataPreservesTypeCode(t *testing.T) {
	client1, server1 := createSessionPair(t, nil)
	client2, server2 := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open channels on both session pairs.
	var serverCh1, serverCh2 *Channel
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
	clientCh2, err := client2.OpenChannel(ctx)
	if err != nil {
		t.Fatalf("OpenChannel 2 failed: %v", err)
	}
	wg.Wait()

	if serverCh1 == nil || serverCh2 == nil {
		t.Fatal("one of the server channels is nil")
	}

	// Pipe the two server-side channels together.
	pipeDone := make(chan error, 1)
	go func() {
		pipeDone <- serverCh1.Pipe(ctx, serverCh2)
	}()

	// Give the pipe goroutine time to install handlers.
	runtime.Gosched()
	time.Sleep(50 * time.Millisecond)

	// Set up extended data handler on client2 to receive forwarded data.
	receivedCh := make(chan struct{}, 1)
	var receivedType SSHExtendedDataType
	var receivedData []byte
	clientCh2.SetExtendedDataReceivedHandler(func(dataType SSHExtendedDataType, data []byte) {
		receivedType = dataType
		receivedData = make([]byte, len(data))
		copy(receivedData, data)
		clientCh2.AdjustWindow(uint32(len(data)))
		select {
		case receivedCh <- struct{}{}:
		default:
		}
	})

	// Send extended data from client1 → serverCh1 → pipe → serverCh2 → client2.
	testData := []byte("piped stderr data")
	if err := clientCh1.SendExtendedData(ctx, ExtendedDataStderr, testData); err != nil {
		t.Fatalf("SendExtendedData failed: %v", err)
	}

	select {
	case <-receivedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for piped extended data")
	}

	if receivedType != ExtendedDataStderr {
		t.Errorf("received type = %d, want %d (ExtendedDataStderr)", receivedType, ExtendedDataStderr)
	}
	if !bytes.Equal(receivedData, testData) {
		t.Errorf("received data = %q, want %q", receivedData, testData)
	}
}
