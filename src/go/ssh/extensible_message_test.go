// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"context"
	"fmt"
	"testing"
	"time"
)

const extensibleMessageTestTimeout = 10 * time.Second

// TestCustomMessageHandlerInvoked registers a handler for a custom message number
// (200), sends that message from the peer, and verifies the handler receives the
// correct payload.
func TestCustomMessageHandlerInvoked(t *testing.T) {
	const customMsgType byte = 200

	serverConfig := NewNoSecurityConfig()
	handlerCalled := make(chan []byte, 1)
	serverConfig.MessageHandlers = map[byte]MessageHandler{
		customMsgType: func(payload []byte) error {
			buf := make([]byte, len(payload))
			copy(buf, payload)
			handlerCalled <- buf
			return nil
		},
	}

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})
	_ = server

	// Send a raw message with type 200 and some payload data from client to server.
	rawMsg := []byte{customMsgType, 0xAA, 0xBB, 0xCC}
	if err := client.protocol.sendMessage(rawMsg); err != nil {
		t.Fatalf("failed to send custom message: %v", err)
	}

	// Verify handler was called with the correct payload.
	select {
	case received := <-handlerCalled:
		if len(received) != len(rawMsg) {
			t.Fatalf("payload length = %d, want %d", len(received), len(rawMsg))
		}
		for i, b := range rawMsg {
			if received[i] != b {
				t.Errorf("payload[%d] = 0x%02X, want 0x%02X", i, received[i], b)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for custom message handler to be called")
	}

	// Session should still be connected.
	if !client.IsConnected() {
		t.Error("client session disconnected after custom message")
	}
	if !server.IsConnected() {
		t.Error("server session disconnected after custom message")
	}
}

// TestUnknownMessageWithoutHandler sends a message with no registered handler
// and verifies the session handles it gracefully by sending UnimplementedMessage
// back (session remains functional).
func TestUnknownMessageWithoutHandler(t *testing.T) {
	const customMsgType byte = 200

	// No custom handlers on either side.
	client, server := createSessionPair(t, nil)

	ctx, cancel := context.WithTimeout(context.Background(), extensibleMessageTestTimeout)
	defer cancel()

	// Send a raw message with unregistered type 200 from client to server.
	rawMsg := []byte{customMsgType, 0x01, 0x02}
	if err := client.protocol.sendMessage(rawMsg); err != nil {
		t.Fatalf("failed to send unknown message: %v", err)
	}

	// Give the dispatch loop time to process the message and send back
	// UnimplementedMessage, and the client time to receive it.
	time.Sleep(200 * time.Millisecond)

	// Both sessions should still be connected (UnimplementedMessage is benign).
	if !client.IsConnected() {
		t.Error("client session disconnected after unknown message")
	}
	if !server.IsConnected() {
		t.Error("server session disconnected after unknown message")
	}

	// Verify the session is still fully functional by opening a channel
	// and sending data through it.
	clientCh, serverCh := openChannelPair(t, client, server)

	testData := []byte("still works")
	received := make(chan []byte, 1)
	serverCh.SetDataReceivedHandler(func(data []byte) {
		buf := make([]byte, len(data))
		copy(buf, data)
		serverCh.AdjustWindow(uint32(len(data)))
		received <- buf
	})

	if err := clientCh.Send(ctx, testData); err != nil {
		t.Fatalf("send data failed after unknown message: %v", err)
	}

	select {
	case data := <-received:
		if string(data) != string(testData) {
			t.Errorf("received %q, want %q", data, testData)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for data — session may not be functional after unknown message")
	}
}

// TestMultipleCustomMessageHandlers registers handlers for 2 different message
// numbers and verifies each receives only its own messages.
func TestMultipleCustomMessageHandlers(t *testing.T) {
	const msgType200 byte = 200
	const msgType201 byte = 201

	serverConfig := NewNoSecurityConfig()
	handler200Called := make(chan []byte, 1)
	handler201Called := make(chan []byte, 1)

	serverConfig.MessageHandlers = map[byte]MessageHandler{
		msgType200: func(payload []byte) error {
			buf := make([]byte, len(payload))
			copy(buf, payload)
			handler200Called <- buf
			return nil
		},
		msgType201: func(payload []byte) error {
			buf := make([]byte, len(payload))
			copy(buf, payload)
			handler201Called <- buf
			return nil
		},
	}

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})
	_ = server

	// Send message type 200.
	msg200 := []byte{msgType200, 0x11, 0x22}
	if err := client.protocol.sendMessage(msg200); err != nil {
		t.Fatalf("failed to send message type 200: %v", err)
	}

	// Send message type 201.
	msg201 := []byte{msgType201, 0x33, 0x44, 0x55}
	if err := client.protocol.sendMessage(msg201); err != nil {
		t.Fatalf("failed to send message type 201: %v", err)
	}

	// Verify handler 200 received its message.
	select {
	case received := <-handler200Called:
		if received[0] != msgType200 {
			t.Errorf("handler200 got type %d, want %d", received[0], msgType200)
		}
		if len(received) != len(msg200) {
			t.Errorf("handler200 payload length = %d, want %d", len(received), len(msg200))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for handler 200")
	}

	// Verify handler 201 received its message.
	select {
	case received := <-handler201Called:
		if received[0] != msgType201 {
			t.Errorf("handler201 got type %d, want %d", received[0], msgType201)
		}
		if len(received) != len(msg201) {
			t.Errorf("handler201 payload length = %d, want %d", len(received), len(msg201))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for handler 201")
	}

	// Verify no cross-contamination.
	select {
	case payload := <-handler200Called:
		t.Errorf("handler200 received extra message: %v", payload)
	case payload := <-handler201Called:
		t.Errorf("handler201 received extra message: %v", payload)
	case <-time.After(100 * time.Millisecond):
		// Expected: no extra messages.
	}
}

// TestCustomMessageHandlerError verifies that when a handler returns an error,
// the session handles it gracefully (closes with protocol error, no panic).
func TestCustomMessageHandlerError(t *testing.T) {
	const customMsgType byte = 200

	serverConfig := NewNoSecurityConfig()
	serverConfig.MessageHandlers = map[byte]MessageHandler{
		customMsgType: func(payload []byte) error {
			return fmt.Errorf("handler intentional error")
		},
	}

	client, server := createSessionPair(t, &SessionPairOptions{
		ServerConfig: serverConfig,
	})

	// Send a raw message with type 200 from client to server.
	rawMsg := []byte{customMsgType, 0x01}
	if err := client.protocol.sendMessage(rawMsg); err != nil {
		t.Fatalf("failed to send custom message: %v", err)
	}

	// The server's dispatch loop should close the session due to the handler error.
	// Wait for the server's done channel to be closed.
	select {
	case <-server.done:
		// Expected: server session closed.
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server session to close after handler error")
	}

	// Verify server session is no longer connected.
	if server.IsConnected() {
		t.Error("server session should be disconnected after handler error")
	}
}
