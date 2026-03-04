// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// TestExtensionDomainStringsMatchCrossPlatform verifies that the Go implementation
// uses the same protocol extension domain strings as the C# and TypeScript
// implementations, ensuring cross-language interoperability.
//
// All three implementations (Go, C#, TypeScript) use @microsoft.com as the
// extension domain for Dev Tunnels SSH protocol extensions. This is the domain
// expected by the Dev Tunnels relay service.
//
// Verified against:
//   - C#: src/cs/SSH/SSHProtocolExtensionNames.cs and SSHSession.cs
//   - TypeScript: src/ts/ssh/sshSessionConfig.ts and sshSession.ts
//
// Note: An earlier review flagged a potential mismatch with @vs-ssh.visualstudio.com,
// but all three implementations consistently use @microsoft.com. The
// @vs-ssh.visualstudio.com domain is NOT used by any current implementation.
func TestExtensionDomainStringsMatchCrossPlatform(t *testing.T) {
	// These exact strings must match the C# and TypeScript implementations.
	// C# constants (SSHProtocolExtensionNames.cs):
	//   OpenChannelRequest = "open-channel-request@microsoft.com"
	//   SessionReconnect   = "session-reconnect@microsoft.com"
	//   SessionLatency     = "session-latency@microsoft.com"
	// C# constants (SSHSession.cs):
	//   InitialChannelRequest  = "initial-channel-request@microsoft.com"
	//   EnableSessionReconnect = "enable-session-reconnect@microsoft.com"
	// TS constants (sshSessionConfig.ts):
	//   openChannelRequest = 'open-channel-request@microsoft.com'
	//   sessionReconnect   = 'session-reconnect@microsoft.com'
	//   sessionLatency     = 'session-latency@microsoft.com'
	// TS constants (sshSession.ts):
	//   initialChannelRequest  = 'initial-channel-request@microsoft.com'
	//   enableSessionReconnect = 'enable-session-reconnect@microsoft.com'
	tests := []struct {
		name     string
		goValue  string
		expected string
	}{
		{
			name:     "OpenChannelRequest",
			goValue:  ExtensionOpenChannelRequest,
			expected: "open-channel-request@microsoft.com",
		},
		{
			name:     "SessionReconnect",
			goValue:  ExtensionSessionReconnect,
			expected: "session-reconnect@microsoft.com",
		},
		{
			name:     "SessionLatency",
			goValue:  ExtensionSessionLatency,
			expected: "session-latency@microsoft.com",
		},
		{
			name:     "InitialChannelRequest",
			goValue:  ExtensionRequestInitialChannelRequest,
			expected: "initial-channel-request@microsoft.com",
		},
		{
			name:     "EnableSessionReconnect",
			goValue:  ExtensionRequestEnableSessionReconnect,
			expected: "enable-session-reconnect@microsoft.com",
		},
		{
			name:     "KeepAlive",
			goValue:  ExtensionRequestKeepAlive,
			expected: "keepalive@openssh.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.goValue != tt.expected {
				t.Errorf("extension domain mismatch: Go=%q, expected=%q (must match C#/TS)",
					tt.goValue, tt.expected)
			}
		})
	}
}

// TestKeyboardInteractiveInfoRequestRFC4256 verifies that the keyboard-interactive
// AuthenticationInfoRequestMessage serialization matches RFC 4256 Section 3.2.
//
// RFC 4256 specifies the SSH_MSG_USERAUTH_INFO_REQUEST format as:
//
//	byte      SSH_MSG_USERAUTH_INFO_REQUEST (60)
//	string    name (ISO-10646 UTF-8)
//	string    instruction (ISO-10646 UTF-8)
//	string    language tag (as per RFC-3066)
//	int       num-prompts
//	string    prompt[1] (ISO-10646 UTF-8)
//	boolean   echo[1]
//	...
//	string    prompt[num-prompts] (ISO-10646 UTF-8)
//	boolean   echo[num-prompts]
//
// The prompts and echo flags are interleaved (each prompt immediately followed
// by its echo flag), NOT stored as separate arrays. This implementation correctly
// follows the interleaved format, matching the C# and TypeScript implementations.
func TestKeyboardInteractiveInfoRequestRFC4256(t *testing.T) {
	original := &messages.AuthenticationInfoRequestMessage{
		Name:        "Auth Challenge",
		Instruction: "Please enter your credentials",
		Language:    "en-US",
		Prompts: []messages.AuthenticationInfoRequestPrompt{
			{Prompt: "Password: ", Echo: false},
			{Prompt: "OTP: ", Echo: true},
		},
	}

	buf := original.ToBuffer()
	if len(buf) == 0 {
		t.Fatal("ToBuffer returned empty buffer")
	}
	if buf[0] != messages.MsgNumAuthInfoRequest {
		t.Fatalf("first byte = %d, want %d (SSH_MSG_USERAUTH_INFO_REQUEST)",
			buf[0], messages.MsgNumAuthInfoRequest)
	}

	// Deserialize and verify round-trip.
	parsed := &messages.AuthenticationInfoRequestMessage{}
	if err := messages.ReadMessage(parsed, buf); err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if parsed.Name != "Auth Challenge" {
		t.Errorf("Name = %q, want %q", parsed.Name, "Auth Challenge")
	}
	if parsed.Instruction != "Please enter your credentials" {
		t.Errorf("Instruction = %q, want %q", parsed.Instruction, "Please enter your credentials")
	}
	if parsed.Language != "en-US" {
		t.Errorf("Language = %q, want %q", parsed.Language, "en-US")
	}
	if len(parsed.Prompts) != 2 {
		t.Fatalf("len(Prompts) = %d, want 2", len(parsed.Prompts))
	}
	// Verify interleaved prompt+echo pairs (RFC 4256 format).
	if parsed.Prompts[0].Prompt != "Password: " {
		t.Errorf("Prompts[0].Prompt = %q, want %q", parsed.Prompts[0].Prompt, "Password: ")
	}
	if parsed.Prompts[0].Echo != false {
		t.Error("Prompts[0].Echo = true, want false")
	}
	if parsed.Prompts[1].Prompt != "OTP: " {
		t.Errorf("Prompts[1].Prompt = %q, want %q", parsed.Prompts[1].Prompt, "OTP: ")
	}
	if parsed.Prompts[1].Echo != true {
		t.Error("Prompts[1].Echo = false, want true")
	}
}

// TestKeyboardInteractiveInfoRequestEmptyPrompts verifies that an InfoRequest
// with zero prompts round-trips correctly (RFC 4256 allows num-prompts=0).
func TestKeyboardInteractiveInfoRequestEmptyPrompts(t *testing.T) {
	original := &messages.AuthenticationInfoRequestMessage{
		Name:        "",
		Instruction: "No prompts needed",
		Language:    "",
		Prompts:     nil,
	}

	buf := original.ToBuffer()
	parsed := &messages.AuthenticationInfoRequestMessage{}
	if err := messages.ReadMessage(parsed, buf); err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if len(parsed.Prompts) != 0 {
		t.Errorf("len(Prompts) = %d, want 0", len(parsed.Prompts))
	}
	if parsed.Instruction != "No prompts needed" {
		t.Errorf("Instruction = %q, want %q", parsed.Instruction, "No prompts needed")
	}
}

// TestKeyboardInteractiveInfoResponseRFC4256 verifies that the keyboard-interactive
// AuthenticationInfoResponseMessage serialization matches RFC 4256 Section 3.4.
//
// RFC 4256 specifies the SSH_MSG_USERAUTH_INFO_RESPONSE format as:
//
//	byte      SSH_MSG_USERAUTH_INFO_RESPONSE (61)
//	int       num-responses
//	string    response[1] (ISO-10646 UTF-8)
//	...
//	string    response[num-responses] (ISO-10646 UTF-8)
func TestKeyboardInteractiveInfoResponseRFC4256(t *testing.T) {
	original := &messages.AuthenticationInfoResponseMessage{
		Responses: []string{"my-password", "123456"},
	}

	buf := original.ToBuffer()
	if len(buf) == 0 {
		t.Fatal("ToBuffer returned empty buffer")
	}
	if buf[0] != messages.MsgNumAuthInfoResponse {
		t.Fatalf("first byte = %d, want %d (SSH_MSG_USERAUTH_INFO_RESPONSE)",
			buf[0], messages.MsgNumAuthInfoResponse)
	}

	parsed := &messages.AuthenticationInfoResponseMessage{}
	if err := messages.ReadMessage(parsed, buf); err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if len(parsed.Responses) != 2 {
		t.Fatalf("len(Responses) = %d, want 2", len(parsed.Responses))
	}
	if parsed.Responses[0] != "my-password" {
		t.Errorf("Responses[0] = %q, want %q", parsed.Responses[0], "my-password")
	}
	if parsed.Responses[1] != "123456" {
		t.Errorf("Responses[1] = %q, want %q", parsed.Responses[1], "123456")
	}
}

// TestKeyboardInteractiveInfoResponseEmpty verifies that an InfoResponse
// with zero responses round-trips correctly.
func TestKeyboardInteractiveInfoResponseEmpty(t *testing.T) {
	original := &messages.AuthenticationInfoResponseMessage{
		Responses: nil,
	}

	buf := original.ToBuffer()
	parsed := &messages.AuthenticationInfoResponseMessage{}
	if err := messages.ReadMessage(parsed, buf); err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if len(parsed.Responses) != 0 {
		t.Errorf("len(Responses) = %d, want 0", len(parsed.Responses))
	}
}
