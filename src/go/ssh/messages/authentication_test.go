// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	"testing"

	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// --- AuthenticationRequestMessage tests ---

func TestAuthenticationRequestMessageRoundTrip(t *testing.T) {
	original := &AuthenticationRequestMessage{
		Username:    "testuser",
		ServiceName: "ssh-connection",
		MethodName:  "password",
		Password:    "secret123",
	}
	target := &AuthenticationRequestMessage{}
	roundTrip(t, original, target)

	if target.Username != "testuser" {
		t.Errorf("Username = %q, want %q", target.Username, "testuser")
	}
	if target.ServiceName != "ssh-connection" {
		t.Errorf("ServiceName = %q, want %q", target.ServiceName, "ssh-connection")
	}
	if target.MethodName != "password" {
		t.Errorf("MethodName = %q, want %q", target.MethodName, "password")
	}
	if target.Password != "secret123" {
		t.Errorf("Password = %q, want %q", target.Password, "secret123")
	}
}

func TestAuthenticationRequestMessageType(t *testing.T) {
	m := &AuthenticationRequestMessage{}
	if m.MessageType() != 50 {
		t.Errorf("MessageType() = %d, want 50", m.MessageType())
	}
}

func TestAuthenticationRequestMessageNoneMethod(t *testing.T) {
	original := &AuthenticationRequestMessage{
		Username:    "admin",
		ServiceName: "ssh-connection",
		MethodName:  "none",
	}
	target := &AuthenticationRequestMessage{}
	roundTrip(t, original, target)

	if target.MethodName != "none" {
		t.Errorf("MethodName = %q, want %q", target.MethodName, "none")
	}
}

func TestAuthenticationRequestMessagePublicKey(t *testing.T) {
	original := &AuthenticationRequestMessage{
		Username:    "user@domain.com",
		ServiceName: "ssh-connection",
		MethodName:  "publickey",
	}
	target := &AuthenticationRequestMessage{}
	roundTrip(t, original, target)

	if target.Username != "user@domain.com" {
		t.Errorf("Username = %q, want %q", target.Username, "user@domain.com")
	}
	if target.MethodName != "publickey" {
		t.Errorf("MethodName = %q, want %q", target.MethodName, "publickey")
	}
}

func TestAuthenticationRequestMessageUnicodeUsername(t *testing.T) {
	original := &AuthenticationRequestMessage{
		Username:    "用户名",
		ServiceName: "ssh-connection",
		MethodName:  "password",
		Password:    "密码",
	}
	target := &AuthenticationRequestMessage{}
	roundTrip(t, original, target)

	if target.Username != "用户名" {
		t.Errorf("Username = %q, want %q", target.Username, "用户名")
	}
	if target.Password != "密码" {
		t.Errorf("Password = %q, want %q", target.Password, "密码")
	}
}

func TestAuthenticationRequestMessageEmptyFields(t *testing.T) {
	original := &AuthenticationRequestMessage{
		Username:    "",
		ServiceName: "",
		MethodName:  "",
	}
	target := &AuthenticationRequestMessage{}
	roundTrip(t, original, target)

	if target.Username != "" {
		t.Errorf("Username = %q, want empty", target.Username)
	}
	if target.ServiceName != "" {
		t.Errorf("ServiceName = %q, want empty", target.ServiceName)
	}
	if target.MethodName != "" {
		t.Errorf("MethodName = %q, want empty", target.MethodName)
	}
}

// --- AuthenticationFailureMessage tests ---

func TestAuthenticationFailureMessageRoundTrip(t *testing.T) {
	original := &AuthenticationFailureMessage{
		MethodNames:    []string{"publickey", "password", "keyboard-interactive"},
		PartialSuccess: false,
	}
	target := &AuthenticationFailureMessage{}
	roundTrip(t, original, target)

	assertStringSlice(t, "MethodNames", target.MethodNames, original.MethodNames)
	if target.PartialSuccess != false {
		t.Error("PartialSuccess should be false")
	}
}

func TestAuthenticationFailureMessageType(t *testing.T) {
	m := &AuthenticationFailureMessage{}
	if m.MessageType() != 51 {
		t.Errorf("MessageType() = %d, want 51", m.MessageType())
	}
}

func TestAuthenticationFailureMessagePartialSuccess(t *testing.T) {
	original := &AuthenticationFailureMessage{
		MethodNames:    []string{"password"},
		PartialSuccess: true,
	}
	target := &AuthenticationFailureMessage{}
	roundTrip(t, original, target)

	if target.PartialSuccess != true {
		t.Error("PartialSuccess should be true")
	}
	assertStringSlice(t, "MethodNames", target.MethodNames, []string{"password"})
}

func TestAuthenticationFailureMessageEmptyMethods(t *testing.T) {
	original := &AuthenticationFailureMessage{
		MethodNames:    []string{},
		PartialSuccess: false,
	}
	target := &AuthenticationFailureMessage{}
	roundTrip(t, original, target)

	assertStringSlice(t, "MethodNames", target.MethodNames, []string{})
}

// --- AuthenticationSuccessMessage tests ---

func TestAuthenticationSuccessMessageRoundTrip(t *testing.T) {
	original := &AuthenticationSuccessMessage{}
	target := &AuthenticationSuccessMessage{}
	roundTrip(t, original, target)
}

func TestAuthenticationSuccessMessageType(t *testing.T) {
	m := &AuthenticationSuccessMessage{}
	if m.MessageType() != 52 {
		t.Errorf("MessageType() = %d, want 52", m.MessageType())
	}
}

func TestAuthenticationSuccessMessageBufferSize(t *testing.T) {
	m := &AuthenticationSuccessMessage{}
	buf := m.ToBuffer()
	if len(buf) != 1 {
		t.Errorf("buffer length = %d, want 1", len(buf))
	}
}

// --- PublicKeyOkMessage tests ---

func TestPublicKeyOkMessageRoundTrip(t *testing.T) {
	pubKey := []byte{0x00, 0x00, 0x00, 0x07, 's', 's', 'h', '-', 'r', 's', 'a', 0x01, 0x02, 0x03}
	original := &PublicKeyOkMessage{
		KeyAlgorithmName: "rsa-sha2-256",
		PublicKey:        pubKey,
	}
	target := &PublicKeyOkMessage{}
	roundTrip(t, original, target)

	if target.KeyAlgorithmName != "rsa-sha2-256" {
		t.Errorf("KeyAlgorithmName = %q, want %q", target.KeyAlgorithmName, "rsa-sha2-256")
	}
	assertByteSlice(t, "PublicKey", target.PublicKey, pubKey)
}

func TestPublicKeyOkMessageType(t *testing.T) {
	m := &PublicKeyOkMessage{}
	if m.MessageType() != 60 {
		t.Errorf("MessageType() = %d, want 60", m.MessageType())
	}
}

func TestPublicKeyOkMessageECDSA(t *testing.T) {
	pubKey := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	original := &PublicKeyOkMessage{
		KeyAlgorithmName: "ecdsa-sha2-nistp256",
		PublicKey:        pubKey,
	}
	target := &PublicKeyOkMessage{}
	roundTrip(t, original, target)

	if target.KeyAlgorithmName != "ecdsa-sha2-nistp256" {
		t.Errorf("KeyAlgorithmName = %q, want %q", target.KeyAlgorithmName, "ecdsa-sha2-nistp256")
	}
	assertByteSlice(t, "PublicKey", target.PublicKey, pubKey)
}

func TestPublicKeyOkMessageEmptyKey(t *testing.T) {
	original := &PublicKeyOkMessage{
		KeyAlgorithmName: "ssh-rsa",
		PublicKey:        []byte{},
	}
	target := &PublicKeyOkMessage{}
	roundTrip(t, original, target)

	if len(target.PublicKey) != 0 {
		t.Errorf("PublicKey length = %d, want 0", len(target.PublicKey))
	}
}

// --- AuthenticationInfoRequestMessage tests ---

func TestAuthenticationInfoRequestMessageRoundTrip(t *testing.T) {
	original := &AuthenticationInfoRequestMessage{
		Name:        "Authentication Required",
		Instruction: "Please enter your credentials",
		Language:    "en-US",
		Prompts: []AuthenticationInfoRequestPrompt{
			{Prompt: "Username: ", Echo: true},
			{Prompt: "Password: ", Echo: false},
		},
	}
	target := &AuthenticationInfoRequestMessage{}
	roundTrip(t, original, target)

	if target.Name != "Authentication Required" {
		t.Errorf("Name = %q, want %q", target.Name, "Authentication Required")
	}
	if target.Instruction != "Please enter your credentials" {
		t.Errorf("Instruction = %q, want %q", target.Instruction, "Please enter your credentials")
	}
	if target.Language != "en-US" {
		t.Errorf("Language = %q, want %q", target.Language, "en-US")
	}
	if len(target.Prompts) != 2 {
		t.Fatalf("Prompts length = %d, want 2", len(target.Prompts))
	}
	if target.Prompts[0].Prompt != "Username: " {
		t.Errorf("Prompts[0].Prompt = %q, want %q", target.Prompts[0].Prompt, "Username: ")
	}
	if target.Prompts[0].Echo != true {
		t.Error("Prompts[0].Echo should be true")
	}
	if target.Prompts[1].Prompt != "Password: " {
		t.Errorf("Prompts[1].Prompt = %q, want %q", target.Prompts[1].Prompt, "Password: ")
	}
	if target.Prompts[1].Echo != false {
		t.Error("Prompts[1].Echo should be false")
	}
}

func TestAuthenticationInfoRequestMessageType(t *testing.T) {
	m := &AuthenticationInfoRequestMessage{}
	if m.MessageType() != 60 {
		t.Errorf("MessageType() = %d, want 60", m.MessageType())
	}
}

func TestAuthenticationInfoRequestMessageEmptyPrompts(t *testing.T) {
	original := &AuthenticationInfoRequestMessage{
		Name:        "",
		Instruction: "",
		Language:    "",
		Prompts:     []AuthenticationInfoRequestPrompt{},
	}
	target := &AuthenticationInfoRequestMessage{}
	roundTrip(t, original, target)

	if len(target.Prompts) != 0 {
		t.Errorf("Prompts length = %d, want 0", len(target.Prompts))
	}
}

func TestAuthenticationInfoRequestMessageSinglePrompt(t *testing.T) {
	original := &AuthenticationInfoRequestMessage{
		Name:        "OTP",
		Instruction: "Enter one-time password",
		Language:    "",
		Prompts: []AuthenticationInfoRequestPrompt{
			{Prompt: "Token: ", Echo: false},
		},
	}
	target := &AuthenticationInfoRequestMessage{}
	roundTrip(t, original, target)

	if len(target.Prompts) != 1 {
		t.Fatalf("Prompts length = %d, want 1", len(target.Prompts))
	}
	if target.Prompts[0].Prompt != "Token: " {
		t.Errorf("Prompts[0].Prompt = %q, want %q", target.Prompts[0].Prompt, "Token: ")
	}
	if target.Prompts[0].Echo != false {
		t.Error("Prompts[0].Echo should be false")
	}
}

func TestAuthenticationInfoRequestMessageUnicodePrompts(t *testing.T) {
	original := &AuthenticationInfoRequestMessage{
		Name:        "认证",
		Instruction: "请输入密码",
		Language:    "zh-CN",
		Prompts: []AuthenticationInfoRequestPrompt{
			{Prompt: "密码: ", Echo: false},
		},
	}
	target := &AuthenticationInfoRequestMessage{}
	roundTrip(t, original, target)

	if target.Name != "认证" {
		t.Errorf("Name = %q, want %q", target.Name, "认证")
	}
	if target.Instruction != "请输入密码" {
		t.Errorf("Instruction = %q, want %q", target.Instruction, "请输入密码")
	}
}

// --- AuthenticationInfoResponseMessage tests ---

func TestAuthenticationInfoResponseMessageRoundTrip(t *testing.T) {
	original := &AuthenticationInfoResponseMessage{
		Responses: []string{"admin", "s3cret"},
	}
	target := &AuthenticationInfoResponseMessage{}
	roundTrip(t, original, target)

	if len(target.Responses) != 2 {
		t.Fatalf("Responses length = %d, want 2", len(target.Responses))
	}
	if target.Responses[0] != "admin" {
		t.Errorf("Responses[0] = %q, want %q", target.Responses[0], "admin")
	}
	if target.Responses[1] != "s3cret" {
		t.Errorf("Responses[1] = %q, want %q", target.Responses[1], "s3cret")
	}
}

func TestAuthenticationInfoResponseMessageType(t *testing.T) {
	m := &AuthenticationInfoResponseMessage{}
	if m.MessageType() != 61 {
		t.Errorf("MessageType() = %d, want 61", m.MessageType())
	}
}

func TestAuthenticationInfoResponseMessageEmpty(t *testing.T) {
	original := &AuthenticationInfoResponseMessage{
		Responses: []string{},
	}
	target := &AuthenticationInfoResponseMessage{}
	roundTrip(t, original, target)

	if len(target.Responses) != 0 {
		t.Errorf("Responses length = %d, want 0", len(target.Responses))
	}
}

func TestAuthenticationInfoResponseMessageSingleResponse(t *testing.T) {
	original := &AuthenticationInfoResponseMessage{
		Responses: []string{"123456"},
	}
	target := &AuthenticationInfoResponseMessage{}
	roundTrip(t, original, target)

	if len(target.Responses) != 1 {
		t.Fatalf("Responses length = %d, want 1", len(target.Responses))
	}
	if target.Responses[0] != "123456" {
		t.Errorf("Responses[0] = %q, want %q", target.Responses[0], "123456")
	}
}

func TestAuthenticationInfoResponseMessageUnicodeResponses(t *testing.T) {
	original := &AuthenticationInfoResponseMessage{
		Responses: []string{"密码123", "验证码"},
	}
	target := &AuthenticationInfoResponseMessage{}
	roundTrip(t, original, target)

	if target.Responses[0] != "密码123" {
		t.Errorf("Responses[0] = %q, want %q", target.Responses[0], "密码123")
	}
	if target.Responses[1] != "验证码" {
		t.Errorf("Responses[1] = %q, want %q", target.Responses[1], "验证码")
	}
}

// --- Keyboard-interactive wire format tests (CRIT-01) ---

func TestKeyboardInteractivePromptsOrder(t *testing.T) {
	// Verify byte-level order is all-prompts-then-all-echos, matching C#/TS.
	original := &AuthenticationInfoRequestMessage{
		Name:        "Auth",
		Instruction: "Please respond",
		Language:    "",
		Prompts: []AuthenticationInfoRequestPrompt{
			{Prompt: "Username: ", Echo: true},
			{Prompt: "Password: ", Echo: false},
			{Prompt: "OTP: ", Echo: false},
		},
	}
	buf := original.ToBuffer()
	r := sshio.NewSSHDataReader(buf)

	// Skip message type byte.
	_, _ = r.ReadByte()
	// Skip name, instruction, language.
	_, _ = r.ReadString()
	_, _ = r.ReadString()
	_, _ = r.ReadString()
	// Read num-prompts.
	count, _ := r.ReadUInt32()
	if count != 3 {
		t.Fatalf("count = %d, want 3", count)
	}

	// Expect all prompt strings first.
	p0, _ := r.ReadString()
	p1, _ := r.ReadString()
	p2, _ := r.ReadString()
	if p0 != "Username: " || p1 != "Password: " || p2 != "OTP: " {
		t.Fatalf("prompts = %q, %q, %q; want Username/Password/OTP", p0, p1, p2)
	}

	// Then all echo flags.
	e0, _ := r.ReadBoolean()
	e1, _ := r.ReadBoolean()
	e2, _ := r.ReadBoolean()
	if e0 != true || e1 != false || e2 != false {
		t.Fatalf("echos = %v, %v, %v; want true, false, false", e0, e1, e2)
	}
}

func TestKeyboardInteractiveRoundTrip(t *testing.T) {
	// Round-trip with multiple prompts verifying all fields preserved.
	original := &AuthenticationInfoRequestMessage{
		Name:        "MFA Challenge",
		Instruction: "Enter credentials",
		Language:    "en",
		Prompts: []AuthenticationInfoRequestPrompt{
			{Prompt: "Username: ", Echo: true},
			{Prompt: "Password: ", Echo: false},
			{Prompt: "TOTP Code: ", Echo: true},
		},
	}
	target := &AuthenticationInfoRequestMessage{}
	roundTrip(t, original, target)

	if target.Name != original.Name {
		t.Errorf("Name = %q, want %q", target.Name, original.Name)
	}
	if target.Instruction != original.Instruction {
		t.Errorf("Instruction = %q, want %q", target.Instruction, original.Instruction)
	}
	if target.Language != original.Language {
		t.Errorf("Language = %q, want %q", target.Language, original.Language)
	}
	if len(target.Prompts) != 3 {
		t.Fatalf("Prompts length = %d, want 3", len(target.Prompts))
	}
	for i, p := range original.Prompts {
		if target.Prompts[i].Prompt != p.Prompt {
			t.Errorf("Prompts[%d].Prompt = %q, want %q", i, target.Prompts[i].Prompt, p.Prompt)
		}
		if target.Prompts[i].Echo != p.Echo {
			t.Errorf("Prompts[%d].Echo = %v, want %v", i, target.Prompts[i].Echo, p.Echo)
		}
	}
}

// --- Cross-message type validation tests ---

func TestReadMessageWrongTypeKex(t *testing.T) {
	m := &KeyExchangeInitMessage{
		KeyExchangeAlgorithms:               []string{"none"},
		ServerHostKeyAlgorithms:             []string{"none"},
		EncryptionAlgorithmsClientToServer:  []string{"none"},
		EncryptionAlgorithmsServerToClient:  []string{"none"},
		MacAlgorithmsClientToServer:         []string{"none"},
		MacAlgorithmsServerToClient:         []string{"none"},
		CompressionAlgorithmsClientToServer: []string{"none"},
		CompressionAlgorithmsServerToClient: []string{"none"},
		LanguagesClientToServer:             []string{},
		LanguagesServerToClient:             []string{},
	}
	buf := m.ToBuffer()

	// Try to read as NewKeys
	target := &NewKeysMessage{}
	err := ReadMessage(target, buf)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
	if _, ok := err.(*InvalidMessageTypeError); !ok {
		t.Errorf("expected InvalidMessageTypeError, got %T", err)
	}
}

func TestReadMessageWrongTypeAuth(t *testing.T) {
	m := &AuthenticationRequestMessage{
		Username:    "test",
		ServiceName: "ssh-connection",
		MethodName:  "none",
	}
	buf := m.ToBuffer()

	target := &AuthenticationSuccessMessage{}
	err := ReadMessage(target, buf)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}
