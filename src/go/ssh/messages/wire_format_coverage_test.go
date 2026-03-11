// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	"math"
	"math/big"
	"strings"
	"testing"
)

// --- MinimalFields / MaximalFields tests for every message type ---
// MinimalFields: zero values, empty strings, empty slices.
// MaximalFields: max uint32/uint64, long strings, all optional fields set.

// --- DisconnectMessage ---

func TestDisconnectMessageMinimalFields(t *testing.T) {
	original := &DisconnectMessage{
		ReasonCode:  0,
		Description: "",
		Language:    "",
	}
	target := &DisconnectMessage{}
	roundTrip(t, original, target)
	if target.ReasonCode != 0 {
		t.Errorf("ReasonCode = %d, want 0", target.ReasonCode)
	}
	if target.Description != "" {
		t.Errorf("Description = %q, want empty", target.Description)
	}
	if target.Language != "" {
		t.Errorf("Language = %q, want empty", target.Language)
	}
}

func TestDisconnectMessageMaximalFields(t *testing.T) {
	original := &DisconnectMessage{
		ReasonCode:  SSHDisconnectReason(math.MaxUint32),
		Description: strings.Repeat("x", 1024),
		Language:    "en-US",
	}
	target := &DisconnectMessage{}
	roundTrip(t, original, target)
	if target.ReasonCode != SSHDisconnectReason(math.MaxUint32) {
		t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, math.MaxUint32)
	}
	if target.Description != original.Description {
		t.Error("Description not preserved")
	}
	if target.Language != "en-US" {
		t.Errorf("Language = %q, want %q", target.Language, "en-US")
	}
}

// --- IgnoreMessage ---

func TestIgnoreMessageMinimalFields(t *testing.T) {
	original := &IgnoreMessage{}
	target := &IgnoreMessage{}
	roundTrip(t, original, target)
}

func TestIgnoreMessageMaximalFields(t *testing.T) {
	original := &IgnoreMessage{}
	target := &IgnoreMessage{}
	roundTrip(t, original, target)
}

// --- UnimplementedMessage ---

func TestUnimplementedMessageMinimalFields(t *testing.T) {
	original := &UnimplementedMessage{SequenceNumber: 0}
	target := &UnimplementedMessage{}
	roundTrip(t, original, target)
	if target.SequenceNumber != 0 {
		t.Errorf("SequenceNumber = %d, want 0", target.SequenceNumber)
	}
}

func TestUnimplementedMessageMaximalFields(t *testing.T) {
	original := &UnimplementedMessage{SequenceNumber: math.MaxUint32}
	target := &UnimplementedMessage{}
	roundTrip(t, original, target)
	if target.SequenceNumber != math.MaxUint32 {
		t.Errorf("SequenceNumber = %d, want %d", target.SequenceNumber, uint32(math.MaxUint32))
	}
}

// --- DebugMessage ---

func TestDebugMessageMinimalFields(t *testing.T) {
	original := &DebugMessage{
		AlwaysDisplay: false,
		Message:       "",
		Language:      "",
	}
	target := &DebugMessage{}
	roundTrip(t, original, target)
	if target.AlwaysDisplay != false {
		t.Error("AlwaysDisplay should be false")
	}
	if target.Message != "" {
		t.Errorf("Message = %q, want empty", target.Message)
	}
}

func TestDebugMessageMaximalFields(t *testing.T) {
	original := &DebugMessage{
		AlwaysDisplay: true,
		Message:       strings.Repeat("debug", 200),
		Language:      "ja-JP",
	}
	target := &DebugMessage{}
	roundTrip(t, original, target)
	if target.AlwaysDisplay != true {
		t.Error("AlwaysDisplay should be true")
	}
	if target.Message != original.Message {
		t.Error("Message not preserved")
	}
	if target.Language != "ja-JP" {
		t.Errorf("Language = %q, want %q", target.Language, "ja-JP")
	}
}

// --- ServiceRequestMessage ---

func TestServiceRequestMessageMinimalFields(t *testing.T) {
	original := &ServiceRequestMessage{ServiceName: ""}
	target := &ServiceRequestMessage{}
	roundTrip(t, original, target)
	if target.ServiceName != "" {
		t.Errorf("ServiceName = %q, want empty", target.ServiceName)
	}
}

func TestServiceRequestMessageMaximalFields(t *testing.T) {
	original := &ServiceRequestMessage{ServiceName: "ssh-connection"}
	target := &ServiceRequestMessage{}
	roundTrip(t, original, target)
	if target.ServiceName != "ssh-connection" {
		t.Errorf("ServiceName = %q, want %q", target.ServiceName, "ssh-connection")
	}
}

// --- ServiceAcceptMessage ---

func TestServiceAcceptMessageMinimalFields(t *testing.T) {
	original := &ServiceAcceptMessage{ServiceName: ""}
	target := &ServiceAcceptMessage{}
	roundTrip(t, original, target)
	if target.ServiceName != "" {
		t.Errorf("ServiceName = %q, want empty", target.ServiceName)
	}
}

func TestServiceAcceptMessageMaximalFields(t *testing.T) {
	original := &ServiceAcceptMessage{ServiceName: "ssh-userauth"}
	target := &ServiceAcceptMessage{}
	roundTrip(t, original, target)
	if target.ServiceName != "ssh-userauth" {
		t.Errorf("ServiceName = %q, want %q", target.ServiceName, "ssh-userauth")
	}
}

// --- ExtensionInfoMessage ---

func TestExtensionInfoMessageMinimalFields(t *testing.T) {
	original := &ExtensionInfoMessage{Extensions: map[string]string{}}
	target := &ExtensionInfoMessage{}
	roundTrip(t, original, target)
	if len(target.Extensions) != 0 {
		t.Errorf("Extensions length = %d, want 0", len(target.Extensions))
	}
}

func TestExtensionInfoMessageMaximalFields(t *testing.T) {
	original := &ExtensionInfoMessage{
		Extensions: map[string]string{
			"server-sig-algs":             "rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256",
			"delay-compression":           "zlib@openssh.com",
			"no-flow-control":             "s",
			strings.Repeat("k", 128):      strings.Repeat("v", 256),
		},
	}
	target := &ExtensionInfoMessage{}
	roundTrip(t, original, target)
	if len(target.Extensions) != len(original.Extensions) {
		t.Errorf("Extensions length = %d, want %d", len(target.Extensions), len(original.Extensions))
	}
	for k, v := range original.Extensions {
		if target.Extensions[k] != v {
			t.Errorf("Extensions[%q] = %q, want %q", k, target.Extensions[k], v)
		}
	}
}

// --- SessionRequestMessage ---

func TestSessionRequestMessageMinimalFields(t *testing.T) {
	original := &SessionRequestMessage{RequestType: "", WantReply: false}
	target := &SessionRequestMessage{}
	roundTrip(t, original, target)
	if target.RequestType != "" {
		t.Errorf("RequestType = %q, want empty", target.RequestType)
	}
	if target.WantReply {
		t.Error("WantReply should be false")
	}
}

func TestSessionRequestMessageMaximalFields(t *testing.T) {
	original := &SessionRequestMessage{RequestType: "tcpip-forward", WantReply: true}
	target := &SessionRequestMessage{}
	roundTrip(t, original, target)
	if target.RequestType != "tcpip-forward" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "tcpip-forward")
	}
	if !target.WantReply {
		t.Error("WantReply should be true")
	}
}

// --- SessionRequestSuccessMessage ---

func TestSessionRequestSuccessMessageMinimalFields(t *testing.T) {
	original := &SessionRequestSuccessMessage{}
	target := &SessionRequestSuccessMessage{}
	roundTrip(t, original, target)
}

func TestSessionRequestSuccessMessageMaximalFields(t *testing.T) {
	original := &SessionRequestSuccessMessage{}
	target := &SessionRequestSuccessMessage{}
	roundTrip(t, original, target)
}

// --- SessionRequestFailureMessage ---

func TestSessionRequestFailureMessageMinimalFields(t *testing.T) {
	original := &SessionRequestFailureMessage{}
	target := &SessionRequestFailureMessage{}
	roundTrip(t, original, target)
}

func TestSessionRequestFailureMessageMaximalFields(t *testing.T) {
	original := &SessionRequestFailureMessage{}
	target := &SessionRequestFailureMessage{}
	roundTrip(t, original, target)
}

// --- SessionChannelRequestMessage ---

func TestSessionChannelRequestMessageMinimalFields(t *testing.T) {
	original := &SessionChannelRequestMessage{
		SessionRequestMessage: SessionRequestMessage{RequestType: "", WantReply: false},
		SenderChannel:         0,
		Request:               &ChannelRequestMessage{RecipientChannel: 0, RequestType: "", WantReply: false},
	}
	target := &SessionChannelRequestMessage{}
	roundTrip(t, original, target)
	if target.SenderChannel != 0 {
		t.Errorf("SenderChannel = %d, want 0", target.SenderChannel)
	}
	if target.Request == nil {
		t.Fatal("Request should not be nil")
	}
}

func TestSessionChannelRequestMessageMaximalFields(t *testing.T) {
	original := &SessionChannelRequestMessage{
		SessionRequestMessage: SessionRequestMessage{
			RequestType: "open-channel-request",
			WantReply:   true,
		},
		SenderChannel: math.MaxUint32,
		Request: &ChannelRequestMessage{
			RecipientChannel: math.MaxUint32,
			RequestType:      "shell",
			WantReply:        true,
		},
	}
	target := &SessionChannelRequestMessage{}
	roundTrip(t, original, target)
	if target.SenderChannel != math.MaxUint32 {
		t.Errorf("SenderChannel = %d, want %d", target.SenderChannel, uint32(math.MaxUint32))
	}
	if target.Request.RequestType != "shell" {
		t.Errorf("Request.RequestType = %q, want %q", target.Request.RequestType, "shell")
	}
}

// --- AuthenticationRequestMessage ---

func TestAuthenticationRequestMessageMinimalFields(t *testing.T) {
	original := &AuthenticationRequestMessage{
		Username:    "",
		ServiceName: "",
		MethodName:  "none",
	}
	target := &AuthenticationRequestMessage{}
	roundTrip(t, original, target)
	if target.Username != "" {
		t.Errorf("Username = %q, want empty", target.Username)
	}
	if target.MethodName != "none" {
		t.Errorf("MethodName = %q, want %q", target.MethodName, "none")
	}
}

func TestAuthenticationRequestMessageMaximalFields(t *testing.T) {
	original := &AuthenticationRequestMessage{
		Username:         strings.Repeat("u", 256),
		ServiceName:      "ssh-connection",
		MethodName:       "publickey",
		HasSignature:     true,
		KeyAlgorithmName: "ecdsa-sha2-nistp256",
		PublicKey:         []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		Signature:         []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE},
	}
	target := &AuthenticationRequestMessage{}
	roundTrip(t, original, target)
	if target.Username != original.Username {
		t.Error("Username not preserved")
	}
	if target.MethodName != "publickey" {
		t.Errorf("MethodName = %q, want %q", target.MethodName, "publickey")
	}
	if !target.HasSignature {
		t.Error("HasSignature should be true")
	}
	if target.KeyAlgorithmName != "ecdsa-sha2-nistp256" {
		t.Errorf("KeyAlgorithmName = %q, want %q", target.KeyAlgorithmName, "ecdsa-sha2-nistp256")
	}
	assertByteSlice(t, "PublicKey", target.PublicKey, original.PublicKey)
	assertByteSlice(t, "Signature", target.Signature, original.Signature)
}

// --- AuthenticationFailureMessage ---

func TestAuthenticationFailureMessageMinimalFields(t *testing.T) {
	original := &AuthenticationFailureMessage{
		MethodNames:    []string{},
		PartialSuccess: false,
	}
	target := &AuthenticationFailureMessage{}
	roundTrip(t, original, target)
	if len(target.MethodNames) != 0 {
		t.Errorf("MethodNames length = %d, want 0", len(target.MethodNames))
	}
	if target.PartialSuccess {
		t.Error("PartialSuccess should be false")
	}
}

func TestAuthenticationFailureMessageMaximalFields(t *testing.T) {
	original := &AuthenticationFailureMessage{
		MethodNames:    []string{"publickey", "password", "keyboard-interactive"},
		PartialSuccess: true,
	}
	target := &AuthenticationFailureMessage{}
	roundTrip(t, original, target)
	assertStringSlice(t, "MethodNames", target.MethodNames, original.MethodNames)
	if !target.PartialSuccess {
		t.Error("PartialSuccess should be true")
	}
}

// --- AuthenticationSuccessMessage ---

func TestAuthenticationSuccessMessageMinimalFields(t *testing.T) {
	original := &AuthenticationSuccessMessage{}
	target := &AuthenticationSuccessMessage{}
	roundTrip(t, original, target)
}

func TestAuthenticationSuccessMessageMaximalFields(t *testing.T) {
	original := &AuthenticationSuccessMessage{}
	target := &AuthenticationSuccessMessage{}
	roundTrip(t, original, target)
}

// --- PublicKeyOkMessage ---

func TestPublicKeyOkMessageMinimalFields(t *testing.T) {
	original := &PublicKeyOkMessage{
		KeyAlgorithmName: "",
		PublicKey:         []byte{},
	}
	target := &PublicKeyOkMessage{}
	roundTrip(t, original, target)
	if target.KeyAlgorithmName != "" {
		t.Errorf("KeyAlgorithmName = %q, want empty", target.KeyAlgorithmName)
	}
}

func TestPublicKeyOkMessageMaximalFields(t *testing.T) {
	original := &PublicKeyOkMessage{
		KeyAlgorithmName: "rsa-sha2-512",
		PublicKey:         make([]byte, 512),
	}
	for i := range original.PublicKey {
		original.PublicKey[i] = byte(i % 256)
	}
	target := &PublicKeyOkMessage{}
	roundTrip(t, original, target)
	if target.KeyAlgorithmName != "rsa-sha2-512" {
		t.Errorf("KeyAlgorithmName = %q, want %q", target.KeyAlgorithmName, "rsa-sha2-512")
	}
	assertByteSlice(t, "PublicKey", target.PublicKey, original.PublicKey)
}

// --- AuthenticationInfoRequestMessage ---

func TestAuthenticationInfoRequestMessageMinimalFields(t *testing.T) {
	original := &AuthenticationInfoRequestMessage{
		Name:        "",
		Instruction: "",
		Language:    "",
		Prompts:     nil,
	}
	target := &AuthenticationInfoRequestMessage{}
	roundTrip(t, original, target)
	if len(target.Prompts) != 0 {
		t.Errorf("Prompts length = %d, want 0", len(target.Prompts))
	}
}

func TestAuthenticationInfoRequestMessageMaximalFields(t *testing.T) {
	original := &AuthenticationInfoRequestMessage{
		Name:        "Two-Factor Authentication",
		Instruction: "Please enter your credentials",
		Language:    "en-US",
		Prompts: []AuthenticationInfoRequestPrompt{
			{Prompt: "Password: ", Echo: false},
			{Prompt: "OTP Token: ", Echo: true},
			{Prompt: "Security Question: ", Echo: true},
			{Prompt: "Verification Code: ", Echo: false},
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
	if len(target.Prompts) != 4 {
		t.Fatalf("Prompts length = %d, want 4", len(target.Prompts))
	}
	for i, p := range original.Prompts {
		if target.Prompts[i].Prompt != p.Prompt {
			t.Errorf("Prompt[%d] = %q, want %q", i, target.Prompts[i].Prompt, p.Prompt)
		}
		if target.Prompts[i].Echo != p.Echo {
			t.Errorf("Echo[%d] = %v, want %v", i, target.Prompts[i].Echo, p.Echo)
		}
	}
}

// --- AuthenticationInfoResponseMessage ---

func TestAuthenticationInfoResponseMessageMinimalFields(t *testing.T) {
	original := &AuthenticationInfoResponseMessage{Responses: nil}
	target := &AuthenticationInfoResponseMessage{}
	roundTrip(t, original, target)
	if len(target.Responses) != 0 {
		t.Errorf("Responses length = %d, want 0", len(target.Responses))
	}
}

func TestAuthenticationInfoResponseMessageMaximalFields(t *testing.T) {
	original := &AuthenticationInfoResponseMessage{
		Responses: []string{"mypassword", "123456", "pet name", strings.Repeat("x", 1024)},
	}
	target := &AuthenticationInfoResponseMessage{}
	roundTrip(t, original, target)
	assertStringSlice(t, "Responses", target.Responses, original.Responses)
}

// --- ChannelOpenMessage ---

func TestChannelOpenMessageMinimalFields(t *testing.T) {
	original := &ChannelOpenMessage{
		ChannelType:   "",
		SenderChannel: 0,
		MaxWindowSize: 0,
		MaxPacketSize: 0,
	}
	target := &ChannelOpenMessage{}
	roundTrip(t, original, target)
	if target.ChannelType != "" {
		t.Errorf("ChannelType = %q, want empty", target.ChannelType)
	}
	if target.SenderChannel != 0 || target.MaxWindowSize != 0 || target.MaxPacketSize != 0 {
		t.Error("numeric fields should be 0")
	}
}

func TestChannelOpenMessageMaximalFields(t *testing.T) {
	original := &ChannelOpenMessage{
		ChannelType:   "forwarded-tcpip",
		SenderChannel: math.MaxUint32,
		MaxWindowSize: math.MaxUint32,
		MaxPacketSize: math.MaxUint32,
	}
	target := &ChannelOpenMessage{}
	roundTrip(t, original, target)
	if target.ChannelType != "forwarded-tcpip" {
		t.Errorf("ChannelType = %q, want %q", target.ChannelType, "forwarded-tcpip")
	}
	if target.SenderChannel != math.MaxUint32 {
		t.Errorf("SenderChannel = %d, want %d", target.SenderChannel, uint32(math.MaxUint32))
	}
	if target.MaxWindowSize != math.MaxUint32 {
		t.Errorf("MaxWindowSize = %d, want %d", target.MaxWindowSize, uint32(math.MaxUint32))
	}
	if target.MaxPacketSize != math.MaxUint32 {
		t.Errorf("MaxPacketSize = %d, want %d", target.MaxPacketSize, uint32(math.MaxUint32))
	}
}

// --- ChannelOpenConfirmationMessage ---

func TestChannelOpenConfirmationMessageMinimalFields(t *testing.T) {
	original := &ChannelOpenConfirmationMessage{
		RecipientChannel: 0,
		SenderChannel:    0,
		MaxWindowSize:    0,
		MaxPacketSize:    0,
	}
	target := &ChannelOpenConfirmationMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != 0 || target.SenderChannel != 0 ||
		target.MaxWindowSize != 0 || target.MaxPacketSize != 0 {
		t.Error("all fields should be 0")
	}
}

func TestChannelOpenConfirmationMessageMaximalFields(t *testing.T) {
	original := &ChannelOpenConfirmationMessage{
		RecipientChannel: math.MaxUint32,
		SenderChannel:    math.MaxUint32,
		MaxWindowSize:    math.MaxUint32,
		MaxPacketSize:    math.MaxUint32,
	}
	target := &ChannelOpenConfirmationMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
	if target.SenderChannel != math.MaxUint32 {
		t.Errorf("SenderChannel = %d, want max", target.SenderChannel)
	}
	if target.MaxWindowSize != math.MaxUint32 {
		t.Errorf("MaxWindowSize = %d, want max", target.MaxWindowSize)
	}
	if target.MaxPacketSize != math.MaxUint32 {
		t.Errorf("MaxPacketSize = %d, want max", target.MaxPacketSize)
	}
}

// --- ChannelOpenFailureMessage ---

func TestChannelOpenFailureMessageMinimalFields(t *testing.T) {
	original := &ChannelOpenFailureMessage{
		RecipientChannel: 0,
		ReasonCode:       0,
		Description:      "",
		Language:         "",
	}
	target := &ChannelOpenFailureMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != 0 || target.ReasonCode != 0 {
		t.Error("numeric fields should be 0")
	}
}

func TestChannelOpenFailureMessageMaximalFields(t *testing.T) {
	original := &ChannelOpenFailureMessage{
		RecipientChannel: math.MaxUint32,
		ReasonCode:       ChannelOpenFailureResourceShortage,
		Description:      strings.Repeat("err", 100),
		Language:         "de-DE",
	}
	target := &ChannelOpenFailureMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
	if target.ReasonCode != ChannelOpenFailureResourceShortage {
		t.Errorf("ReasonCode = %d, want %d", target.ReasonCode, ChannelOpenFailureResourceShortage)
	}
	if target.Description != original.Description {
		t.Error("Description not preserved")
	}
}

// --- ChannelWindowAdjustMessage ---

func TestChannelWindowAdjustMessageMinimalFields(t *testing.T) {
	original := &ChannelWindowAdjustMessage{RecipientChannel: 0, BytesToAdd: 0}
	target := &ChannelWindowAdjustMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != 0 || target.BytesToAdd != 0 {
		t.Error("fields should be 0")
	}
}

func TestChannelWindowAdjustMessageMaximalFields(t *testing.T) {
	original := &ChannelWindowAdjustMessage{
		RecipientChannel: math.MaxUint32,
		BytesToAdd:       math.MaxUint32,
	}
	target := &ChannelWindowAdjustMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
	if target.BytesToAdd != math.MaxUint32 {
		t.Errorf("BytesToAdd = %d, want max", target.BytesToAdd)
	}
}

// --- ChannelDataMessage ---

func TestChannelDataMessageMinimalFields(t *testing.T) {
	original := &ChannelDataMessage{RecipientChannel: 0, Data: []byte{}}
	target := &ChannelDataMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != 0 {
		t.Errorf("RecipientChannel = %d, want 0", target.RecipientChannel)
	}
	if len(target.Data) != 0 {
		t.Errorf("Data length = %d, want 0", len(target.Data))
	}
}

func TestChannelDataMessageMaximalFields(t *testing.T) {
	data := make([]byte, 32768)
	for i := range data {
		data[i] = byte(i % 256)
	}
	original := &ChannelDataMessage{RecipientChannel: math.MaxUint32, Data: data}
	target := &ChannelDataMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
	assertByteSlice(t, "Data", target.Data, data)
}

// --- ChannelExtendedDataMessage ---

func TestChannelExtendedDataMessageMinimalFields(t *testing.T) {
	original := &ChannelExtendedDataMessage{
		RecipientChannel: 0,
		DataTypeCode:     0,
		Data:             []byte{},
	}
	target := &ChannelExtendedDataMessage{}
	roundTrip(t, original, target)
	if target.DataTypeCode != 0 {
		t.Errorf("DataTypeCode = %d, want 0", target.DataTypeCode)
	}
}

func TestChannelExtendedDataMessageMaximalFields(t *testing.T) {
	original := &ChannelExtendedDataMessage{
		RecipientChannel: math.MaxUint32,
		DataTypeCode:     1, // SSH_EXTENDED_DATA_STDERR
		Data:             []byte("error output data here"),
	}
	target := &ChannelExtendedDataMessage{}
	roundTrip(t, original, target)
	if target.DataTypeCode != 1 {
		t.Errorf("DataTypeCode = %d, want 1", target.DataTypeCode)
	}
	assertByteSlice(t, "Data", target.Data, original.Data)
}

// --- ChannelEofMessage ---

func TestChannelEofMessageMinimalFields(t *testing.T) {
	original := &ChannelEofMessage{RecipientChannel: 0}
	target := &ChannelEofMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != 0 {
		t.Errorf("RecipientChannel = %d, want 0", target.RecipientChannel)
	}
}

func TestChannelEofMessageMaximalFields(t *testing.T) {
	original := &ChannelEofMessage{RecipientChannel: math.MaxUint32}
	target := &ChannelEofMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
}

// --- ChannelCloseMessage ---

func TestChannelCloseMessageMinimalFields(t *testing.T) {
	original := &ChannelCloseMessage{RecipientChannel: 0}
	target := &ChannelCloseMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != 0 {
		t.Errorf("RecipientChannel = %d, want 0", target.RecipientChannel)
	}
}

func TestChannelCloseMessageMaximalFields(t *testing.T) {
	original := &ChannelCloseMessage{RecipientChannel: math.MaxUint32}
	target := &ChannelCloseMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
}

// --- ChannelRequestMessage ---

func TestChannelRequestMessageMinimalFields(t *testing.T) {
	original := &ChannelRequestMessage{
		RecipientChannel: 0,
		RequestType:      "",
		WantReply:        false,
	}
	target := &ChannelRequestMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != 0 {
		t.Errorf("RecipientChannel = %d, want 0", target.RecipientChannel)
	}
	if target.RequestType != "" {
		t.Errorf("RequestType = %q, want empty", target.RequestType)
	}
	if target.WantReply {
		t.Error("WantReply should be false")
	}
}

func TestChannelRequestMessageMaximalFields(t *testing.T) {
	original := &ChannelRequestMessage{
		RecipientChannel: math.MaxUint32,
		RequestType:      "subsystem",
		WantReply:        true,
	}
	target := &ChannelRequestMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
	if target.RequestType != "subsystem" {
		t.Errorf("RequestType = %q, want %q", target.RequestType, "subsystem")
	}
	if !target.WantReply {
		t.Error("WantReply should be true")
	}
}

// --- ChannelSignalMessage ---

func TestChannelSignalMessageMinimalFields(t *testing.T) {
	original := &ChannelSignalMessage{
		RecipientChannel: 0,
		RequestType:      "exit-status",
		WantReply:        false,
		ExitStatus:       0,
	}
	target := &ChannelSignalMessage{}
	roundTrip(t, original, target)
	if target.ExitStatus != 0 {
		t.Errorf("ExitStatus = %d, want 0", target.ExitStatus)
	}
}

func TestChannelSignalMessageMaximalFields(t *testing.T) {
	original := &ChannelSignalMessage{
		RecipientChannel: math.MaxUint32,
		RequestType:      "exit-signal",
		WantReply:        true,
		ExitSignal:       "KILL",
		ErrorMessage:     "process was killed",
	}
	target := &ChannelSignalMessage{}
	roundTrip(t, original, target)
	if target.ExitSignal != "KILL" {
		t.Errorf("ExitSignal = %q, want %q", target.ExitSignal, "KILL")
	}
	if target.ErrorMessage != "process was killed" {
		t.Errorf("ErrorMessage = %q, want %q", target.ErrorMessage, "process was killed")
	}
}

// --- ChannelSuccessMessage ---

func TestChannelSuccessMessageMinimalFields(t *testing.T) {
	original := &ChannelSuccessMessage{RecipientChannel: 0}
	target := &ChannelSuccessMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != 0 {
		t.Errorf("RecipientChannel = %d, want 0", target.RecipientChannel)
	}
}

func TestChannelSuccessMessageMaximalFields(t *testing.T) {
	original := &ChannelSuccessMessage{RecipientChannel: math.MaxUint32}
	target := &ChannelSuccessMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
}

// --- ChannelFailureMessage ---

func TestChannelFailureMessageMinimalFields(t *testing.T) {
	original := &ChannelFailureMessage{RecipientChannel: 0}
	target := &ChannelFailureMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != 0 {
		t.Errorf("RecipientChannel = %d, want 0", target.RecipientChannel)
	}
}

func TestChannelFailureMessageMaximalFields(t *testing.T) {
	original := &ChannelFailureMessage{RecipientChannel: math.MaxUint32}
	target := &ChannelFailureMessage{}
	roundTrip(t, original, target)
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
}

// --- KeyExchangeInitMessage ---

func TestKeyExchangeInitMessageMinimalFields(t *testing.T) {
	original := &KeyExchangeInitMessage{
		Cookie:                                 [16]byte{},
		KeyExchangeAlgorithms:                  nil,
		ServerHostKeyAlgorithms:                nil,
		EncryptionAlgorithmsClientToServer:     nil,
		EncryptionAlgorithmsServerToClient:     nil,
		MacAlgorithmsClientToServer:            nil,
		MacAlgorithmsServerToClient:            nil,
		CompressionAlgorithmsClientToServer:    nil,
		CompressionAlgorithmsServerToClient:    nil,
		LanguagesClientToServer:                nil,
		LanguagesServerToClient:                nil,
		FirstKexPacketFollows:                  false,
		Reserved:                               0,
	}
	target := &KeyExchangeInitMessage{}
	roundTrip(t, original, target)
	if target.FirstKexPacketFollows {
		t.Error("FirstKexPacketFollows should be false")
	}
}

func TestKeyExchangeInitMessageMaximalFields(t *testing.T) {
	cookie := [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	original := &KeyExchangeInitMessage{
		Cookie:                                 cookie,
		KeyExchangeAlgorithms:                  []string{"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "diffie-hellman-group14-sha256"},
		ServerHostKeyAlgorithms:                []string{"ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512"},
		EncryptionAlgorithmsClientToServer:     []string{"aes256-gcm@openssh.com", "aes256-ctr", "aes256-cbc"},
		EncryptionAlgorithmsServerToClient:     []string{"aes256-gcm@openssh.com", "aes256-ctr"},
		MacAlgorithmsClientToServer:            []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512"},
		MacAlgorithmsServerToClient:            []string{"hmac-sha2-256-etm@openssh.com"},
		CompressionAlgorithmsClientToServer:    []string{"none", "zlib@openssh.com"},
		CompressionAlgorithmsServerToClient:    []string{"none"},
		LanguagesClientToServer:                []string{"en"},
		LanguagesServerToClient:                []string{"en", "de"},
		FirstKexPacketFollows:                  true,
		Reserved:                               math.MaxUint32,
	}
	target := &KeyExchangeInitMessage{}
	roundTrip(t, original, target)
	if target.Cookie != cookie {
		t.Error("Cookie not preserved")
	}
	assertStringSlice(t, "KeyExchangeAlgorithms", target.KeyExchangeAlgorithms, original.KeyExchangeAlgorithms)
	assertStringSlice(t, "ServerHostKeyAlgorithms", target.ServerHostKeyAlgorithms, original.ServerHostKeyAlgorithms)
	assertStringSlice(t, "EncryptionAlgorithmsClientToServer", target.EncryptionAlgorithmsClientToServer, original.EncryptionAlgorithmsClientToServer)
	assertStringSlice(t, "EncryptionAlgorithmsServerToClient", target.EncryptionAlgorithmsServerToClient, original.EncryptionAlgorithmsServerToClient)
	assertStringSlice(t, "MacAlgorithmsClientToServer", target.MacAlgorithmsClientToServer, original.MacAlgorithmsClientToServer)
	assertStringSlice(t, "MacAlgorithmsServerToClient", target.MacAlgorithmsServerToClient, original.MacAlgorithmsServerToClient)
	assertStringSlice(t, "CompressionAlgorithmsClientToServer", target.CompressionAlgorithmsClientToServer, original.CompressionAlgorithmsClientToServer)
	assertStringSlice(t, "CompressionAlgorithmsServerToClient", target.CompressionAlgorithmsServerToClient, original.CompressionAlgorithmsServerToClient)
	assertStringSlice(t, "LanguagesClientToServer", target.LanguagesClientToServer, original.LanguagesClientToServer)
	assertStringSlice(t, "LanguagesServerToClient", target.LanguagesServerToClient, original.LanguagesServerToClient)
	if !target.FirstKexPacketFollows {
		t.Error("FirstKexPacketFollows should be true")
	}
}

// --- NewKeysMessage ---

func TestNewKeysMessageMinimalFields(t *testing.T) {
	original := &NewKeysMessage{}
	target := &NewKeysMessage{}
	roundTrip(t, original, target)
}

func TestNewKeysMessageMaximalFields(t *testing.T) {
	original := &NewKeysMessage{}
	target := &NewKeysMessage{}
	roundTrip(t, original, target)
}

// --- KeyExchangeDhInitMessage ---

func TestKeyExchangeDhInitMessageMinimalFields(t *testing.T) {
	original := &KeyExchangeDhInitMessage{E: big.NewInt(0)}
	target := &KeyExchangeDhInitMessage{}
	roundTrip(t, original, target)
	if target.E.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("E = %v, want 0", target.E)
	}
}

func TestKeyExchangeDhInitMessageMaximalFields(t *testing.T) {
	// Use a large number to test big.Int serialization.
	e := new(big.Int)
	e.SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234", 16)
	original := &KeyExchangeDhInitMessage{E: e}
	target := &KeyExchangeDhInitMessage{}
	roundTrip(t, original, target)
	if target.E.Cmp(e) != 0 {
		t.Errorf("E = %v, want %v", target.E, e)
	}
}

// --- KeyExchangeDhReplyMessage ---

func TestKeyExchangeDhReplyMessageMinimalFields(t *testing.T) {
	original := &KeyExchangeDhReplyMessage{
		HostKey:   []byte{},
		F:         big.NewInt(0),
		Signature: []byte{},
	}
	target := &KeyExchangeDhReplyMessage{}
	roundTrip(t, original, target)
	if len(target.HostKey) != 0 {
		t.Errorf("HostKey length = %d, want 0", len(target.HostKey))
	}
	if len(target.Signature) != 0 {
		t.Errorf("Signature length = %d, want 0", len(target.Signature))
	}
}

func TestKeyExchangeDhReplyMessageMaximalFields(t *testing.T) {
	hostKey := make([]byte, 256)
	for i := range hostKey {
		hostKey[i] = byte(i % 256)
	}
	sig := make([]byte, 128)
	for i := range sig {
		sig[i] = byte(0xFF - byte(i%256))
	}
	f := new(big.Int)
	f.SetString("DEADBEEFCAFEBABE0123456789ABCDEF", 16)
	original := &KeyExchangeDhReplyMessage{
		HostKey:   hostKey,
		F:         f,
		Signature: sig,
	}
	target := &KeyExchangeDhReplyMessage{}
	roundTrip(t, original, target)
	assertByteSlice(t, "HostKey", target.HostKey, hostKey)
	if target.F.Cmp(f) != 0 {
		t.Errorf("F = %v, want %v", target.F, f)
	}
	assertByteSlice(t, "Signature", target.Signature, sig)
}

// --- SessionReconnectRequestMessage ---

func TestSessionReconnectRequestMessageMinimalFields(t *testing.T) {
	original := &SessionReconnectRequestMessage{
		RequestType:                "ssh-reconnect@ms.com",
		WantReply:                  true,
		ClientReconnectToken:       []byte{},
		LastReceivedSequenceNumber: 0,
	}
	target := &SessionReconnectRequestMessage{}
	roundTrip(t, original, target)
	if len(target.ClientReconnectToken) != 0 {
		t.Errorf("ClientReconnectToken length = %d, want 0", len(target.ClientReconnectToken))
	}
	if target.LastReceivedSequenceNumber != 0 {
		t.Errorf("LastReceivedSequenceNumber = %d, want 0", target.LastReceivedSequenceNumber)
	}
}

func TestSessionReconnectRequestMessageMaximalFields(t *testing.T) {
	token := make([]byte, 64)
	for i := range token {
		token[i] = byte(i)
	}
	original := &SessionReconnectRequestMessage{
		RequestType:                "ssh-reconnect@ms.com",
		WantReply:                  true,
		ClientReconnectToken:       token,
		LastReceivedSequenceNumber: math.MaxUint64,
	}
	target := &SessionReconnectRequestMessage{}
	roundTrip(t, original, target)
	assertByteSlice(t, "ClientReconnectToken", target.ClientReconnectToken, token)
	if target.LastReceivedSequenceNumber != math.MaxUint64 {
		t.Errorf("LastReceivedSequenceNumber = %d, want max", target.LastReceivedSequenceNumber)
	}
}

// --- SessionReconnectResponseMessage ---

func TestSessionReconnectResponseMessageMinimalFields(t *testing.T) {
	original := &SessionReconnectResponseMessage{
		ServerReconnectToken:        []byte{},
		LastReceivedSequenceNumber: 0,
	}
	target := &SessionReconnectResponseMessage{}
	roundTrip(t, original, target)
	if len(target.ServerReconnectToken) != 0 {
		t.Errorf("ServerReconnectToken length = %d, want 0", len(target.ServerReconnectToken))
	}
}

func TestSessionReconnectResponseMessageMaximalFields(t *testing.T) {
	token := make([]byte, 64)
	for i := range token {
		token[i] = byte(0xFF - byte(i%256))
	}
	original := &SessionReconnectResponseMessage{
		ServerReconnectToken:        token,
		LastReceivedSequenceNumber: math.MaxUint64,
	}
	target := &SessionReconnectResponseMessage{}
	roundTrip(t, original, target)
	assertByteSlice(t, "ServerReconnectToken", target.ServerReconnectToken, token)
	if target.LastReceivedSequenceNumber != math.MaxUint64 {
		t.Errorf("LastReceivedSequenceNumber = %d, want max", target.LastReceivedSequenceNumber)
	}
}

// --- SessionReconnectFailureMessage ---

func TestSessionReconnectFailureMessageMinimalFields(t *testing.T) {
	original := &SessionReconnectFailureMessage{
		ReasonCode:  0,
		Description: "",
		Language:    "",
	}
	target := &SessionReconnectFailureMessage{}
	roundTrip(t, original, target)
	if target.ReasonCode != 0 {
		t.Errorf("ReasonCode = %d, want 0", target.ReasonCode)
	}
}

func TestSessionReconnectFailureMessageMaximalFields(t *testing.T) {
	original := &SessionReconnectFailureMessage{
		ReasonCode:  SSHReconnectFailureReason(math.MaxUint32),
		Description: "session not found on server",
		Language:    "en",
	}
	target := &SessionReconnectFailureMessage{}
	roundTrip(t, original, target)
	if target.ReasonCode != SSHReconnectFailureReason(math.MaxUint32) {
		t.Errorf("ReasonCode = %d, want max", target.ReasonCode)
	}
	if target.Description != original.Description {
		t.Errorf("Description = %q, want %q", target.Description, original.Description)
	}
	if target.Language != "en" {
		t.Errorf("Language = %q, want %q", target.Language, "en")
	}
}

// --- CommandRequestMessage ---

func TestCommandRequestMessageMinimalFields(t *testing.T) {
	original := &CommandRequestMessage{
		RecipientChannel: 0,
		RequestType:      "exec",
		WantReply:        false,
		Command:          "",
	}
	target := &CommandRequestMessage{}
	roundTrip(t, original, target)
	if target.Command != "" {
		t.Errorf("Command = %q, want empty", target.Command)
	}
}

func TestCommandRequestMessageMaximalFields(t *testing.T) {
	original := &CommandRequestMessage{
		RecipientChannel: math.MaxUint32,
		RequestType:      "exec",
		WantReply:        true,
		Command:          strings.Repeat("/usr/bin/command ", 64),
	}
	target := &CommandRequestMessage{}
	roundTrip(t, original, target)
	if target.Command != original.Command {
		t.Error("Command not preserved")
	}
	if target.RecipientChannel != math.MaxUint32 {
		t.Errorf("RecipientChannel = %d, want max", target.RecipientChannel)
	}
}
