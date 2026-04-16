// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"strings"
	"testing"
)

func TestParseLibraryFormat(t *testing.T) {
	v := ParseVersionInfo("SSH-2.0-dev-tunnels-ssh_1.2")
	if v == nil {
		t.Fatal("expected successful parse")
	}
	if v.ProtocolVersion != "2.0" {
		t.Errorf("expected protocol version 2.0, got %s", v.ProtocolVersion)
	}
	if v.Name != "dev-tunnels-ssh" {
		t.Errorf("expected name 'dev-tunnels-ssh', got %q", v.Name)
	}
	if v.Version != "1.2" {
		t.Errorf("expected version '1.2', got %q", v.Version)
	}
}

func TestParseCSharpFormat(t *testing.T) {
	v := ParseVersionInfo("SSH-2.0-Microsoft.DevTunnels.Ssh_3.10")
	if v == nil {
		t.Fatal("expected successful parse")
	}
	if v.Name != "Microsoft.DevTunnels.Ssh" {
		t.Errorf("expected name 'Microsoft.DevTunnels.Ssh', got %q", v.Name)
	}
	if v.Version != "3.10" {
		t.Errorf("expected version '3.10', got %q", v.Version)
	}
}

func TestParseOpenSSHFormat(t *testing.T) {
	v := ParseVersionInfo("SSH-2.0-OpenSSH_7.9")
	if v == nil {
		t.Fatal("expected successful parse")
	}
	if v.Name != "OpenSSH" {
		t.Errorf("expected name 'OpenSSH', got %q", v.Name)
	}
	if v.Version != "7.9" {
		t.Errorf("expected version '7.9', got %q", v.Version)
	}
}

func TestParseOpenSSHWindowsFormat(t *testing.T) {
	v := ParseVersionInfo("SSH-2.0-OpenSSH_for_Windows_8.1")
	if v == nil {
		t.Fatal("expected successful parse")
	}
	if v.Name != "OpenSSH for Windows" {
		t.Errorf("expected name 'OpenSSH for Windows', got %q", v.Name)
	}
	if v.Version != "8.1" {
		t.Errorf("expected version '8.1', got %q", v.Version)
	}
}

func TestParseMinimalFormat(t *testing.T) {
	v := ParseVersionInfo("SSH-2.0-test")
	if v == nil {
		t.Fatal("expected successful parse")
	}
	if v.Name != "test" {
		t.Errorf("expected name 'test', got %q", v.Name)
	}
	if v.Version != "" {
		t.Errorf("expected empty version, got %q", v.Version)
	}
}

func TestParseExtraInfoFormat(t *testing.T) {
	v := ParseVersionInfo("SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2")
	if v == nil {
		t.Fatal("expected successful parse")
	}
	if v.Name != "OpenSSH" {
		t.Errorf("expected name 'OpenSSH', got %q", v.Name)
	}
	if v.Version != "7.9" {
		t.Errorf("expected version '7.9', got %q", v.Version)
	}
}

func TestParseGoLibraryFormat(t *testing.T) {
	v := ParseVersionInfo("SSH-2.0-dev-tunnels-ssh-go_0.1")
	if v == nil {
		t.Fatal("expected successful parse")
	}
	if v.Name != "dev-tunnels-ssh-go" {
		t.Errorf("expected name 'dev-tunnels-ssh-go', got %q", v.Name)
	}
	if v.Version != "0.1" {
		t.Errorf("expected version '0.1', got %q", v.Version)
	}
	if !v.IsDevTunnelsSSH() {
		t.Error("expected IsDevTunnelsSSH to be true for Go library")
	}
}

func TestParseInvalidFormat(t *testing.T) {
	tests := []string{
		"",
		"not-ssh",
		"SSH-abc-test",
		"SSH-test",
		"HTTP-2.0-test",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			v := ParseVersionInfo(input)
			if v != nil {
				t.Errorf("expected nil for invalid input %q, got %+v", input, v)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	input := "SSH-2.0-OpenSSH_7.9"
	v := ParseVersionInfo(input)
	if v == nil {
		t.Fatal("expected successful parse")
	}
	if v.String() != input {
		t.Errorf("expected String() to return %q, got %q", input, v.String())
	}
}

func TestGetLocalVersion(t *testing.T) {
	v := GetLocalVersion()
	if v == nil {
		t.Fatal("expected non-nil local version")
	}
	if v.ProtocolVersion != "2.0" {
		t.Errorf("expected protocol version 2.0, got %s", v.ProtocolVersion)
	}
	if v.Name != "dev-tunnels-ssh-go" {
		t.Errorf("expected name 'dev-tunnels-ssh-go', got %q", v.Name)
	}
	if v.Version != "0.1" {
		t.Errorf("expected version '0.1', got %q", v.Version)
	}
	if !strings.HasPrefix(v.String(), "SSH-2.0-") {
		t.Errorf("expected version string to start with SSH-2.0-, got %q", v.String())
	}
	if !v.IsDevTunnelsSSH() {
		t.Error("expected IsDevTunnelsSSH to be true")
	}
}

func TestIsDevTunnelsSSH(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"SSH-2.0-Microsoft.DevTunnels.Ssh_3.10", true},
		{"SSH-2.0-Microsoft.VisualStudio.Ssh_1.0", true},
		{"SSH-2.0-dev-tunnels-ssh_1.0", true},
		{"SSH-2.0-vs-ssh_1.0", true},
		{"SSH-2.0-dev-tunnels-ssh-go_0.1", true},
		{"SSH-2.0-OpenSSH_7.9", false},
		{"SSH-2.0-other_1.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			v := ParseVersionInfo(tt.input)
			if v == nil {
				t.Fatal("expected successful parse")
			}
			if v.IsDevTunnelsSSH() != tt.expected {
				t.Errorf("IsDevTunnelsSSH() = %v, expected %v", v.IsDevTunnelsSSH(), tt.expected)
			}
		})
	}
}

func TestParseRoundTrip(t *testing.T) {
	local := GetLocalVersion()
	parsed := ParseVersionInfo(local.String())
	if parsed == nil {
		t.Fatal("expected successful parse of local version string")
	}
	if parsed.Name != local.Name {
		t.Errorf("expected name %q, got %q", local.Name, parsed.Name)
	}
	if parsed.Version != local.Version {
		t.Errorf("expected version %q, got %q", local.Version, parsed.Version)
	}
}
