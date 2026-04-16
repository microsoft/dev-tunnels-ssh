// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"testing"
)

func TestAuthenticationTypeValues(t *testing.T) {
	// Verify enum values match C#/TS exactly.
	tests := []struct {
		name  string
		value AuthenticationType
		want  int
	}{
		{"ClientNone", AuthClientNone, 0},
		{"ClientHostBased", AuthClientHostBased, 1},
		{"ClientPassword", AuthClientPassword, 2},
		{"ClientPublicKeyQuery", AuthClientPublicKeyQuery, 3},
		{"ClientPublicKey", AuthClientPublicKey, 4},
		{"ClientInteractive", AuthClientInteractive, 5},
		{"ServerPublicKey", AuthServerPublicKey, 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.value) != tt.want {
				t.Errorf("%s: expected %d, got %d", tt.name, tt.want, int(tt.value))
			}
		})
	}
}

func TestAuthenticationTypeDistinct(t *testing.T) {
	values := []AuthenticationType{
		AuthClientNone,
		AuthClientHostBased,
		AuthClientPassword,
		AuthClientPublicKeyQuery,
		AuthClientPublicKey,
		AuthClientInteractive,
		AuthServerPublicKey,
	}
	seen := make(map[AuthenticationType]bool)
	for _, v := range values {
		if seen[v] {
			t.Errorf("duplicate AuthenticationType value: %d", v)
		}
		seen[v] = true
	}
}
