// Copyright (c) Microsoft Corporation. All rights reserved.

package messages

import (
	"math/big"
	"testing"
)

// --- KeyExchangeInitMessage tests ---

func TestKeyExchangeInitMessageRoundTrip(t *testing.T) {
	original := &KeyExchangeInitMessage{
		Cookie: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		KeyExchangeAlgorithms:               []string{"diffie-hellman-group14-sha256", "ecdh-sha2-nistp256"},
		ServerHostKeyAlgorithms:             []string{"rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256"},
		EncryptionAlgorithmsClientToServer:  []string{"aes256-ctr", "aes256-gcm@openssh.com"},
		EncryptionAlgorithmsServerToClient:  []string{"aes256-ctr", "aes256-gcm@openssh.com"},
		MacAlgorithmsClientToServer:         []string{"hmac-sha2-256", "hmac-sha2-512"},
		MacAlgorithmsServerToClient:         []string{"hmac-sha2-256", "hmac-sha2-512"},
		CompressionAlgorithmsClientToServer: []string{"none"},
		CompressionAlgorithmsServerToClient: []string{"none"},
		LanguagesClientToServer:             []string{},
		LanguagesServerToClient:             []string{},
		FirstKexPacketFollows:               false,
		Reserved:                            0,
	}
	target := &KeyExchangeInitMessage{}
	roundTrip(t, original, target)

	if target.Cookie != original.Cookie {
		t.Errorf("Cookie = %v, want %v", target.Cookie, original.Cookie)
	}
	assertStringSlice(t, "KeyExchangeAlgorithms", target.KeyExchangeAlgorithms, original.KeyExchangeAlgorithms)
	assertStringSlice(t, "ServerHostKeyAlgorithms", target.ServerHostKeyAlgorithms, original.ServerHostKeyAlgorithms)
	assertStringSlice(t, "EncryptionAlgorithmsClientToServer", target.EncryptionAlgorithmsClientToServer, original.EncryptionAlgorithmsClientToServer)
	assertStringSlice(t, "EncryptionAlgorithmsServerToClient", target.EncryptionAlgorithmsServerToClient, original.EncryptionAlgorithmsServerToClient)
	assertStringSlice(t, "MacAlgorithmsClientToServer", target.MacAlgorithmsClientToServer, original.MacAlgorithmsClientToServer)
	assertStringSlice(t, "MacAlgorithmsServerToClient", target.MacAlgorithmsServerToClient, original.MacAlgorithmsServerToClient)
	assertStringSlice(t, "CompressionAlgorithmsClientToServer", target.CompressionAlgorithmsClientToServer, original.CompressionAlgorithmsClientToServer)
	assertStringSlice(t, "CompressionAlgorithmsServerToClient", target.CompressionAlgorithmsServerToClient, original.CompressionAlgorithmsServerToClient)
	if target.FirstKexPacketFollows != false {
		t.Error("FirstKexPacketFollows should be false")
	}
	if target.Reserved != 0 {
		t.Errorf("Reserved = %d, want 0", target.Reserved)
	}
}

func TestKeyExchangeInitMessageType(t *testing.T) {
	m := &KeyExchangeInitMessage{}
	if m.MessageType() != 20 {
		t.Errorf("MessageType() = %d, want 20", m.MessageType())
	}
}

func TestKeyExchangeInitMessageFirstKexFollows(t *testing.T) {
	original := &KeyExchangeInitMessage{
		KeyExchangeAlgorithms:               []string{"diffie-hellman-group14-sha256"},
		ServerHostKeyAlgorithms:             []string{"rsa-sha2-256"},
		EncryptionAlgorithmsClientToServer:  []string{"aes256-ctr"},
		EncryptionAlgorithmsServerToClient:  []string{"aes256-ctr"},
		MacAlgorithmsClientToServer:         []string{"hmac-sha2-256"},
		MacAlgorithmsServerToClient:         []string{"hmac-sha2-256"},
		CompressionAlgorithmsClientToServer: []string{"none"},
		CompressionAlgorithmsServerToClient: []string{"none"},
		LanguagesClientToServer:             []string{},
		LanguagesServerToClient:             []string{},
		FirstKexPacketFollows:               true,
		Reserved:                            0,
	}
	target := &KeyExchangeInitMessage{}
	roundTrip(t, original, target)

	if target.FirstKexPacketFollows != true {
		t.Error("FirstKexPacketFollows should be true")
	}
}

func TestKeyExchangeInitMessageEmptyLists(t *testing.T) {
	original := &KeyExchangeInitMessage{
		KeyExchangeAlgorithms:               []string{},
		ServerHostKeyAlgorithms:             []string{},
		EncryptionAlgorithmsClientToServer:  []string{},
		EncryptionAlgorithmsServerToClient:  []string{},
		MacAlgorithmsClientToServer:         []string{},
		MacAlgorithmsServerToClient:         []string{},
		CompressionAlgorithmsClientToServer: []string{},
		CompressionAlgorithmsServerToClient: []string{},
		LanguagesClientToServer:             []string{},
		LanguagesServerToClient:             []string{},
	}
	target := &KeyExchangeInitMessage{}
	roundTrip(t, original, target)

	assertStringSlice(t, "KeyExchangeAlgorithms", target.KeyExchangeAlgorithms, []string{})
	assertStringSlice(t, "ServerHostKeyAlgorithms", target.ServerHostKeyAlgorithms, []string{})
}

func TestKeyExchangeInitMessageCookiePreserved(t *testing.T) {
	cookie := [16]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
		0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0}
	original := &KeyExchangeInitMessage{
		Cookie:                              cookie,
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
	target := &KeyExchangeInitMessage{}
	roundTrip(t, original, target)

	if target.Cookie != cookie {
		t.Errorf("Cookie = %v, want %v", target.Cookie, cookie)
	}
}

// --- NewKeysMessage tests ---

func TestNewKeysMessageRoundTrip(t *testing.T) {
	original := &NewKeysMessage{}
	target := &NewKeysMessage{}
	roundTrip(t, original, target)
}

func TestNewKeysMessageType(t *testing.T) {
	m := &NewKeysMessage{}
	if m.MessageType() != 21 {
		t.Errorf("MessageType() = %d, want 21", m.MessageType())
	}
}

func TestNewKeysMessageBufferSize(t *testing.T) {
	m := &NewKeysMessage{}
	buf := m.ToBuffer()
	if len(buf) != 1 {
		t.Errorf("buffer length = %d, want 1", len(buf))
	}
}

// --- KeyExchangeDhInitMessage tests ---

func TestKeyExchangeDhInitMessageRoundTrip(t *testing.T) {
	e := new(big.Int).SetBytes([]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	})
	original := &KeyExchangeDhInitMessage{E: e}
	target := &KeyExchangeDhInitMessage{}
	roundTrip(t, original, target)

	if target.E.Cmp(e) != 0 {
		t.Errorf("E = %v, want %v", target.E, e)
	}
}

func TestKeyExchangeDhInitMessageType(t *testing.T) {
	m := &KeyExchangeDhInitMessage{}
	if m.MessageType() != 30 {
		t.Errorf("MessageType() = %d, want 30", m.MessageType())
	}
}

func TestKeyExchangeDhInitMessageLargeValue(t *testing.T) {
	// Simulate a 2048-bit DH public value
	bytes := make([]byte, 256)
	bytes[0] = 0x7F // Ensure no leading-zero issue
	for i := 1; i < len(bytes); i++ {
		bytes[i] = byte(i & 0xFF)
	}
	e := new(big.Int).SetBytes(bytes)
	original := &KeyExchangeDhInitMessage{E: e}
	target := &KeyExchangeDhInitMessage{}
	roundTrip(t, original, target)

	if target.E.Cmp(e) != 0 {
		t.Errorf("E value mismatch for large DH value")
	}
}

func TestKeyExchangeDhInitMessageZero(t *testing.T) {
	original := &KeyExchangeDhInitMessage{E: new(big.Int)}
	target := &KeyExchangeDhInitMessage{}
	roundTrip(t, original, target)

	if target.E.Cmp(new(big.Int)) != 0 {
		t.Errorf("E = %v, want 0", target.E)
	}
}

// --- KeyExchangeDhReplyMessage tests ---

func TestKeyExchangeDhReplyMessageRoundTrip(t *testing.T) {
	hostKey := []byte{0x00, 0x00, 0x00, 0x07, 's', 's', 'h', '-', 'r', 's', 'a', 0x01, 0x02}
	f := new(big.Int).SetBytes([]byte{0xAB, 0xCD, 0xEF, 0x01, 0x23})
	signature := []byte{0x00, 0x00, 0x00, 0x0C, 'r', 's', 'a', '-', 's', 'h', 'a', '2', '-', '2', '5', '6', 0xDE, 0xAD}

	original := &KeyExchangeDhReplyMessage{
		HostKey:   hostKey,
		F:         f,
		Signature: signature,
	}
	target := &KeyExchangeDhReplyMessage{}
	roundTrip(t, original, target)

	assertByteSlice(t, "HostKey", target.HostKey, hostKey)
	if target.F.Cmp(f) != 0 {
		t.Errorf("F = %v, want %v", target.F, f)
	}
	assertByteSlice(t, "Signature", target.Signature, signature)
}

func TestKeyExchangeDhReplyMessageType(t *testing.T) {
	m := &KeyExchangeDhReplyMessage{}
	if m.MessageType() != 31 {
		t.Errorf("MessageType() = %d, want 31", m.MessageType())
	}
}

func TestKeyExchangeDhReplyMessageEmptyHostKey(t *testing.T) {
	original := &KeyExchangeDhReplyMessage{
		HostKey:   []byte{},
		F:         big.NewInt(42),
		Signature: []byte{},
	}
	target := &KeyExchangeDhReplyMessage{}
	roundTrip(t, original, target)

	if len(target.HostKey) != 0 {
		t.Errorf("HostKey length = %d, want 0", len(target.HostKey))
	}
	if target.F.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("F = %v, want 42", target.F)
	}
	if len(target.Signature) != 0 {
		t.Errorf("Signature length = %d, want 0", len(target.Signature))
	}
}

// --- Wire format tests for KEX messages ---

func TestKeyExchangeInitMessageWireFormat(t *testing.T) {
	m := &KeyExchangeInitMessage{
		Cookie:                              [16]byte{0xAA, 0xBB},
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
		FirstKexPacketFollows:               false,
		Reserved:                            0,
	}
	buf := m.ToBuffer()

	// First byte must be message type 20
	if buf[0] != 20 {
		t.Errorf("buf[0] = %d, want 20", buf[0])
	}
	// Next 16 bytes are the cookie
	if buf[1] != 0xAA || buf[2] != 0xBB {
		t.Errorf("cookie first two bytes = %02x %02x, want AA BB", buf[1], buf[2])
	}
}

func TestNewKeysMessageWireFormat(t *testing.T) {
	m := &NewKeysMessage{}
	buf := m.ToBuffer()

	if len(buf) != 1 {
		t.Fatalf("buffer length = %d, want 1", len(buf))
	}
	if buf[0] != 21 {
		t.Errorf("buf[0] = %d, want 21", buf[0])
	}
}

// --- helper functions ---

func assertStringSlice(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s length = %d, want %d", name, len(got), len(want))
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", name, i, got[i], want[i])
		}
	}
}

func assertByteSlice(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s length = %d, want %d", name, len(got), len(want))
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %d, want %d", name, i, got[i], want[i])
			return
		}
	}
}
