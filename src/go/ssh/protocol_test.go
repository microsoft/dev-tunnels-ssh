// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/algorithms"
)

// duplexPipe creates a pair of connected ReadWriteClosers for testing.
func duplexPipe() (io.ReadWriteCloser, io.ReadWriteCloser) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &pipeRWC{r: r1, w: w2}, &pipeRWC{r: r2, w: w1}
}

type pipeRWC struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipeRWC) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeRWC) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeRWC) Close() error {
	p.r.Close()
	return p.w.Close()
}

// createCipherPair creates matching encrypt/decrypt cipher instances for testing.
func createCipherPair(t *testing.T, algo *algorithms.EncryptionAlgorithm) (algorithms.Cipher, algorithms.Cipher) {
	t.Helper()
	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 100)
	}
	enc, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatalf("failed to create encrypt cipher: %v", err)
	}
	dec, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatalf("failed to create decrypt cipher: %v", err)
	}
	return enc, dec
}

// createHmacPair creates matching signer/verifier instances for testing.
func createHmacPair(algo *algorithms.HmacAlgorithm) (algorithms.MessageSigner, algorithms.MessageVerifier) {
	key := make([]byte, algo.KeyLength)
	for i := range key {
		key[i] = byte(i + 50)
	}
	return algo.CreateSigner(key), algo.CreateVerifier(key)
}

func TestProtocolPlaintextRoundTrip(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	payload := []byte{0x05, 0x01, 0x02, 0x03} // type byte + data

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}

	if p1.SendSequence != 1 {
		t.Errorf("sender sequence = %d, want 1", p1.SendSequence)
	}
	if atomic.LoadUint64(&p2.ReceiveSequence) != 1 {
		t.Errorf("receiver sequence = %d, want 1", atomic.LoadUint64(&p2.ReceiveSequence))
	}
}

func TestProtocolAesCtrHmacSha256RoundTrip(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())

	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	payload := []byte{0x15, 0xAA, 0xBB, 0xCC, 0xDD}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}
}

func TestProtocolAesCtrHmacSha512RoundTrip(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha512())

	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	payload := []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}
}

func TestProtocolAesCbcHmacSha256RoundTrip(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	enc, dec := createCipherPair(t, algorithms.NewAes256Cbc())
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())

	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	payload := []byte{0x15, 0x01, 0x02, 0x03, 0x04, 0x05}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}
}

func TestProtocolEtmHmacSha256RoundTrip(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha256Etm())

	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	payload := []byte{0x15, 0xAA, 0xBB, 0xCC, 0xDD}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}
}

func TestProtocolEtmHmacSha512RoundTrip(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha512Etm())

	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	payload := []byte{0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}
}

func TestProtocolGcmRoundTrip(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	// GCM: the cipher itself serves as signer/verifier.
	algo := algorithms.NewAes256Gcm()
	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 100)
	}

	encCipher, err := algo.CreateCipher(true, key, iv)
	if err != nil {
		t.Fatalf("failed to create encrypt cipher: %v", err)
	}
	decCipher, err := algo.CreateCipher(false, key, iv)
	if err != nil {
		t.Fatalf("failed to create decrypt cipher: %v", err)
	}

	// GCM cipher implements both Cipher and MessageSigner/MessageVerifier.
	encGcm := encCipher.(*algorithms.AesGcmCipher)
	decGcm := decCipher.(*algorithms.AesGcmCipher)

	p1.SetEncryption(encCipher, nil, encGcm, nil)
	p2.SetEncryption(nil, decCipher, nil, decGcm)

	payload := []byte{0x15, 0xAA, 0xBB, 0xCC, 0xDD}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("payload mismatch: got %v, want %v", received, payload)
	}
}

func TestProtocolMultipleMessagesSequenceTracking(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())

	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	messages := [][]byte{
		{0x01, 0x10},
		{0x02, 0x20, 0x21},
		{0x03, 0x30, 0x31, 0x32},
		{0x04, 0x40, 0x41, 0x42, 0x43},
		{0x05, 0x50, 0x51, 0x52, 0x53, 0x54},
	}

	done := make(chan error, 1)
	go func() {
		for _, msg := range messages {
			if err := p1.sendMessage(msg); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i, expected := range messages {
		received, err := p2.receiveMessage()
		if err != nil {
			t.Fatalf("receiveMessage %d failed: %v", i, err)
		}
		if !bytes.Equal(received, expected) {
			t.Errorf("message %d: got %v, want %v", i, received, expected)
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if p1.SendSequence != 5 {
		t.Errorf("sender sequence = %d, want 5", p1.SendSequence)
	}
	if atomic.LoadUint64(&p2.ReceiveSequence) != 5 {
		t.Errorf("receiver sequence = %d, want 5", atomic.LoadUint64(&p2.ReceiveSequence))
	}
}

func TestProtocolGcmMultipleMessages(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	algo := algorithms.NewAes256Gcm()
	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	for i := range key {
		key[i] = byte(i * 3)
	}
	for i := range iv {
		iv[i] = byte(i * 7)
	}

	encCipher, _ := algo.CreateCipher(true, key, iv)
	decCipher, _ := algo.CreateCipher(false, key, iv)

	encGcm := encCipher.(*algorithms.AesGcmCipher)
	decGcm := decCipher.(*algorithms.AesGcmCipher)

	p1.SetEncryption(encCipher, nil, encGcm, nil)
	p2.SetEncryption(nil, decCipher, nil, decGcm)

	// Send multiple messages to verify GCM nonce increments correctly.
	messages := [][]byte{
		{0x01, 0x10},
		{0x02, 0x20, 0x21},
		{0x03, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E},
	}

	done := make(chan error, 1)
	go func() {
		for _, msg := range messages {
			if err := p1.sendMessage(msg); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i, expected := range messages {
		received, err := p2.receiveMessage()
		if err != nil {
			t.Fatalf("receiveMessage %d failed: %v", i, err)
		}
		if !bytes.Equal(received, expected) {
			t.Errorf("message %d: got %v, want %v", i, received, expected)
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}
}

func TestProtocolEncryptedCiphertextDiffersFromPlaintext(t *testing.T) {
	// Verify that the wire bytes are actually encrypted (differ from plaintext).
	buf := &bufferCloser{}
	p := newSSHProtocol(buf, nil)

	enc, _ := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, _ := createHmacPair(algorithms.NewHmacSha256())
	p.SetEncryption(enc, nil, signer, nil)

	payload := []byte{0x15, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}

	err := p.sendMessage(payload)
	if err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	wireBytes := buf.Bytes()

	// The encrypted packet should not contain the plaintext payload.
	if bytes.Contains(wireBytes, payload) {
		t.Error("wire bytes contain plaintext payload — encryption not working")
	}

	// Wire bytes should not be empty.
	if len(wireBytes) == 0 {
		t.Error("no wire bytes written")
	}
}

// bufferCloser wraps bytes.Buffer to implement io.ReadWriteCloser.
type bufferCloser struct {
	bytes.Buffer
}

func (b *bufferCloser) Close() error { return nil }

func TestProtocolLargePayloadEncrypted(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())

	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	// Create a large payload (just under max packet size).
	payload := make([]byte, 32000)
	payload[0] = 0x15 // message type
	for i := 1; i < len(payload); i++ {
		payload[i] = byte(i & 0xFF)
	}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("large payload mismatch: lengths got=%d want=%d", len(received), len(payload))
	}
}

func TestProtocolEtmLargePayload(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha512Etm())

	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	payload := make([]byte, 16000)
	payload[0] = 0x05
	for i := 1; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("large EtM payload mismatch: lengths got=%d want=%d", len(received), len(payload))
	}
}

func TestProtocolGcmLargePayload(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	algo := algorithms.NewAes256Gcm()
	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	for i := range key {
		key[i] = byte(i + 10)
	}
	for i := range iv {
		iv[i] = byte(i + 200)
	}

	encCipher, _ := algo.CreateCipher(true, key, iv)
	decCipher, _ := algo.CreateCipher(false, key, iv)

	encGcm := encCipher.(*algorithms.AesGcmCipher)
	decGcm := decCipher.(*algorithms.AesGcmCipher)

	p1.SetEncryption(encCipher, nil, encGcm, nil)
	p2.SetEncryption(nil, decCipher, nil, decGcm)

	payload := make([]byte, 8000)
	payload[0] = 0x15
	for i := 1; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessage(payload)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessage failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("large GCM payload mismatch: lengths got=%d want=%d", len(received), len(payload))
	}
}

func TestProtocolVersionStringExchange(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	done := make(chan error, 1)
	go func() {
		done <- p1.writeVersionString("SSH-2.0-test_1.0")
	}()

	version, err := p2.readVersionString()
	if err != nil {
		t.Fatalf("readVersionString failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("writeVersionString failed: %v", err)
	}

	if version != "SSH-2.0-test_1.0" {
		t.Errorf("version = %q, want %q", version, "SSH-2.0-test_1.0")
	}
}

func TestProtocolSetEncryptionNilDisables(t *testing.T) {
	p := newSSHProtocol(nil, nil)

	// Verify initially nil.
	if p.encryptCipher != nil || p.decryptCipher != nil || p.signer != nil || p.verifier != nil {
		t.Error("expected nil initial encryption state")
	}

	// Set encryption.
	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())
	p.SetEncryption(enc, dec, signer, verifier)

	if p.encryptCipher == nil || p.decryptCipher == nil || p.signer == nil || p.verifier == nil {
		t.Error("expected non-nil encryption state after SetEncryption")
	}

	// Disable encryption.
	p.SetEncryption(nil, nil, nil, nil)
	if p.encryptCipher != nil || p.decryptCipher != nil || p.signer != nil || p.verifier != nil {
		t.Error("expected nil encryption state after disabling")
	}
}

func TestProtocolIsSendLengthEncrypted(t *testing.T) {
	p := newSSHProtocol(nil, nil)

	// No encryption: length is not encrypted.
	if p.isSendLengthEncrypted() {
		t.Error("expected length not encrypted with no cipher/signer")
	}

	// Standard HMAC: length IS encrypted.
	enc, _ := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, _ := createHmacPair(algorithms.NewHmacSha256())
	p.SetEncryption(enc, nil, signer, nil)
	if !p.isSendLengthEncrypted() {
		t.Error("expected length encrypted with standard HMAC")
	}

	// EtM: length is NOT encrypted.
	signerEtm, _ := createHmacPair(algorithms.NewHmacSha256Etm())
	p.SetEncryption(enc, nil, signerEtm, nil)
	if p.isSendLengthEncrypted() {
		t.Error("expected length not encrypted with EtM")
	}

	// GCM: length is NOT encrypted.
	algo := algorithms.NewAes256Gcm()
	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	gcmCipher, _ := algo.CreateCipher(true, key, iv)
	gcmSigner := gcmCipher.(*algorithms.AesGcmCipher)
	p.SetEncryption(gcmCipher, nil, gcmSigner, nil)
	if p.isSendLengthEncrypted() {
		t.Error("expected length not encrypted with GCM")
	}
}

func TestProtocolIsRecvLengthEncrypted(t *testing.T) {
	p := newSSHProtocol(nil, nil)

	// No encryption: length is not encrypted.
	if p.isRecvLengthEncrypted() {
		t.Error("expected length not encrypted with no cipher/verifier")
	}

	// Standard HMAC: length IS encrypted.
	_, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	_, verifier := createHmacPair(algorithms.NewHmacSha256())
	p.SetEncryption(nil, dec, nil, verifier)
	if !p.isRecvLengthEncrypted() {
		t.Error("expected length encrypted with standard HMAC")
	}

	// EtM: length is NOT encrypted.
	_, verifierEtm := createHmacPair(algorithms.NewHmacSha256Etm())
	p.SetEncryption(nil, dec, nil, verifierEtm)
	if p.isRecvLengthEncrypted() {
		t.Error("expected length not encrypted with EtM")
	}

	// GCM: length is NOT encrypted.
	algo := algorithms.NewAes256Gcm()
	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	gcmCipher, _ := algo.CreateCipher(false, key, iv)
	gcmVerifier := gcmCipher.(*algorithms.AesGcmCipher)
	p.SetEncryption(nil, gcmCipher, nil, gcmVerifier)
	if p.isRecvLengthEncrypted() {
		t.Error("expected length not encrypted with GCM")
	}
}

// --- Packet validation tests (US-003) ---

func TestReceivePacketLengthZero(t *testing.T) {
	buf := &bufferCloser{}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 0)
	buf.Write(header)
	buf.Write(make([]byte, 20)) // extra bytes to prevent premature EOF

	p := newSSHProtocol(buf, nil)
	_, err := p.receiveMessage()
	if err == nil {
		t.Fatal("expected error for zero packet length, got nil")
	}
	if !strings.Contains(err.Error(), "too small") {
		t.Errorf("expected 'too small' in error, got: %v", err)
	}
}

func TestReceivePacketLengthTooSmall(t *testing.T) {
	buf := &bufferCloser{}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 1) // packet_length = 1, below minimum of 2
	buf.Write(header)
	buf.Write(make([]byte, 20))

	p := newSSHProtocol(buf, nil)
	_, err := p.receiveMessage()
	if err == nil {
		t.Fatal("expected error for packet length 1, got nil")
	}
	if !strings.Contains(err.Error(), "too small") {
		t.Errorf("expected 'too small' in error, got: %v", err)
	}
}

func TestReceivePacketLengthTooLarge(t *testing.T) {
	buf := &bufferCloser{}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, maxPacketLength+1)
	buf.Write(header)
	buf.Write(make([]byte, 20))

	p := newSSHProtocol(buf, nil)
	_, err := p.receiveMessage()
	if err == nil {
		t.Fatal("expected error for too-large packet length, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' in error, got: %v", err)
	}
}

func TestReceivePacketTruncated(t *testing.T) {
	buf := &bufferCloser{}
	// Declare packet_length = 100 but only provide 10 bytes of data after the header.
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 100)
	buf.Write(header)
	buf.Write(make([]byte, 10))

	p := newSSHProtocol(buf, nil)
	_, err := p.receiveMessage()
	if err == nil {
		t.Fatal("expected error for truncated packet, got nil")
	}
	// io.ReadFull returns io.ErrUnexpectedEOF when the stream ends prematurely.
	if !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "unexpected") {
		t.Errorf("expected EOF-related error, got: %v", err)
	}
}

func TestReceivePacketPaddingInvalid(t *testing.T) {
	buf := &bufferCloser{}
	// packet_length = 8, padding_length = 10 (exceeds packetLength - 1 = 7).
	packet := make([]byte, 12) // 4 (header) + 8 (data)
	binary.BigEndian.PutUint32(packet[0:4], 8)
	packet[4] = 10 // invalid: padding > packet_length - 1
	buf.Write(packet)

	p := newSSHProtocol(buf, nil)
	_, err := p.receiveMessage()
	if err == nil {
		t.Fatal("expected error for invalid padding, got nil")
	}
	if !strings.Contains(err.Error(), "negative payload") {
		t.Errorf("expected 'negative payload' in error, got: %v", err)
	}
}

func TestReceivePacketBadMAC(t *testing.T) {
	buf := &bufferCloser{}

	_, verifier := createHmacPair(algorithms.NewHmacSha256())

	// Build a valid-structure packet: packet_length=12, padding=6, payload=5 bytes.
	packet := make([]byte, 16) // 4 (header) + 12 (data)
	binary.BigEndian.PutUint32(packet[0:4], 12)
	packet[4] = 6 // padding_length
	copy(packet[5:10], []byte{0x01, 0x02, 0x03, 0x04, 0x05})
	// bytes 10-15 are padding (zeros)
	buf.Write(packet)
	// Write incorrect MAC (all zeros).
	buf.Write(make([]byte, verifier.DigestLength()))

	p := newSSHProtocol(buf, nil)
	p.SetEncryption(nil, nil, nil, verifier)

	_, err := p.receiveMessage()
	if err == nil {
		t.Fatal("expected error for bad MAC, got nil")
	}
	if !strings.Contains(err.Error(), "mac verification failed") {
		t.Errorf("expected 'mac verification failed', got: %v", err)
	}
}
