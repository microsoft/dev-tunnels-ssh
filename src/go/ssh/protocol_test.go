// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/algorithms"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// duplexPipe creates a pair of connected ReadWriteClosers for testing.
// Uses asyncPipeRWC which adds a write buffer via a goroutine pump.
// This emulates the OS kernel write buffer that real transports (TCP, Unix
// sockets) provide, preventing deadlocks when both sides send inline from
// their dispatch loops on a zero-buffered io.Pipe.
func duplexPipe() (io.ReadWriteCloser, io.ReadWriteCloser) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return newAsyncPipeRWC(r1, w2), newAsyncPipeRWC(r2, w1)
}

// asyncPipeRWC wraps an io.Pipe with a buffered write path. Writes copy data
// into a channel and return immediately; a background goroutine drains the
// channel into the underlying PipeWriter. This provides the write buffering
// that real OS transports (TCP sockets) offer via kernel buffers, which
// io.Pipe lacks.
type asyncPipeRWC struct {
	r         *io.PipeReader
	w         *io.PipeWriter
	wch       chan []byte
	wdone     chan struct{}
	closeCh   chan struct{} // closed to signal writers/pump to stop
	closeOnce sync.Once
}

func newAsyncPipeRWC(r *io.PipeReader, w *io.PipeWriter) *asyncPipeRWC {
	p := &asyncPipeRWC{
		r:       r,
		w:       w,
		wch:     make(chan []byte, 256),
		wdone:   make(chan struct{}),
		closeCh: make(chan struct{}),
	}
	go p.writePump()
	return p
}

func (p *asyncPipeRWC) writePump() {
	defer close(p.wdone)
	for {
		select {
		case data := <-p.wch:
			if _, err := p.w.Write(data); err != nil {
				p.closeOnce.Do(func() { close(p.closeCh) })
				return
			}
		case <-p.closeCh:
			return
		}
	}
}

func (p *asyncPipeRWC) Read(b []byte) (int, error) { return p.r.Read(b) }

func (p *asyncPipeRWC) Write(b []byte) (int, error) {
	// Check closed first to avoid non-deterministic select when both
	// wch (has buffer room) and closeCh are ready simultaneously.
	select {
	case <-p.closeCh:
		return 0, io.ErrClosedPipe
	default:
	}
	data := make([]byte, len(b))
	copy(data, b)
	select {
	case p.wch <- data:
		return len(b), nil
	case <-p.closeCh:
		return 0, io.ErrClosedPipe
	}
}

func (p *asyncPipeRWC) Close() error {
	p.closeOnce.Do(func() { close(p.closeCh) })
	<-p.wdone
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

// TestProtocolGcmVaryingPayloadSizes sends multiple GCM-encrypted messages with
// varying sizes on the same protocol instance to exercise buffer pool reuse and
// sealBuf growth.
func TestProtocolGcmVaryingPayloadSizes(t *testing.T) {
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

	// Varying sizes: small → large (forces pool/sealBuf growth) → small again.
	sizes := []int{10, 200, 50000, 100000, 200, 10}
	for _, size := range sizes {
		payload := make([]byte, size)
		payload[0] = 0x15 // valid message type
		for i := 1; i < len(payload); i++ {
			payload[i] = byte(i % 256)
		}

		done := make(chan error, 1)
		go func() {
			done <- p1.sendMessage(payload)
		}()

		received, err := p2.receiveMessage()
		if err != nil {
			t.Fatalf("receiveMessage failed for size %d: %v", size, err)
		}

		if err := <-done; err != nil {
			t.Fatalf("sendMessage failed for size %d: %v", size, err)
		}

		if !bytes.Equal(received, payload) {
			t.Fatalf("payload mismatch for size %d: got len=%d want len=%d",
				size, len(received), len(payload))
		}
	}
}

// TestProtocolEtmVaryingPayloadSizes sends multiple ETM-encrypted messages with
// varying sizes to exercise sendHmacBuf and recvHmacBuf reuse.
func TestProtocolEtmVaryingPayloadSizes(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	algo := algorithms.NewAes256Ctr()
	hmacAlgo := algorithms.NewHmacSha256Etm()

	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	hmacKey := make([]byte, hmacAlgo.KeyLength)
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range iv {
		iv[i] = byte(i + 100)
	}
	for i := range hmacKey {
		hmacKey[i] = byte(i + 50)
	}

	encCipher, _ := algo.CreateCipher(true, key, iv)
	decCipher, _ := algo.CreateCipher(false, key, iv)
	signer := hmacAlgo.CreateSigner(hmacKey)
	verifier := hmacAlgo.CreateVerifier(hmacKey)

	p1.SetEncryption(encCipher, nil, signer, nil)
	p2.SetEncryption(nil, decCipher, nil, verifier)

	sizes := []int{10, 200, 50000, 200, 10}
	for _, size := range sizes {
		payload := make([]byte, size)
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
			t.Fatalf("receiveMessage failed for size %d: %v", size, err)
		}

		if err := <-done; err != nil {
			t.Fatalf("sendMessage failed for size %d: %v", size, err)
		}

		if !bytes.Equal(received, payload) {
			t.Fatalf("payload mismatch for size %d", size)
		}
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

// TestSendMessageDirectPlaintext verifies sendMessageDirect produces the same
// wire output as sendMessage (via ToBuffer) for an unencrypted protocol.
func TestSendMessageDirectPlaintext(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	msg := &messages.ChannelDataMessage{
		RecipientChannel: 42,
		Data:             []byte("hello sendMessageDirect"),
	}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessageDirect(msg)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessageDirect failed: %v", err)
	}

	// Verify the received payload matches what ToBuffer produces.
	expected := msg.ToBuffer()
	if !bytes.Equal(received, expected) {
		t.Errorf("payload mismatch: got %v, want %v", received, expected)
	}
}

// TestSendMessageDirectEncrypted verifies sendMessageDirect works through
// the encrypted path (AES-CTR + HMAC-SHA256).
func TestSendMessageDirectEncrypted(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	enc, dec := createCipherPair(t, algorithms.NewAes256Ctr())
	signer, verifier := createHmacPair(algorithms.NewHmacSha256())

	p1.SetEncryption(enc, nil, signer, nil)
	p2.SetEncryption(nil, dec, nil, verifier)

	msg := &messages.ChannelDataMessage{
		RecipientChannel: 7,
		Data:             []byte("encrypted sendMessageDirect test"),
	}

	done := make(chan error, 1)
	go func() {
		done <- p1.sendMessageDirect(msg)
	}()

	received, err := p2.receiveMessage()
	if err != nil {
		t.Fatalf("receiveMessage failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessageDirect failed: %v", err)
	}

	expected := msg.ToBuffer()
	if !bytes.Equal(received, expected) {
		t.Errorf("payload mismatch: got len=%d, want len=%d", len(received), len(expected))
	}
}

// TestSendMessageDirectMultiple verifies sendMessageDirect reuses its internal
// writer correctly across multiple sequential sends.
func TestSendMessageDirectMultiple(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	msgs := []*messages.ChannelDataMessage{
		{RecipientChannel: 1, Data: []byte("short")},
		{RecipientChannel: 2, Data: make([]byte, 5000)},  // large — forces writer growth
		{RecipientChannel: 3, Data: []byte("back small")}, // small after large — tests reset
	}

	done := make(chan error, 1)
	go func() {
		for _, msg := range msgs {
			if err := p1.sendMessageDirect(msg); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	for i, msg := range msgs {
		received, err := p2.receiveMessage()
		if err != nil {
			t.Fatalf("receiveMessage %d failed: %v", i, err)
		}
		expected := msg.ToBuffer()
		if !bytes.Equal(received, expected) {
			t.Errorf("message %d: payload mismatch: got len=%d, want len=%d",
				i, len(received), len(expected))
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("sendMessageDirect failed: %v", err)
	}

	if p1.SendSequence != 3 {
		t.Errorf("sender sequence = %d, want 3", p1.SendSequence)
	}
}

// TestBufferedWriterSimultaneousSends verifies that two protocol instances on
// opposite ends of a zero-buffered io.Pipe can both send simultaneously without
// deadlocking. This simulates the dispatch-loop scenario where both client and
// server send extension info inline after NewKeys.
func TestBufferedWriterSimultaneousSends(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	msg1 := make([]byte, 64)
	msg1[0] = 0x07 // ExtensionInfo message type
	for i := 1; i < len(msg1); i++ {
		msg1[i] = byte(i)
	}

	msg2 := make([]byte, 64)
	msg2[0] = 0x07
	for i := 1; i < len(msg2); i++ {
		msg2[i] = byte(i + 100)
	}

	// Both sides send simultaneously — this would deadlock without buffering.
	done1 := make(chan error, 1)
	done2 := make(chan error, 1)
	go func() { done1 <- p1.sendMessage(msg1) }()
	go func() { done2 <- p2.sendMessage(msg2) }()

	// Both sides read — if deadlocked, this times out.
	recv1 := make(chan []byte, 1)
	recv2 := make(chan []byte, 1)
	go func() {
		data, err := p2.receiveMessage()
		if err != nil {
			done1 <- err
			return
		}
		recv1 <- data
	}()
	go func() {
		data, err := p1.receiveMessage()
		if err != nil {
			done2 <- err
			return
		}
		recv2 <- data
	}()

	if err := <-done1; err != nil {
		t.Fatalf("p1 send failed: %v", err)
	}
	if err := <-done2; err != nil {
		t.Fatalf("p2 send failed: %v", err)
	}

	r1 := <-recv1
	r2 := <-recv2

	if !bytes.Equal(r1, msg1) {
		t.Errorf("p2 received wrong data from p1")
	}
	if !bytes.Equal(r2, msg2) {
		t.Errorf("p1 received wrong data from p2")
	}
}

// TestBufferedWriterFlushPerMessage verifies that each sendMessage call flushes
// the buffered writer, so messages are available to the reader immediately
// rather than being stuck in the buffer.
func TestBufferedWriterFlushPerMessage(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	// Send 5 small messages one at a time and verify each is received
	// before the next is sent. This proves flush happens per-message.
	for i := 0; i < 5; i++ {
		payload := []byte{0x15, byte(i)} // valid message type + sequence

		done := make(chan error, 1)
		go func() {
			done <- p1.sendMessage(payload)
		}()

		received, err := p2.receiveMessage()
		if err != nil {
			t.Fatalf("message %d: receive failed: %v", i, err)
		}

		if err := <-done; err != nil {
			t.Fatalf("message %d: send failed: %v", i, err)
		}

		if !bytes.Equal(received, payload) {
			t.Errorf("message %d: got %v, want %v", i, received, payload)
		}
	}
}

// TestBufferedWriterEncryptedSimultaneousSends verifies simultaneous sends
// work correctly with encryption enabled (AES-GCM).
func TestBufferedWriterEncryptedSimultaneousSends(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	algo := algorithms.NewAes256Gcm()
	key := make([]byte, algo.KeyLength)
	iv := make([]byte, algo.IVLength())
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range iv {
		iv[i] = byte(i + 200)
	}

	// Each side gets its own cipher pair for send/receive.
	enc1, _ := algo.CreateCipher(true, key, iv)
	dec1, _ := algo.CreateCipher(false, key, iv)
	gcmEnc1 := enc1.(*algorithms.AesGcmCipher)
	gcmDec1 := dec1.(*algorithms.AesGcmCipher)

	// Second pair with different IV to avoid nonce collision.
	iv2 := make([]byte, algo.IVLength())
	for i := range iv2 {
		iv2[i] = byte(i + 100)
	}
	enc2, _ := algo.CreateCipher(true, key, iv2)
	dec2, _ := algo.CreateCipher(false, key, iv2)
	gcmEnc2 := enc2.(*algorithms.AesGcmCipher)
	gcmDec2 := dec2.(*algorithms.AesGcmCipher)

	// p1 encrypts with enc1, p2 decrypts with dec1. p2 encrypts with enc2, p1 decrypts with dec2.
	p1.SetEncryption(enc1, dec2, gcmEnc1, gcmDec2)
	p2.SetEncryption(enc2, dec1, gcmEnc2, gcmDec1)

	msg1 := make([]byte, 200)
	msg1[0] = 0x15
	for i := 1; i < len(msg1); i++ {
		msg1[i] = byte(i % 256)
	}

	msg2 := make([]byte, 200)
	msg2[0] = 0x15
	for i := 1; i < len(msg2); i++ {
		msg2[i] = byte((i + 50) % 256)
	}

	// Simultaneous encrypted sends.
	done1 := make(chan error, 1)
	done2 := make(chan error, 1)
	go func() { done1 <- p1.sendMessage(msg1) }()
	go func() { done2 <- p2.sendMessage(msg2) }()

	recv1 := make(chan []byte, 1)
	recv2 := make(chan []byte, 1)
	go func() {
		data, err := p2.receiveMessage()
		if err != nil {
			done1 <- err
			return
		}
		recv1 <- data
	}()
	go func() {
		data, err := p1.receiveMessage()
		if err != nil {
			done2 <- err
			return
		}
		recv2 <- data
	}()

	if err := <-done1; err != nil {
		t.Fatalf("p1 encrypted send failed: %v", err)
	}
	if err := <-done2; err != nil {
		t.Fatalf("p2 encrypted send failed: %v", err)
	}

	r1 := <-recv1
	r2 := <-recv2

	if !bytes.Equal(r1, msg1) {
		t.Errorf("encrypted simultaneous send: p2 received wrong data from p1")
	}
	if !bytes.Equal(r2, msg2) {
		t.Errorf("encrypted simultaneous send: p1 received wrong data from p2")
	}
}

// TestBufferedWriterVersionString verifies that writeVersionString also goes
// through the buffered writer and is readable immediately.
func TestBufferedWriterVersionString(t *testing.T) {
	s1, s2 := duplexPipe()
	defer s1.Close()
	defer s2.Close()

	p1 := newSSHProtocol(s1, nil)
	p2 := newSSHProtocol(s2, nil)

	done := make(chan error, 1)
	go func() {
		done <- p1.writeVersionString("SSH-2.0-TestBuffered")
	}()

	version, err := p2.readVersionString()
	if err != nil {
		t.Fatalf("readVersionString failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("writeVersionString failed: %v", err)
	}

	if version != "SSH-2.0-TestBuffered" {
		t.Errorf("got version %q, want %q", version, "SSH-2.0-TestBuffered")
	}
}
