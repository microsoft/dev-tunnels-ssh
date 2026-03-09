// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mathrand "math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/algorithms"
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

const (
	maxPacketLength   uint32 = 1024 * 1024 // 1 MB
	packetLengthSize         = 4
	paddingLengthSize        = 1
	defaultBlockSize         = 8
	minPaddingLength         = 4
	sequenceNumberSize       = 4
)

// packetPool reuses packet buffers across send operations to reduce GC pressure.
// Each pool entry is a *[]byte to avoid interface{} boxing of the slice header.
var packetPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 65536)
		return &buf
	},
}

// SSHProtocol handles binary SSH packet framing on a stream.
//
// Wire packet format (RFC 4253):
//
//	[uint32 packet_length] [byte padding_length] [payload] [random padding] [MAC]
//
// Where packet_length = padding_length_size(1) + payload_length + padding_length.
//
// Three encryption modes are supported:
//   - Standard: HMAC on plaintext, then encrypt full packet (including length)
//   - EtM (encrypt-then-MAC): encrypt without length, then HMAC on ciphertext
//   - GCM (AEAD): encrypt without length, authentication tag from cipher
type SSHProtocol struct {
	stream io.ReadWriteCloser
	reader *bufio.Reader

	writer  *bufio.Writer // buffered writer for stream; protected by sendMu
	sendMu  sync.Mutex   // protects send-side state: cipher, signer, sequence, stream writes
	closeMu sync.Mutex
	closed  bool

	// encrypted is an atomic flag indicating whether encryption is active.
	// Set in SetEncryption, read lock-free in hasEncryption to avoid sendMu contention.
	encrypted int32 // atomic; 0 = false, 1 = true

	// Encryption and HMAC state (nil before key exchange).
	// Send-side fields protected by sendMu; receive-side fields only accessed from dispatch loop.
	// The send path (sendMessage) reads ONLY encryptCipher/signer.
	// The receive path (receiveMessage) reads ONLY decryptCipher/verifier.
	// SetEncryption acquires sendMu to safely write send-side fields; receive-side
	// fields are safe because SetEncryption is called from the dispatch loop.
	encryptCipher algorithms.Cipher   // send-side: encryption cipher
	decryptCipher algorithms.Cipher   // receive-side: decryption cipher
	signer        algorithms.MessageSigner   // send-side: HMAC signer
	verifier      algorithms.MessageVerifier // receive-side: HMAC verifier

	// SendSequence tracks the number of messages sent (64-bit for reconnect tracking).
	// The lower 32 bits are used for HMAC computation per SSH spec.
	SendSequence uint64
	// ReceiveSequence tracks the number of messages received (64-bit for reconnect tracking).
	// Atomic because it is written by the dispatch loop and read by sendMessage via LastIncomingSequence.
	ReceiveSequence uint64 // atomic

	// Reconnect info flags. When enabled, extra bytes are appended to/stripped from
	// each packet for sequence acknowledgment and optional latency measurement.
	// These are atomic int32 (0/1) to allow concurrent access from send and dispatch goroutines.
	OutgoingMessagesHaveReconnectInfo int32 // atomic; 0 = false, 1 = true
	IncomingMessagesHaveReconnectInfo int32 // atomic; 0 = false, 1 = true
	OutgoingMessagesHaveLatencyInfo   int32 // atomic; 0 = false, 1 = true
	IncomingMessagesHaveLatencyInfo   int32 // atomic; 0 = false, 1 = true

	// reconnectInfoReady is closed when IncomingMessagesHaveReconnectInfo is set,
	// signaling that message caching is active. Reconnect() and handleReconnectRequest()
	// wait on this to guarantee caching is active before returning — matching C#/TS
	// behavior where reconnect state is fully established before the reconnect
	// operation completes.
	reconnectInfoReady     chan struct{}
	reconnectInfoReadyOnce sync.Once

	// Message cache for reconnection. Sent messages are cached until the remote side
	// acknowledges receipt, enabling retransmission after reconnect.
	// Protected by cacheMu.
	recentSentMessages []SequencedMessage
	cacheMu            sync.Mutex
	maxCacheSize       int // maximum number of cached messages (0 = no limit)

	// lastIncomingTimestamp records when the last message was received (microseconds).
	// Atomic because it is written by the dispatch loop and read by sendMessage.
	lastIncomingTimestamp int64 // atomic

	// BytesSent and BytesReceived track cumulative wire bytes for key rotation threshold.
	// These are atomic to allow concurrent send/receive access.
	// Reset to 0 after successful key exchange in activateNewKeys.
	BytesSent     uint64 // atomic
	BytesReceived uint64 // atomic

	// metrics tracks session-level wire byte and message counters.
	metrics *SessionMetrics

	// trace is set from Session to enable protocol-level tracing.
	trace         TraceFunc
	traceChannelData bool

	// Reusable HMAC input buffers to avoid per-message allocation.
	// sendHmacBuf is protected by sendMu; recvHmacBuf is only used from dispatch loop.
	sendHmacBuf []byte
	recvHmacBuf []byte

	// fastRand is a non-crypto PRNG for padding when encryption is disabled.
	// Padding bytes serve no security purpose in unencrypted mode.
	// Protected by sendMu.
	fastRand *mathrand.Rand

	// sendWriter is a reusable buffer for serializing messages, eliminating
	// per-message SSHDataWriter allocation. Protected by sendMu.
	sendWriter *sshio.SSHDataWriter
}

// SequencedMessage stores a sent message payload with its sequence number
// and timestamp for reconnection retransmission.
type SequencedMessage struct {
	Sequence uint64
	Payload  []byte // original payload (before reconnect info appended)
	SentTime int64  // timestamp in microseconds
}

func newSSHProtocol(stream io.ReadWriteCloser, metrics *SessionMetrics) *SSHProtocol {
	return &SSHProtocol{
		stream:             stream,
		writer:             bufio.NewWriterSize(stream, 65536),
		reader:             bufio.NewReader(stream),
		metrics:            metrics,
		fastRand:           mathrand.New(mathrand.NewSource(time.Now().UnixNano())),
		sendWriter:         sshio.NewSSHDataWriter(make([]byte, 1024)),
		reconnectInfoReady: make(chan struct{}),
	}
}

// SetEncryption activates encryption and HMAC on this protocol instance.
// Called after key exchange completes. Pass nil to disable encryption.
// Acquires sendMu to prevent races with sendMessage reading send-side fields.
func (p *SSHProtocol) SetEncryption(
	encryptCipher, decryptCipher algorithms.Cipher,
	signer algorithms.MessageSigner,
	verifier algorithms.MessageVerifier,
) {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	p.encryptCipher = encryptCipher
	p.decryptCipher = decryptCipher
	p.signer = signer
	p.verifier = verifier
	if encryptCipher != nil {
		atomic.StoreInt32(&p.encrypted, 1)
	} else {
		atomic.StoreInt32(&p.encrypted, 0)
	}
}

// hasEncryption returns true if encryption is currently active on this protocol.
// Uses an atomic flag to avoid acquiring sendMu, which may be held by a blocked
// write operation (e.g., keep-alive send on an unbuffered stream).
func (p *SSHProtocol) hasEncryption() bool {
	return atomic.LoadInt32(&p.encrypted) != 0
}

// writeVersionString writes the SSH version identification string to the stream.
// The string is terminated with \r\n per RFC 4253 section 4.2.
func (p *SSHProtocol) writeVersionString(version string) error {
	data := []byte(version + "\r\n")
	p.sendMu.Lock()
	_, err := p.writer.Write(data)
	if err == nil {
		err = p.writer.Flush()
	}
	p.sendMu.Unlock()
	if err == nil && p.metrics != nil {
		p.metrics.addMessageSent(len(data))
	}
	return err
}

// readVersionString reads the SSH version identification string from the stream.
// Per RFC 4253, up to 20 non-SSH lines may precede the version string.
func (p *SSHProtocol) readVersionString() (string, error) {
	totalBytes := 0
	for i := 0; i < 20; i++ {
		line, err := p.reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read version string: %w", err)
		}
		totalBytes += len(line)

		// Trim trailing \r\n or \n.
		line = strings.TrimRight(line, "\r\n")

		if strings.HasPrefix(line, "SSH-") {
			if p.metrics != nil {
				p.metrics.addMessageReceived(totalBytes)
			}
			return line, nil
		}
	}
	return "", fmt.Errorf("ssh version string not found within 20 lines")
}

// isSendLengthEncrypted returns whether the packet length field is encrypted on the send path.
// In EtM and AEAD (GCM) modes, the length is NOT encrypted.
// Only reads send-side fields (signer, encryptCipher) — must be called under sendMu.
func (p *SSHProtocol) isSendLengthEncrypted() bool {
	if p.signer != nil {
		if p.signer.EncryptThenMac() || p.signer.AuthenticatedEncryption() {
			return false
		}
	}
	return p.encryptCipher != nil
}

// isRecvLengthEncrypted returns whether the packet length field is encrypted on the receive path.
// In EtM and AEAD (GCM) modes, the length is NOT encrypted.
// Only reads receive-side fields (verifier, decryptCipher) — only called from dispatch loop.
func (p *SSHProtocol) isRecvLengthEncrypted() bool {
	if p.verifier != nil {
		if p.verifier.EncryptThenMac() || p.verifier.AuthenticatedEncryption() {
			return false
		}
	}
	return p.decryptCipher != nil
}

// sendBlockSize returns the cipher block size for the send path, or the default (8) if no cipher.
// Only reads send-side fields — must be called under sendMu.
func (p *SSHProtocol) sendBlockSize() int {
	if p.encryptCipher != nil {
		bs := p.encryptCipher.BlockLength()
		if bs > defaultBlockSize {
			return bs
		}
	}
	return defaultBlockSize
}

// recvBlockSize returns the cipher block size for the receive path, or the default (8) if no cipher.
// Only reads receive-side fields — only called from dispatch loop.
func (p *SSHProtocol) recvBlockSize() int {
	if p.decryptCipher != nil {
		bs := p.decryptCipher.BlockLength()
		if bs > defaultBlockSize {
			return bs
		}
	}
	return defaultBlockSize
}

// sendMessage frames and sends a serialized message payload on the wire.
// The payload must include the message type byte as the first byte.
func (p *SSHProtocol) sendMessage(payload []byte) error {
	// Hold sendMu for the entire operation. This serializes:
	// 1. Reading encryption state (prevents race with SetEncryption)
	// 2. Cipher Transform calls (cipher has mutable state like GCM nonce)
	// 3. Stream writes (prevents interleaved output)
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return p.sendMessageLocked(payload)
}

// sendMessageDirect serializes a message into a reusable internal buffer and
// sends it, avoiding the per-message SSHDataWriter allocation that ToBuffer()
// creates. The sendWriter is reused across calls (protected by sendMu).
func (p *SSHProtocol) sendMessageDirect(msg messages.Message) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()

	// Serialize message into the reusable sendWriter.
	p.sendWriter.Position = 0
	if err := msg.Write(p.sendWriter); err != nil {
		return err
	}

	// Pass the zero-copy slice to the existing send path.
	// sendMessageLocked only reads (copies) the payload, so aliasing is safe.
	return p.sendMessageLocked(p.sendWriter.Slice())
}

// sendMessageLocked is like sendMessage but assumes sendMu is already held by the caller.
// Used when the caller needs to atomically send a message and update protocol state
// (e.g., enabling reconnect flags immediately after sending the enable message).
func (p *SSHProtocol) sendMessageLocked(payload []byte) error {
	// Save the original payload for caching (before reconnect info is appended).
	originalPayload := payload

	// Append reconnect info to the payload if enabled.
	if atomic.LoadInt32(&p.OutgoingMessagesHaveReconnectInfo) != 0 {
		// Cache the latency flag once to avoid TOCTOU: if the flag changes
		// between buffer allocation and data write, the buffer could be too small.
		hasLatencyInfo := atomic.LoadInt32(&p.OutgoingMessagesHaveLatencyInfo) != 0
		reconnectInfoSize := 8 // uint64 LastIncomingSequence
		if hasLatencyInfo {
			reconnectInfoSize += 4 // uint32 time-since-last-received
		}
		extendedPayload := make([]byte, len(payload)+reconnectInfoSize)
		copy(extendedPayload, payload)

		// Write LastIncomingSequence (uint64, big-endian).
		binary.BigEndian.PutUint64(extendedPayload[len(payload):], p.LastIncomingSequence())

		if hasLatencyInfo {
			// Write time since last received message in microseconds.
			var timeSince uint32
			lastTS := atomic.LoadInt64(&p.lastIncomingTimestamp)
			if p.metrics != nil && lastTS > 0 {
				elapsed := p.metrics.TimeMicroseconds() - lastTS
				if elapsed > 0 && elapsed < int64(^uint32(0)) {
					timeSince = uint32(elapsed)
				} else if elapsed >= int64(^uint32(0)) {
					timeSince = ^uint32(0)
				}
			}
			binary.BigEndian.PutUint32(extendedPayload[len(payload)+8:], timeSince)
		}

		payload = extendedPayload
	}

	blockSize := p.sendBlockSize()
	isLenEncrypted := p.isSendLengthEncrypted()

	// Compute padding length.
	// When length is encrypted, include packetLengthSize in alignment calculation.
	alignBase := paddingLengthSize + len(payload)
	if isLenEncrypted {
		alignBase += packetLengthSize
	}
	paddingLength := blockSize - (alignBase % blockSize)
	if paddingLength < minPaddingLength {
		paddingLength += blockSize
	}

	// packetLength = paddingLengthSize(1) + payload + padding
	packetLength := paddingLengthSize + len(payload) + paddingLength

	// Build the packet: [packet_length(4)] [padding_length(1)] [payload] [padding]
	packetSize := packetLengthSize + packetLength
	macLen := 0
	if p.signer != nil {
		macLen = p.signer.DigestLength()
	}

	// Get a reusable buffer from the pool. Grow if needed for packet + MAC.
	needed := packetSize + macLen
	bufPtr := packetPool.Get().(*[]byte)
	if cap(*bufPtr) < needed {
		*bufPtr = make([]byte, needed)
	} else {
		*bufPtr = (*bufPtr)[:needed]
	}
	packet := (*bufPtr)[:packetSize]

	// Write packet_length (big-endian uint32).
	binary.BigEndian.PutUint32(packet[0:4], uint32(packetLength))

	// Write padding_length.
	packet[packetLengthSize] = byte(paddingLength)

	// Write payload.
	copy(packet[packetLengthSize+paddingLengthSize:], payload)

	// Write random padding. Use fast PRNG when unencrypted since padding bytes
	// serve no security purpose in that mode.
	paddingSlice := packet[packetLengthSize+paddingLengthSize+len(payload):packetSize]
	if p.encryptCipher != nil {
		_, _ = rand.Read(paddingSlice)
	} else {
		for i := range paddingSlice {
			paddingSlice[i] = byte(p.fastRand.Int31())
		}
	}

	// Compute MAC and encrypt based on mode.
	var mac []byte

	if p.signer != nil && p.signer.EncryptThenMac() && p.encryptCipher != nil {
		// EtM mode: encrypt (without length), then compute HMAC on ciphertext.
		_ = p.encryptCipher.Transform(packet[packetLengthSize:])
		mac, p.sendHmacBuf = p.computeHmac(p.signer, packet, p.SendSequence, p.sendHmacBuf)
	} else if p.signer != nil && p.signer.AuthenticatedEncryption() && p.encryptCipher != nil {
		// GCM mode: encrypt (without length), then retrieve tag from cipher.
		_ = p.encryptCipher.Transform(packet[packetLengthSize:])
		mac = p.signer.Sign(packet[packetLengthSize:])
	} else {
		// Standard mode: compute HMAC on plaintext, then encrypt full packet.
		if p.signer != nil {
			mac, p.sendHmacBuf = p.computeHmac(p.signer, packet, p.SendSequence, p.sendHmacBuf)
		}
		if p.encryptCipher != nil {
			_ = p.encryptCipher.Transform(packet)
		}
	}

	// Cache sent message for reconnection if enabled.
	if atomic.LoadInt32(&p.IncomingMessagesHaveReconnectInfo) != 0 {
		payloadCopy := make([]byte, len(originalPayload))
		copy(payloadCopy, originalPayload)
		sentTime := int64(0)
		if p.metrics != nil {
			sentTime = p.metrics.TimeMicroseconds()
		}
		p.cacheMu.Lock()
		p.recentSentMessages = append(p.recentSentMessages, SequencedMessage{
			Sequence: p.SendSequence,
			Payload:  payloadCopy,
			SentTime: sentTime,
		})
		// Evict oldest messages when cache exceeds the configured maximum.
		if p.maxCacheSize > 0 && len(p.recentSentMessages) > p.maxCacheSize {
			excess := len(p.recentSentMessages) - p.maxCacheSize
			p.recentSentMessages = p.recentSentMessages[excess:]
		}
		p.cacheMu.Unlock()
	}

	// Write packet + MAC into the buffered writer, then flush.
	if len(mac) > 0 {
		packet = append(packet, mac...)
	}
	_, err := p.writer.Write(packet)
	if err == nil {
		err = p.writer.Flush()
	}

	// Zero and return buffer to pool (prevents data leakage between sessions).
	for i := range (*bufPtr)[:needed] {
		(*bufPtr)[i] = 0
	}
	packetPool.Put(bufPtr)

	if err != nil {
		return err
	}

	p.SendSequence++

	wireBytes := uint64(packetSize + len(mac))
	atomic.AddUint64(&p.BytesSent, wireBytes)

	if p.metrics != nil {
		p.metrics.addMessageSent(packetSize + len(mac))
	}

	// Trace sent message.
	if p.trace != nil && len(originalPayload) > 0 {
		msgType := originalPayload[0]
		if msgType == messages.MsgNumChannelData || msgType == messages.MsgNumChannelExtendedData {
			if p.traceChannelData {
				p.trace(TraceLevelVerbose, TraceEventSendingChannelData,
					fmt.Sprintf("Sending channel data: type=%d size=%d", msgType, len(originalPayload)))
			}
		} else {
			p.trace(TraceLevelVerbose, TraceEventSendingMessage,
				fmt.Sprintf("Sending message: type=%d size=%d", msgType, len(originalPayload)))
		}
	}

	return nil
}

// computeHmac computes the HMAC over [sequence_number(4)] [packet].
// The sequence number is truncated to uint32 per SSH spec (RFC 4253).
// buf is a reusable buffer for the HMAC input; it is grown if needed.
func (p *SSHProtocol) computeHmac(signer algorithms.MessageSigner, packet []byte, sequence uint64, buf []byte) (mac, updatedBuf []byte) {
	// HMAC input: sequence_number(4 bytes, truncated) || packet
	needed := sequenceNumberSize + len(packet)
	if cap(buf) < needed {
		buf = make([]byte, needed)
	}
	buf = buf[:needed]
	binary.BigEndian.PutUint32(buf[0:4], uint32(sequence))
	copy(buf[sequenceNumberSize:], packet)
	return signer.Sign(buf), buf
}

// verifyHmac reads the MAC from the wire and verifies it against the packet.
// The sequence number is truncated to uint32 per SSH spec (RFC 4253).
func (p *SSHProtocol) verifyHmac(verifier algorithms.MessageVerifier, packet []byte, sequence uint64) (bool, error) {
	digestLen := verifier.DigestLength()
	mac := make([]byte, digestLen)
	_, err := io.ReadFull(p.reader, mac)
	if err != nil {
		return false, err
	}

	// HMAC input: sequence_number(4 bytes) || packet (reuse recvHmacBuf)
	needed := sequenceNumberSize + len(packet)
	if cap(p.recvHmacBuf) < needed {
		p.recvHmacBuf = make([]byte, needed)
	}
	p.recvHmacBuf = p.recvHmacBuf[:needed]
	binary.BigEndian.PutUint32(p.recvHmacBuf[0:4], uint32(sequence))
	copy(p.recvHmacBuf[sequenceNumberSize:], packet)
	return verifier.Verify(p.recvHmacBuf, mac), nil
}

// receiveMessage reads and deframes one SSH packet from the wire.
// Returns the raw payload bytes (including message type byte as first byte).
func (p *SSHProtocol) receiveMessage() ([]byte, error) {
	isLenEncrypted := p.isRecvLengthEncrypted()

	// Determine how many bytes to read first.
	// If length is encrypted, we need to read a full cipher block to decrypt the length.
	// If length is NOT encrypted (EtM/AEAD), we only need 4 bytes.
	firstBlockSize := p.recvBlockSize()
	if !isLenEncrypted {
		firstBlockSize = packetLengthSize
	}

	// Read the first block.
	firstBlock := make([]byte, firstBlockSize)
	_, err := io.ReadFull(p.reader, firstBlock)
	if err != nil {
		return nil, err
	}

	// Decrypt the first block if the length is encrypted (standard mode).
	if p.decryptCipher != nil && isLenEncrypted {
		if err := p.decryptCipher.Transform(firstBlock); err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
	}

	// Extract packet_length from the first 4 bytes.
	packetLength := binary.BigEndian.Uint32(firstBlock[0:4])
	if packetLength > maxPacketLength {
		return nil, fmt.Errorf("packet too large: %d bytes", packetLength)
	}
	if packetLength < 2 {
		return nil, fmt.Errorf("packet too small: %d bytes", packetLength)
	}

	// In encrypted mode, the full packet (length header + data) must be at least
	// one cipher block. Otherwise the copy of firstBlock into fullPacket below
	// would overrun the destination slice.
	if int(packetLength)+packetLengthSize < firstBlockSize {
		return nil, fmt.Errorf("packet too small for block size: %d bytes", packetLength)
	}

	// Read the remaining data after the first block.
	// Total packet bytes = packetLengthSize + packetLength
	// Already read firstBlockSize bytes, so remaining = total - firstBlockSize.
	followingLen := int(packetLength) - (firstBlockSize - packetLengthSize)
	var followingBlocks []byte
	if followingLen > 0 {
		followingBlocks = make([]byte, followingLen)
		_, err = io.ReadFull(p.reader, followingBlocks)
		if err != nil {
			return nil, err
		}
	}

	// Assemble the full packet for HMAC verification:
	// [packet_length(4)] [firstBlock_rest] [followingBlocks]
	fullPacket := make([]byte, packetLengthSize+int(packetLength))
	copy(fullPacket[0:firstBlockSize], firstBlock)
	if followingLen > 0 {
		copy(fullPacket[firstBlockSize:], followingBlocks)
	}

	// Handle MAC verification and decryption based on mode.
	if p.verifier != nil && p.verifier.EncryptThenMac() {
		// EtM mode: verify MAC over ciphertext (before decrypting).
		ok, err := p.verifyHmac(p.verifier, fullPacket, atomic.LoadUint64(&p.ReceiveSequence))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("mac verification failed")
		}

		// Decrypt everything after packet_length.
		if p.decryptCipher != nil && followingLen > 0 {
			if err := p.decryptCipher.Transform(followingBlocks); err != nil {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
			copy(fullPacket[firstBlockSize:], followingBlocks)
		}
	} else if p.verifier != nil && p.verifier.AuthenticatedEncryption() {
		// GCM mode: read the tag, set it on the cipher, then decrypt.
		digestLen := p.verifier.DigestLength()
		gcmTag := make([]byte, digestLen)
		_, err = io.ReadFull(p.reader, gcmTag)
		if err != nil {
			return nil, err
		}

		// Set the tag on the cipher for verification during decryption.
		p.verifier.Verify(followingBlocks, gcmTag)

		// Decrypt everything after packet_length (verification happens inside Transform).
		if p.decryptCipher != nil && followingLen > 0 {
			if err := p.decryptCipher.Transform(followingBlocks); err != nil {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
			copy(fullPacket[firstBlockSize:], followingBlocks)
		}
	} else {
		// Standard mode: decrypt remaining data, then verify MAC.
		if p.decryptCipher != nil && followingLen > 0 {
			if err := p.decryptCipher.Transform(followingBlocks); err != nil {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
			copy(fullPacket[firstBlockSize:], followingBlocks)
		}

		if p.verifier != nil {
			ok, err := p.verifyHmac(p.verifier, fullPacket, atomic.LoadUint64(&p.ReceiveSequence))
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("mac verification failed")
			}
		}
	}

	// Extract padding length and payload from the decrypted packet.
	paddingLength := int(fullPacket[packetLengthSize])
	payloadLen := int(packetLength) - paddingLengthSize - paddingLength
	if payloadLen < 0 {
		return nil, fmt.Errorf("invalid packet: negative payload length")
	}
	if payloadLen == 0 {
		return nil, fmt.Errorf("invalid packet: empty payload")
	}

	// Copy payload out (message type byte + message data).
	payload := make([]byte, payloadLen)
	copy(payload, fullPacket[packetLengthSize+paddingLengthSize:packetLengthSize+paddingLengthSize+payloadLen])

	// Extract reconnect info from the end of the payload if enabled.
	if atomic.LoadInt32(&p.IncomingMessagesHaveReconnectInfo) != 0 {
		hasLatencyInfo := atomic.LoadInt32(&p.IncomingMessagesHaveLatencyInfo) != 0
		var reconnectInfoSize int
		if hasLatencyInfo {
			reconnectInfoSize = 12 // uint64 + uint32
		} else {
			reconnectInfoSize = 8 // uint64
		}

		if len(payload) > reconnectInfoSize {
			infoStart := len(payload) - reconnectInfoSize
			lastSequenceSeenByRemote := binary.BigEndian.Uint64(payload[infoStart : infoStart+8])

			var remoteTimeSinceLastReceived uint32
			if hasLatencyInfo {
				remoteTimeSinceLastReceived = binary.BigEndian.Uint32(payload[infoStart+8 : infoStart+12])
			}

			// Trim the reconnect info from the payload.
			payload = payload[:infoStart]

			receivedTime := int64(0)
			if p.metrics != nil {
				receivedTime = p.metrics.TimeMicroseconds()
			}

			// Purge acknowledged messages from the cache and compute latency.
			p.cacheMu.Lock()
			for len(p.recentSentMessages) > 0 {
				oldest := p.recentSentMessages[0]
				if oldest.Sequence > lastSequenceSeenByRemote {
					break
				}

				// Compute latency from the message that matches the last-seen sequence.
				if hasLatencyInfo && oldest.Sequence == lastSequenceSeenByRemote && p.metrics != nil {
					timeSinceSent := receivedTime - oldest.SentTime
					roundTripLatency := timeSinceSent - int64(remoteTimeSinceLastReceived)
					p.metrics.updateLatency(roundTripLatency)
				}

				// Remove the oldest message (shift slice).
				p.recentSentMessages = p.recentSentMessages[1:]
			}
			p.cacheMu.Unlock()
		}
	}

	// Record timestamp for latency calculations.
	if p.metrics != nil {
		atomic.StoreInt64(&p.lastIncomingTimestamp,p.metrics.TimeMicroseconds())
	}

	atomic.AddUint64(&p.ReceiveSequence, 1)

	macLen := 0
	if p.verifier != nil {
		macLen = p.verifier.DigestLength()
	}
	wireBytes := uint64(packetLengthSize + int(packetLength) + macLen)
	atomic.AddUint64(&p.BytesReceived,wireBytes)

	if p.metrics != nil {
		p.metrics.addMessageReceived(int(wireBytes))
	}

	// Trace received message.
	if p.trace != nil && len(payload) > 0 {
		msgType := payload[0]
		if msgType == messages.MsgNumChannelData || msgType == messages.MsgNumChannelExtendedData {
			if p.traceChannelData {
				p.trace(TraceLevelVerbose, TraceEventReceivingChannelData,
					fmt.Sprintf("Receiving channel data: type=%d size=%d", msgType, len(payload)))
			}
		} else {
			p.trace(TraceLevelVerbose, TraceEventReceivingMessage,
				fmt.Sprintf("Receiving message: type=%d size=%d", msgType, len(payload)))
		}
	}

	return payload, nil
}

// LastIncomingSequence returns the sequence number of the last received message.
// Returns 0 if no messages have been received yet (avoids uint64 underflow).
func (p *SSHProtocol) LastIncomingSequence() uint64 {
	seq := atomic.LoadUint64(&p.ReceiveSequence)
	if seq == 0 {
		return 0
	}
	return seq - 1
}

// GetSentMessages retrieves cached sent messages starting from the given sequence number.
// Returns:
//   - empty slice if the remote side is already up-to-date
//   - nil if the cache doesn't go back far enough (messages were purged)
//   - slice of payload bytes otherwise
//
// Key exchange and disconnect messages are excluded since they cannot be retransmitted;
// a reconnected session will do key exchange separately.
func (p *SSHProtocol) GetSentMessages(startingSequenceNumber uint64) [][]byte {
	if startingSequenceNumber == p.SendSequence {
		// The recipient is already up-to-date.
		return [][]byte{}
	}

	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	if len(p.recentSentMessages) > 0 &&
		startingSequenceNumber < p.recentSentMessages[0].Sequence {
		// The cached recent messages do not go back as far as the requested sequence number.
		return nil
	}

	// Return all messages starting with the requested sequence number,
	// excluding key exchange messages and disconnect messages.
	var result [][]byte
	for _, m := range p.recentSentMessages {
		if m.Sequence < startingSequenceNumber {
			continue
		}
		if len(m.Payload) == 0 {
			continue
		}
		msgType := m.Payload[0]
		// Exclude key exchange messages (20-31) and disconnect (1).
		if isKeyExchangeMessage(msgType) || msgType == messages.MsgNumDisconnect {
			continue
		}
		payloadCopy := make([]byte, len(m.Payload))
		copy(payloadCopy, m.Payload)
		result = append(result, payloadCopy)
	}
	return result
}

// isKeyExchangeMessage returns true if the message type is a key exchange message (20-31).
func isKeyExchangeMessage(msgType byte) bool {
	return msgType >= messages.MsgNumKeyExchangeInit && msgType <= messages.MsgNumKeyExchangeDhReply
}

// close closes the underlying stream.
func (p *SSHProtocol) close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true

	// Flush any buffered data before closing the underlying stream.
	p.sendMu.Lock()
	_ = p.writer.Flush()
	p.sendMu.Unlock()

	return p.stream.Close()
}
