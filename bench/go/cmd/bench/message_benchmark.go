// Copyright (c) Microsoft Corporation. All rights reserved.

package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/algorithms"
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// --- Protocol serialization benchmarks ---

func protocolSerializationScenarios() []benchmarkScenario {
	return []benchmarkScenario{
		{
			name:     "serialize-channel-data",
			category: "protocol-serialization",
			tags:     map[string]string{"msg": "channel-data"},
			run:      runSerializeChannelData,
			verify:   verifySerializeChannelData,
		},
		{
			name:     "serialize-channel-open",
			category: "protocol-serialization",
			tags:     map[string]string{"msg": "channel-open"},
			run:      runSerializeChannelOpen,
			verify:   verifySerializeChannelOpen,
		},
		{
			name:     "serialize-kex-init",
			category: "protocol-serialization",
			tags:     map[string]string{"msg": "kex-init"},
			run:      runSerializeKexInit,
			verify:   verifySerializeKexInit,
		},
	}
}

func runSerializeChannelData(runs int) []metric {
	const iterations = 1000

	data := make([]byte, 32*1024)
	rand.Read(data)

	msg := &messages.ChannelDataMessage{
		RecipientChannel: 1,
		Data:             data,
	}

	timesMs := make([]float64, 0, runs)
	for i := 0; i < runs; i++ {
		start := time.Now()

		for j := 0; j < iterations; j++ {
			buf := msg.ToBuffer()
			var out messages.ChannelDataMessage
			_ = messages.ReadMessage(&out, buf)
		}

		elapsed := time.Since(start)
		timesMs = append(timesMs, float64(elapsed.Nanoseconds())/1e6/float64(iterations))
		fmt.Print(".")
	}

	return []metric{
		{Name: "Round-trip time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}

func runSerializeChannelOpen(runs int) []metric {
	const iterations = 1000

	msg := &messages.ChannelOpenMessage{
		ChannelType:   "session",
		SenderChannel: 42,
		MaxWindowSize: 1024 * 1024,
		MaxPacketSize: 32 * 1024,
	}

	timesMs := make([]float64, 0, runs)
	for i := 0; i < runs; i++ {
		start := time.Now()

		for j := 0; j < iterations; j++ {
			buf := msg.ToBuffer()
			var out messages.ChannelOpenMessage
			_ = messages.ReadMessage(&out, buf)
		}

		elapsed := time.Since(start)
		timesMs = append(timesMs, float64(elapsed.Nanoseconds())/1e6/float64(iterations))
		fmt.Print(".")
	}

	return []metric{
		{Name: "Round-trip time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}

func runSerializeKexInit(runs int) []metric {
	const iterations = 1000

	var cookie [16]byte
	rand.Read(cookie[:])
	msg := &messages.KeyExchangeInitMessage{
		Cookie:                              cookie,
		KeyExchangeAlgorithms:               []string{"ecdh-sha2-nistp384", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"},
		ServerHostKeyAlgorithms:             []string{"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "rsa-sha2-256"},
		EncryptionAlgorithmsClientToServer:  []string{"aes256-gcm@openssh.com", "aes256-ctr"},
		EncryptionAlgorithmsServerToClient:  []string{"aes256-gcm@openssh.com", "aes256-ctr"},
		MacAlgorithmsClientToServer:         []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"},
		MacAlgorithmsServerToClient:         []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"},
		CompressionAlgorithmsClientToServer: []string{"none"},
		CompressionAlgorithmsServerToClient: []string{"none"},
	}

	timesMs := make([]float64, 0, runs)
	for i := 0; i < runs; i++ {
		start := time.Now()

		for j := 0; j < iterations; j++ {
			buf := msg.ToBuffer()
			var out messages.KeyExchangeInitMessage
			_ = messages.ReadMessage(&out, buf)
		}

		elapsed := time.Since(start)
		timesMs = append(timesMs, float64(elapsed.Nanoseconds())/1e6/float64(iterations))
		fmt.Print(".")
	}

	return []metric{
		{Name: "Round-trip time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}

// --- KEX cycle benchmark ---

func kexCycleScenarios() []benchmarkScenario {
	return []benchmarkScenario{
		{
			name:     "kex-cycle-ecdh-p384",
			category: "protocol-kex-cycle",
			tags:     map[string]string{"algo": "ecdh-sha2-nistp384"},
			run:      runKexCycleBenchmark,
		},
	}
}

func runKexCycleBenchmark(runs int) []metric {
	kexAlgo := algorithms.NewECDHP384SHA384()

	// Pre-generate host key outside timed section.
	hostKey, err := ssh.GenerateKeyPair(ssh.AlgoPKEcdsaSha2P384)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating host key: %v\n", err)
		return nil
	}
	hostKeyBytes, err := hostKey.GetPublicKeyBytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting host key bytes: %v\n", err)
		return nil
	}

	s, ok := hostKey.(signer)
	if !ok {
		fmt.Fprintf(os.Stderr, "Host key does not implement signer interface\n")
		return nil
	}

	// KEXINIT message template (both sides use same).
	kexInitMsg := &messages.KeyExchangeInitMessage{
		KeyExchangeAlgorithms:               []string{"ecdh-sha2-nistp384"},
		ServerHostKeyAlgorithms:             []string{"ecdsa-sha2-nistp384"},
		EncryptionAlgorithmsClientToServer:  []string{"aes256-gcm@openssh.com"},
		EncryptionAlgorithmsServerToClient:  []string{"aes256-gcm@openssh.com"},
		MacAlgorithmsClientToServer:         []string{"hmac-sha2-256"},
		MacAlgorithmsServerToClient:         []string{"hmac-sha2-256"},
		CompressionAlgorithmsClientToServer: []string{"none"},
		CompressionAlgorithmsServerToClient: []string{"none"},
	}

	timesMs := make([]float64, 0, runs)
	for i := 0; i < runs; i++ {
		rand.Read(kexInitMsg.Cookie[:])

		start := time.Now()

		// 1. Both sides serialize KEXINIT.
		_ = kexInitMsg.ToBuffer()
		_ = kexInitMsg.ToBuffer()

		// 2. Client starts key exchange.
		clientKex, err := kexAlgo.CreateKeyExchange()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Client KEX create error: %v\n", err)
			continue
		}
		clientPublic, err := clientKex.StartKeyExchange()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Client StartKeyExchange error: %v\n", err)
			continue
		}

		// 3. Serialize DH_INIT (type 30, E value).
		dhInitWriter := sshio.NewSSHDataWriter(make([]byte, 0, len(clientPublic)+64))
		dhInitWriter.WriteByte(30) // SSH_MSG_KEXDH_INIT
		dhInitWriter.WriteBinary(clientPublic)
		dhInitBuf := dhInitWriter.ToBuffer()

		// 4. Server deserializes DH_INIT.
		dhInitReader := sshio.NewSSHDataReader(dhInitBuf)
		dhInitReader.ReadByte()                 // type
		clientE, _ := dhInitReader.ReadBinary() // E value

		// 5. Server starts key exchange and completes with client's E.
		serverKex, err := kexAlgo.CreateKeyExchange()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Server KEX create error: %v\n", err)
			continue
		}
		serverPublic, err := serverKex.StartKeyExchange()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Server StartKeyExchange error: %v\n", err)
			continue
		}
		_, err = serverKex.DecryptKeyExchange(clientE)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Server DecryptKeyExchange error: %v\n", err)
			continue
		}

		// 6. Server signs exchange hash and serializes DH_REPLY.
		testData := make([]byte, 48)
		rand.Read(testData)
		signature, err := s.Sign(testData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Sign error: %v\n", err)
			continue
		}

		dhReplyWriter := sshio.NewSSHDataWriter(make([]byte, 0, len(hostKeyBytes)+len(serverPublic)+len(signature)+128))
		dhReplyWriter.WriteByte(31) // SSH_MSG_KEXDH_REPLY
		dhReplyWriter.WriteBinary(hostKeyBytes)
		dhReplyWriter.WriteBinary(serverPublic)
		dhReplyWriter.WriteBinary(signature)
		dhReplyBuf := dhReplyWriter.ToBuffer()

		// 7. Client deserializes DH_REPLY.
		dhReplyReader := sshio.NewSSHDataReader(dhReplyBuf)
		dhReplyReader.ReadByte()                  // type
		_, _ = dhReplyReader.ReadBinary()         // hostKey
		serverF, _ := dhReplyReader.ReadBinary()  // F value
		sig, _ := dhReplyReader.ReadBinary()      // signature

		// 8. Client completes key exchange.
		_, err = clientKex.DecryptKeyExchange(serverF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Client DecryptKeyExchange error: %v\n", err)
			continue
		}

		// 9. Client verifies signature.
		_, err = s.Verify(testData, sig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verify error: %v\n", err)
			continue
		}

		elapsed := time.Since(start)
		timesMs = append(timesMs, float64(elapsed.Nanoseconds())/1e6)
		fmt.Print(".")
	}

	return []metric{
		{Name: "KEX cycle time", Unit: "ms", Values: timesMs, HigherIsBetter: false},
	}
}

// --- Verification functions ---

func verifySerializeChannelData() error {
	data := make([]byte, 1024)
	rand.Read(data)
	msg := &messages.ChannelDataMessage{RecipientChannel: 42, Data: data}

	buf := msg.ToBuffer()
	var out messages.ChannelDataMessage
	if err := messages.ReadMessage(&out, buf); err != nil {
		return fmt.Errorf("deserialize: %w", err)
	}
	if out.RecipientChannel != 42 {
		return fmt.Errorf("RecipientChannel: got %d, want 42", out.RecipientChannel)
	}
	if !bytes.Equal(out.Data, data) {
		return fmt.Errorf("data mismatch after round-trip")
	}
	return nil
}

func verifySerializeChannelOpen() error {
	msg := &messages.ChannelOpenMessage{
		ChannelType:   "session",
		SenderChannel: 42,
		MaxWindowSize: 1024 * 1024,
		MaxPacketSize: 32 * 1024,
	}

	buf := msg.ToBuffer()
	var out messages.ChannelOpenMessage
	if err := messages.ReadMessage(&out, buf); err != nil {
		return fmt.Errorf("deserialize: %w", err)
	}
	if out.ChannelType != "session" {
		return fmt.Errorf("ChannelType: got %q, want %q", out.ChannelType, "session")
	}
	if out.SenderChannel != 42 {
		return fmt.Errorf("SenderChannel: got %d, want 42", out.SenderChannel)
	}
	if out.MaxWindowSize != 1024*1024 {
		return fmt.Errorf("MaxWindowSize: got %d, want %d", out.MaxWindowSize, 1024*1024)
	}
	return nil
}

func verifySerializeKexInit() error {
	var cookie [16]byte
	rand.Read(cookie[:])
	msg := &messages.KeyExchangeInitMessage{
		Cookie:                              cookie,
		KeyExchangeAlgorithms:               []string{"ecdh-sha2-nistp384"},
		ServerHostKeyAlgorithms:             []string{"ecdsa-sha2-nistp384"},
		EncryptionAlgorithmsClientToServer:  []string{"aes256-gcm@openssh.com"},
		EncryptionAlgorithmsServerToClient:  []string{"aes256-gcm@openssh.com"},
		MacAlgorithmsClientToServer:         []string{"hmac-sha2-256"},
		MacAlgorithmsServerToClient:         []string{"hmac-sha2-256"},
		CompressionAlgorithmsClientToServer: []string{"none"},
		CompressionAlgorithmsServerToClient: []string{"none"},
	}

	buf := msg.ToBuffer()
	var out messages.KeyExchangeInitMessage
	if err := messages.ReadMessage(&out, buf); err != nil {
		return fmt.Errorf("deserialize: %w", err)
	}
	if !reflect.DeepEqual(out.KeyExchangeAlgorithms, msg.KeyExchangeAlgorithms) {
		return fmt.Errorf("KeyExchangeAlgorithms mismatch")
	}
	if !reflect.DeepEqual(out.EncryptionAlgorithmsClientToServer, msg.EncryptionAlgorithmsClientToServer) {
		return fmt.Errorf("EncryptionAlgorithms mismatch")
	}
	return nil
}
