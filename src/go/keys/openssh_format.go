// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	sshio "github.com/microsoft/dev-tunnels-ssh/src/go/ssh/io"
)

// OpenSSH private key format magic header.
var opensshMagic = []byte("openssh-key-v1\x00")

// BcryptRounds is the number of bcrypt rounds for OpenSSH key encryption.
var BcryptRounds = 16

// importOpenSSHPrivateKey imports an OpenSSH-format private key.
func importOpenSSHPrivateKey(data []byte, passphrase string) (ssh.KeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid OpenSSH PEM data")
	}

	if block.Type != "OPENSSH PRIVATE KEY" {
		return nil, fmt.Errorf("not an OpenSSH private key: %s", block.Type)
	}

	return parseOpenSSHPrivateKey(block.Bytes, passphrase)
}

// parseOpenSSHPrivateKey parses the binary content of an OpenSSH private key.
func parseOpenSSHPrivateKey(data []byte, passphrase string) (ssh.KeyPair, error) {
	// Verify magic header.
	if len(data) < len(opensshMagic) {
		return nil, fmt.Errorf("data too short for OpenSSH key")
	}
	for i, b := range opensshMagic {
		if data[i] != b {
			return nil, fmt.Errorf("invalid OpenSSH key magic")
		}
	}

	reader := sshio.NewSSHDataReader(data[len(opensshMagic):])

	cipherName, err := reader.ReadString()
	if err != nil {
		return nil, fmt.Errorf("failed to read cipher name: %w", err)
	}

	kdfName, err := reader.ReadString()
	if err != nil {
		return nil, fmt.Errorf("failed to read KDF name: %w", err)
	}

	kdfOptions, err := reader.ReadBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to read KDF options: %w", err)
	}

	keyCount, err := reader.ReadUInt32()
	if err != nil {
		return nil, fmt.Errorf("failed to read key count: %w", err)
	}
	if keyCount != 1 {
		return nil, fmt.Errorf("unsupported key count: %d", keyCount)
	}

	// Skip public key data (we'll get it from the private section).
	_, err = reader.ReadBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to read public key data: %w", err)
	}

	// Read private key data (may be encrypted).
	privateData, err := reader.ReadBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to read private key data: %w", err)
	}

	// Decrypt if necessary.
	if cipherName != "none" {
		if passphrase == "" {
			return nil, fmt.Errorf("encrypted key requires a passphrase")
		}
		if kdfName != "bcrypt" {
			return nil, fmt.Errorf("unsupported KDF: %s", kdfName)
		}

		privateData, err = decryptOpenSSH(privateData, kdfOptions, cipherName, passphrase)
		if err != nil {
			return nil, err
		}
	}

	return parseOpenSSHPrivateSection(privateData)
}

// decryptOpenSSH decrypts the private section of an OpenSSH key.
func decryptOpenSSH(data, kdfOptions []byte, cipherName, passphrase string) ([]byte, error) {
	kdfReader := sshio.NewSSHDataReader(kdfOptions)
	salt, err := kdfReader.ReadBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to read bcrypt salt: %w", err)
	}
	rounds, err := kdfReader.ReadUInt32()
	if err != nil {
		return nil, fmt.Errorf("failed to read bcrypt rounds: %w", err)
	}

	keyLen, ivLen, err := opensshCipherParams(cipherName)
	if err != nil {
		return nil, err
	}

	// Derive key and IV using bcrypt PBKDF.
	derived := bcryptPbkdf([]byte(passphrase), salt, int(rounds), keyLen+ivLen)
	key := derived[:keyLen]
	iv := derived[keyLen:]

	// Decrypt using AES-CTR.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	plaintext := make([]byte, len(data))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, data)

	return plaintext, nil
}

// parseOpenSSHPrivateSection parses the decrypted private key section.
func parseOpenSSHPrivateSection(data []byte) (ssh.KeyPair, error) {
	reader := sshio.NewSSHDataReader(data)

	// Read and verify check values.
	check1, err := reader.ReadUInt32()
	if err != nil {
		return nil, fmt.Errorf("failed to read check1: %w", err)
	}
	check2, err := reader.ReadUInt32()
	if err != nil {
		return nil, fmt.Errorf("failed to read check2: %w", err)
	}
	if check1 != check2 {
		return nil, fmt.Errorf("decryption failed: check values do not match (wrong passphrase?)")
	}

	// Read key algorithm name.
	algorithmName, err := reader.ReadString()
	if err != nil {
		return nil, fmt.Errorf("failed to read algorithm name: %w", err)
	}

	var kp ssh.KeyPair

	switch algorithmName {
	case ssh.AlgoKeyRsa:
		kp, err = parseOpenSSHRsaKey(reader)
	case ssh.AlgoPKEcdsaSha2P256, ssh.AlgoPKEcdsaSha2P384, ssh.AlgoPKEcdsaSha2P521:
		kp, err = parseOpenSSHEcdsaKey(reader, algorithmName)
	default:
		return nil, fmt.Errorf("unsupported OpenSSH key algorithm: %s", algorithmName)
	}

	if err != nil {
		return nil, err
	}

	// Read comment.
	comment, err := reader.ReadString()
	if err == nil && comment != "" {
		kp.SetComment(comment)
	}

	return kp, nil
}

// parseOpenSSHRsaKey parses an RSA key from the OpenSSH private section.
func parseOpenSSHRsaKey(reader *sshio.SSHDataReader) (ssh.KeyPair, error) {
	n, err := reader.ReadBigInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA n: %w", err)
	}
	e, err := reader.ReadBigInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA e: %w", err)
	}
	d, err := reader.ReadBigInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA d: %w", err)
	}
	iq, err := reader.ReadBigInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA iq: %w", err)
	}
	p, err := reader.ReadBigInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA p: %w", err)
	}
	q, err := reader.ReadBigInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA q: %w", err)
	}

	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D: d,
		Primes: []*big.Int{p, q},
	}
	privKey.Precompute()

	// Verify InverseQ matches what we read.
	_ = iq

	return ssh.NewRsaKeyPair(privKey, rsaAlgorithmForKeySize(n.BitLen()))
}

// parseOpenSSHEcdsaKey parses an ECDSA key from the OpenSSH private section.
func parseOpenSSHEcdsaKey(reader *sshio.SSHDataReader, algorithmName string) (ssh.KeyPair, error) {
	// Read curve name.
	_, err := reader.ReadString()
	if err != nil {
		return nil, fmt.Errorf("failed to read curve name: %w", err)
	}

	// Read public key point.
	pointBytes, err := reader.ReadBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to read public key point: %w", err)
	}

	// Read private key scalar.
	dBytes, err := reader.ReadBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Determine curve.
	var curve elliptic.Curve
	switch algorithmName {
	case ssh.AlgoPKEcdsaSha2P256:
		curve = elliptic.P256()
	case ssh.AlgoPKEcdsaSha2P384:
		curve = elliptic.P384()
	case ssh.AlgoPKEcdsaSha2P521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ECDSA algorithm: %s", algorithmName)
	}

	// Parse public key point.
	x, y := elliptic.Unmarshal(curve, pointBytes)
	if x == nil {
		return nil, fmt.Errorf("invalid ECDSA public key point")
	}

	d := new(big.Int).SetBytes(dBytes)
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}

	return ssh.NewEcdsaKeyPair(privKey)
}

// exportOpenSSHPrivateKey exports a private key in OpenSSH format.
func exportOpenSSHPrivateKey(key ssh.KeyPair, passphrase string) ([]byte, error) {
	if !key.HasPrivateKey() {
		return nil, fmt.Errorf("private key not available")
	}

	// Build the private section.
	privateSection, err := buildOpenSSHPrivateSection(key)
	if err != nil {
		return nil, err
	}

	// Build the public key data.
	pubKeyData, err := key.GetPublicKeyBytes()
	if err != nil {
		return nil, err
	}

	cipherName := "none"
	kdfName := "none"
	var kdfOptions []byte

	if passphrase != "" {
		cipherName = "aes256-ctr"
		kdfName = "bcrypt"

		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}

		kdfWriter := sshio.NewSSHDataWriter(make([]byte, 0))
		kdfWriter.WriteBinary(salt)
		kdfWriter.WriteUInt32(uint32(BcryptRounds))
		kdfOptions = kdfWriter.ToBuffer()

		keyLen := 32 // AES-256
		ivLen := aes.BlockSize
		derived := bcryptPbkdf([]byte(passphrase), salt, BcryptRounds, keyLen+ivLen)
		aesKey := derived[:keyLen]
		iv := derived[keyLen:]

		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}

		// Pad private section to block size boundary.
		blockSize := aes.BlockSize
		padLen := blockSize - (len(privateSection) % blockSize)
		if padLen != blockSize {
			for i := 0; i < padLen; i++ {
				privateSection = append(privateSection, byte(i+1))
			}
		}

		ciphertext := make([]byte, len(privateSection))
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(ciphertext, privateSection)
		privateSection = ciphertext
	}

	// Build the full key data.
	writer := sshio.NewSSHDataWriter(make([]byte, 0))
	writer.Write(opensshMagic)
	writer.WriteString(cipherName)
	writer.WriteString(kdfName)
	writer.WriteBinary(kdfOptions)
	writer.WriteUInt32(1) // key count
	writer.WriteBinary(pubKeyData)
	writer.WriteBinary(privateSection)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: writer.ToBuffer(),
	}), nil
}

// buildOpenSSHPrivateSection builds the plaintext private section.
func buildOpenSSHPrivateSection(key ssh.KeyPair) ([]byte, error) {
	// Generate random check values.
	checkBytes := make([]byte, 4)
	if _, err := rand.Read(checkBytes); err != nil {
		return nil, err
	}
	check := binary.BigEndian.Uint32(checkBytes)

	writer := sshio.NewSSHDataWriter(make([]byte, 0))
	writer.WriteUInt32(check)
	writer.WriteUInt32(check)

	switch k := key.(type) {
	case *ssh.RsaKeyPair:
		writer.WriteString(ssh.AlgoKeyRsa)
		privKey := k.PrivateKey()
		writer.WriteBigInt(privKey.N)
		writer.WriteBigInt(big.NewInt(int64(privKey.E)))
		writer.WriteBigInt(privKey.D)
		// InverseQ = q^(-1) mod p
		iq := new(big.Int).ModInverse(privKey.Primes[1], privKey.Primes[0])
		writer.WriteBigInt(iq)
		writer.WriteBigInt(privKey.Primes[0])
		writer.WriteBigInt(privKey.Primes[1])

	case *ssh.EcdsaKeyPair:
		privKey := k.PrivateKey()
		algoName := k.KeyAlgorithmName()
		writer.WriteString(algoName)

		// Curve name.
		var curveName string
		switch privKey.Curve {
		case elliptic.P256():
			curveName = "nistp256"
		case elliptic.P384():
			curveName = "nistp384"
		case elliptic.P521():
			curveName = "nistp521"
		}
		writer.WriteString(curveName)

		// Public key point.
		pointBytes := elliptic.Marshal(privKey.Curve, privKey.X, privKey.Y)
		writer.WriteBinary(pointBytes)

		// Private key scalar.
		dBytes := privKey.D.Bytes()
		writer.WriteBinary(dBytes)

	default:
		return nil, fmt.Errorf("unsupported key type for OpenSSH export: %T", key)
	}

	// Comment.
	writer.WriteString(key.Comment())

	// Padding: sequential bytes (1, 2, 3, ...) to align to 8 bytes.
	buf := writer.ToBuffer()
	padLen := 8 - (len(buf) % 8)
	if padLen != 8 {
		for i := 0; i < padLen; i++ {
			buf = append(buf, byte(i+1))
		}
	}

	return buf, nil
}

// opensshCipherParams returns key length and IV length for a given cipher name.
func opensshCipherParams(cipherName string) (keyLen, ivLen int, err error) {
	switch cipherName {
	case "aes128-ctr":
		return 16, 16, nil
	case "aes192-ctr":
		return 24, 16, nil
	case "aes256-ctr":
		return 32, 16, nil
	default:
		return 0, 0, fmt.Errorf("unsupported OpenSSH cipher: %s", cipherName)
	}
}
