// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// SSH2 format constants.
const (
	ssh2PublicKeyBegin    = "---- BEGIN SSH2 PUBLIC KEY ----"
	ssh2PublicKeyEnd      = "---- END SSH2 PUBLIC KEY ----"
	ssh2PrivateKeyBegin   = "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"
	ssh2PrivateKeyEnd     = "---- END SSH2 ENCRYPTED PRIVATE KEY ----"
	ssh2MagicNumber       = 0x3f6ff9eb
	ssh2RsaKeyType        = "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}"
	ssh2NoCipher          = "none"
	ssh2TripleDesCipher   = "3des-cbc"
)

// importSSH2Key imports a key in SSH2 (ssh.com / RFC 4716) format.
func importSSH2Key(data []byte, passphrase string) (ssh.KeyPair, error) {
	text := string(data)

	if strings.Contains(text, ssh2PublicKeyBegin) {
		return importSSH2PublicKey(text)
	}
	if strings.Contains(text, ssh2PrivateKeyBegin) {
		return importSSH2PrivateKey(text, passphrase)
	}

	return nil, fmt.Errorf("not a valid SSH2 format key")
}

// importSSH2PublicKey parses an SSH2 public key (RFC 4716).
func importSSH2PublicKey(text string) (ssh.KeyPair, error) {
	b64Data, comment, err := parseSSH2Block(text, ssh2PublicKeyBegin, ssh2PublicKeyEnd)
	if err != nil {
		return nil, err
	}

	keyData, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in SSH2 public key: %w", err)
	}

	kp, err := ssh.KeyPairFromPublicKeyBytes(keyData)
	if err != nil {
		return nil, err
	}

	if comment != "" {
		kp.SetComment(comment)
	}

	return kp, nil
}

// importSSH2PrivateKey parses an SSH2 private key (ssh.com format).
func importSSH2PrivateKey(text, passphrase string) (ssh.KeyPair, error) {
	b64Data, comment, err := parseSSH2Block(text, ssh2PrivateKeyBegin, ssh2PrivateKeyEnd)
	if err != nil {
		return nil, err
	}

	keyData, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in SSH2 private key: %w", err)
	}

	kp, err := parseSSH2PrivateKeyData(keyData, passphrase)
	if err != nil {
		return nil, err
	}

	if comment != "" {
		kp.SetComment(comment)
	}

	return kp, nil
}

// parseSSH2Block extracts the base64 data and comment from an SSH2 block.
func parseSSH2Block(text, beginMarker, endMarker string) (b64Data, comment string, err error) {
	startIdx := strings.Index(text, beginMarker)
	if startIdx < 0 {
		return "", "", fmt.Errorf("missing SSH2 begin marker")
	}
	endIdx := strings.Index(text, endMarker)
	if endIdx < 0 {
		return "", "", fmt.Errorf("missing SSH2 end marker")
	}

	body := text[startIdx+len(beginMarker) : endIdx]
	lines := strings.Split(strings.TrimSpace(body), "\n")

	var dataLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Parse headers (RFC 4716: "Header-tag: value")
		if strings.HasPrefix(line, "Comment:") {
			c := strings.TrimPrefix(line, "Comment:")
			c = strings.TrimSpace(c)
			// Remove surrounding quotes if present.
			if len(c) >= 2 && c[0] == '"' && c[len(c)-1] == '"' {
				c = c[1 : len(c)-1]
			}
			comment = c
			continue
		}
		if strings.Contains(line, ":") && !strings.ContainsAny(line[:strings.Index(line, ":")], " +/=") {
			// Other header - skip.
			continue
		}
		dataLines = append(dataLines, line)
	}

	return strings.Join(dataLines, ""), comment, nil
}

// parseSSH2PrivateKeyData parses the binary ssh.com private key format.
func parseSSH2PrivateKeyData(data []byte, passphrase string) (ssh.KeyPair, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ssh2 private key data too short")
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != ssh2MagicNumber {
		return nil, fmt.Errorf("invalid SSH2 private key magic: 0x%08x", magic)
	}

	// totalLength at offset 4.
	_ = binary.BigEndian.Uint32(data[4:8])

	offset := 8

	// Read key type string.
	keyType, n, err := readSSH2String(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read key type: %w", err)
	}
	offset += n

	// Read cipher name.
	cipherName, n, err := readSSH2String(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read cipher name: %w", err)
	}
	offset += n

	// Read private key blob.
	blobLen, n, err := readSSH2Uint32(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob length: %w", err)
	}
	offset += n

	if offset+int(blobLen) > len(data) {
		return nil, fmt.Errorf("ssh2 private key data truncated")
	}

	privateBlob := data[offset : offset+int(blobLen)]

	// Decrypt if necessary.
	if cipherName != ssh2NoCipher {
		if passphrase == "" {
			return nil, fmt.Errorf("encrypted key requires a passphrase")
		}
		privateBlob, err = decryptSSH2PrivateKey(privateBlob, cipherName, passphrase)
		if err != nil {
			return nil, err
		}
	}

	_ = keyType // We detect key type from the key type string.

	if !strings.Contains(keyType, "rsa") {
		return nil, fmt.Errorf("unsupported SSH2 key type: %s", keyType)
	}

	return parseSSH2RsaPrivateKey(privateBlob)
}

// parseSSH2RsaPrivateKey parses an RSA private key from ssh.com format.
// Each BigInt is prefixed with its bit length (uint32).
func parseSSH2RsaPrivateKey(data []byte) (ssh.KeyPair, error) {
	offset := 0

	// Inner length field.
	if len(data) < 4 {
		return nil, fmt.Errorf("ssh2 RSA key data too short")
	}
	_ = binary.BigEndian.Uint32(data[0:4])
	offset = 4

	e, n2, err := readSSH2BigInt(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA e: %w", err)
	}
	offset += n2

	d, n2, err := readSSH2BigInt(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA d: %w", err)
	}
	offset += n2

	n, n2, err := readSSH2BigInt(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA n: %w", err)
	}
	offset += n2

	iq, n2, err := readSSH2BigInt(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA iq: %w", err)
	}
	offset += n2

	q, n2, err := readSSH2BigInt(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA q: %w", err)
	}
	offset += n2

	p, _, err := readSSH2BigInt(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA p: %w", err)
	}

	_ = iq

	privKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	privKey.Precompute()

	return ssh.NewRsaKeyPair(privKey, rsaAlgorithmForKeySize(n.BitLen()))
}

// decryptSSH2PrivateKey decrypts an SSH2 private key blob.
func decryptSSH2PrivateKey(data []byte, cipherName, passphrase string) ([]byte, error) {
	if cipherName != ssh2TripleDesCipher {
		return nil, fmt.Errorf("unsupported SSH2 cipher: %s", cipherName)
	}

	// Derive key using MD5 (weak, but that's what SSH2 uses).
	keyLen := 24 // 3DES key length
	key := deriveSSH2Key([]byte(passphrase), keyLen)

	// IV is all zeros for SSH2.
	iv := make([]byte, 8) // DES block size

	// Decrypt with 3DES-CBC.
	plaintext, err := tripleDesDecryptCBC(key, iv, data)
	if err != nil {
		return nil, fmt.Errorf("ssh2 decryption failed: %w", err)
	}

	return plaintext, nil
}

// deriveSSH2Key derives an encryption key using MD5 hash chain.
// The derivation is: MD5(passphrase), MD5(passphrase || prev_hash), ...
func deriveSSH2Key(passphrase []byte, keyLen int) []byte {
	var key []byte
	var prev []byte

	for len(key) < keyLen {
		h := md5.New()
		h.Write(passphrase)
		if prev != nil {
			h.Write(prev)
		}
		prev = h.Sum(nil)
		key = append(key, prev...)
	}

	return key[:keyLen]
}

// tripleDesDecryptCBC decrypts data using 3DES-CBC.
func tripleDesDecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create 3DES cipher: %w", err)
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of block size %d",
			len(ciphertext), block.BlockSize())
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// exportSSH2PublicKey exports a public key in SSH2 (RFC 4716) format.
func exportSSH2PublicKey(key ssh.KeyPair) ([]byte, error) {
	pubKeyData, err := key.GetPublicKeyBytes()
	if err != nil {
		return nil, err
	}

	b64 := base64.StdEncoding.EncodeToString(pubKeyData)

	var buf bytes.Buffer
	buf.WriteString(ssh2PublicKeyBegin + "\n")

	if key.Comment() != "" {
		buf.WriteString(fmt.Sprintf("Comment: \"%s\"\n", key.Comment()))
	}

	// Wrap base64 at 70 characters.
	for len(b64) > 70 {
		buf.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	if len(b64) > 0 {
		buf.WriteString(b64 + "\n")
	}

	buf.WriteString(ssh2PublicKeyEnd + "\n")
	return buf.Bytes(), nil
}

// exportSSH2PrivateKey exports a private key in SSH2 (ssh.com) format (unencrypted).
func exportSSH2PrivateKey(key ssh.KeyPair) ([]byte, error) {
	rsaKey, ok := key.(*ssh.RsaKeyPair)
	if !ok {
		return nil, fmt.Errorf("ssh2 private key format only supports RSA keys")
	}

	privKey := rsaKey.PrivateKey()
	if privKey == nil {
		return nil, fmt.Errorf("private key not available")
	}

	// Build private key blob.
	privateBlob := buildSSH2RsaPrivateBlob(privKey)

	// Build the full binary structure.
	var binaryData bytes.Buffer

	// Key type string.
	keyTypeBytes := writeSSH2String(ssh2RsaKeyType)
	// Cipher name.
	cipherBytes := writeSSH2String(ssh2NoCipher)
	// Blob with length prefix.
	blobWithLen := make([]byte, 4+len(privateBlob))
	binary.BigEndian.PutUint32(blobWithLen, uint32(len(privateBlob)))
	copy(blobWithLen[4:], privateBlob)

	totalLen := 8 + len(keyTypeBytes) + len(cipherBytes) + len(blobWithLen)

	// Magic number.
	magicBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBytes, ssh2MagicNumber)
	binaryData.Write(magicBytes)

	// Total length.
	totalLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(totalLenBytes, uint32(totalLen))
	binaryData.Write(totalLenBytes)

	binaryData.Write(keyTypeBytes)
	binaryData.Write(cipherBytes)
	binaryData.Write(blobWithLen)

	b64 := base64.StdEncoding.EncodeToString(binaryData.Bytes())

	var buf bytes.Buffer
	buf.WriteString(ssh2PrivateKeyBegin + "\n")

	if key.Comment() != "" {
		buf.WriteString(fmt.Sprintf("Comment: \"%s\"\n", key.Comment()))
	}

	// Wrap base64 at 70 characters.
	for len(b64) > 70 {
		buf.WriteString(b64[:70] + "\n")
		b64 = b64[70:]
	}
	if len(b64) > 0 {
		buf.WriteString(b64 + "\n")
	}

	buf.WriteString(ssh2PrivateKeyEnd + "\n")
	return buf.Bytes(), nil
}

// buildSSH2RsaPrivateBlob builds the inner RSA private key blob for SSH2 format.
func buildSSH2RsaPrivateBlob(privKey *rsa.PrivateKey) []byte {
	var inner bytes.Buffer

	writeSSH2BigIntTo(&inner, big.NewInt(int64(privKey.E)))
	writeSSH2BigIntTo(&inner, privKey.D)
	writeSSH2BigIntTo(&inner, privKey.N)
	// InverseQ
	iq := new(big.Int).ModInverse(privKey.Primes[1], privKey.Primes[0])
	writeSSH2BigIntTo(&inner, iq)
	writeSSH2BigIntTo(&inner, privKey.Primes[1]) // q
	writeSSH2BigIntTo(&inner, privKey.Primes[0]) // p

	// Prefix with inner length.
	innerBytes := inner.Bytes()
	result := make([]byte, 4+len(innerBytes))
	binary.BigEndian.PutUint32(result, uint32(len(innerBytes)*8)) // bit length
	copy(result[4:], innerBytes)

	return result
}

// readSSH2String reads a length-prefixed string from SSH2 binary data.
func readSSH2String(data []byte, offset int) (string, int, error) {
	if offset+4 > len(data) {
		return "", 0, fmt.Errorf("truncated string length")
	}
	length := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if offset+length > len(data) {
		return "", 0, fmt.Errorf("truncated string data")
	}
	return string(data[offset : offset+length]), 4 + length, nil
}

// readSSH2Uint32 reads a uint32 from SSH2 binary data.
func readSSH2Uint32(data []byte, offset int) (uint32, int, error) {
	if offset+4 > len(data) {
		return 0, 0, fmt.Errorf("truncated uint32")
	}
	return binary.BigEndian.Uint32(data[offset:]), 4, nil
}

// readSSH2BigInt reads a BigInt prefixed with bit length from SSH2 format.
func readSSH2BigInt(data []byte, offset int) (*big.Int, int, error) {
	if offset+4 > len(data) {
		return nil, 0, fmt.Errorf("truncated BigInt bit length")
	}
	bitLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	byteLen := (bitLen + 7) / 8
	if offset+byteLen > len(data) {
		return nil, 0, fmt.Errorf("truncated BigInt data (need %d bytes at offset %d, have %d)", byteLen, offset, len(data))
	}

	value := new(big.Int).SetBytes(data[offset : offset+byteLen])
	return value, 4 + byteLen, nil
}

// writeSSH2String writes a length-prefixed string for SSH2 binary format.
func writeSSH2String(s string) []byte {
	data := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(data, uint32(len(s)))
	copy(data[4:], s)
	return data
}

// writeSSH2BigIntTo writes a BigInt with bit-length prefix to a buffer.
func writeSSH2BigIntTo(buf *bytes.Buffer, value *big.Int) {
	b := value.Bytes()
	bitLen := value.BitLen()

	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(bitLen))
	buf.Write(lenBytes)
	buf.Write(b)
}

// isSSH2Format checks if data looks like SSH2 format.
func isSSH2Format(data []byte) bool {
	text := string(data)
	return strings.Contains(text, ssh2PublicKeyBegin) ||
		strings.Contains(text, ssh2PrivateKeyBegin)
}
