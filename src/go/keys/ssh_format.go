// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// importSSHPublicKey parses an SSH public key in the format: algorithm base64 [comment]
func importSSHPublicKey(data []byte) (ssh.KeyPair, error) {
	line := strings.TrimSpace(string(data))
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SSH public key format")
	}

	keyData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in SSH public key: %w", err)
	}

	kp, err := ssh.KeyPairFromPublicKeyBytes(keyData)
	if err != nil {
		return nil, err
	}

	if len(parts) == 3 {
		kp.SetComment(parts[2])
	}

	return kp, nil
}

// exportSSHPublicKey writes an SSH public key in the format: algorithm base64 [comment]
func exportSSHPublicKey(key ssh.KeyPair) ([]byte, error) {
	pubBytes, err := key.GetPublicKeyBytes()
	if err != nil {
		return nil, err
	}

	algorithm := key.KeyAlgorithmName()
	b64 := base64.StdEncoding.EncodeToString(pubBytes)

	var result string
	if key.Comment() != "" {
		result = fmt.Sprintf("%s %s %s\n", algorithm, b64, key.Comment())
	} else {
		result = fmt.Sprintf("%s %s\n", algorithm, b64)
	}
	return []byte(result), nil
}

// isSSHPublicKeyFormat checks if data looks like an SSH public key line.
func isSSHPublicKeyFormat(data []byte) bool {
	line := strings.TrimSpace(string(data))
	return strings.HasPrefix(line, "ssh-rsa ") ||
		strings.HasPrefix(line, "ssh-dss ") ||
		strings.HasPrefix(line, "ecdsa-sha2-")
}
