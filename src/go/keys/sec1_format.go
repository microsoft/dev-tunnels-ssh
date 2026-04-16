// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// importSec1PrivateKey parses an ECDSA private key from SEC1 DER data.
func importSec1PrivateKey(der []byte) (ssh.KeyPair, error) {
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SEC1 private key: %w", err)
	}

	return ssh.NewEcdsaKeyPair(key)
}

// exportSec1PrivateKey exports an ECDSA private key in SEC1 PEM format (unencrypted).
func exportSec1PrivateKey(key ssh.KeyPair) ([]byte, error) {
	ecKey, ok := key.(*ssh.EcdsaKeyPair)
	if !ok {
		return nil, fmt.Errorf("sec1 format only supports ECDSA keys")
	}

	privKey := ecKey.PrivateKey()
	if privKey == nil {
		return nil, fmt.Errorf("private key not available")
	}

	der, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SEC1 private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}), nil
}

// importSec1WithFormat imports SEC1 data with PEM decoding.
func importSec1WithFormat(data []byte, passphrase string) (ssh.KeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid SEC1 PEM data")
	}

	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("not a SEC1 PEM type: %s", block.Type)
	}

	if isEncryptedPEM(block) {
		if passphrase == "" {
			return nil, fmt.Errorf("encrypted key requires a passphrase")
		}
		der, err := decryptPkcs1PEM(block, passphrase)
		if err != nil {
			return nil, err
		}
		return importSec1PrivateKey(der)
	}

	return importSec1PrivateKey(block.Bytes)
}
