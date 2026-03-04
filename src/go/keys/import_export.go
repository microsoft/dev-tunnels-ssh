// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

import (
	"encoding/pem"
	"fmt"
	"os"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
)

// ImportKey auto-detects the key format and imports a key from PEM, SSH, SSH2, or JWK format data.
// passphrase is used for encrypted keys; pass "" for unencrypted keys.
func ImportKey(data []byte, passphrase string) (ssh.KeyPair, error) {
	// Try PEM decode first.
	block, _ := pem.Decode(data)
	if block != nil {
		return importFromPEM(block, passphrase)
	}

	// Try SSH2 format (uses non-standard PEM markers with 4 dashes).
	if isSSH2Format(data) {
		return importSSH2Key(data, passphrase)
	}

	// Try SSH public key format.
	if isSSHPublicKeyFormat(data) {
		return importSSHPublicKey(data)
	}

	// Try JWK format.
	if isJwkFormat(data) {
		return importJwk(data)
	}

	return nil, fmt.Errorf("unsupported key format: unable to detect format from data")
}

// ImportKeyWithFormat imports a key in the specified format.
func ImportKeyWithFormat(data []byte, format KeyFormat, passphrase string) (ssh.KeyPair, error) {
	switch format {
	case KeyFormatDefault:
		return ImportKey(data, passphrase)
	case KeyFormatSSH:
		return importSSHPublicKey(data)
	case KeyFormatSSH2:
		return importSSH2Key(data, passphrase)
	case KeyFormatPkcs1:
		return importPkcs1WithFormat(data, passphrase)
	case KeyFormatSec1:
		return importSec1WithFormat(data, passphrase)
	case KeyFormatPkcs8:
		return importPkcs8WithFormat(data, passphrase)
	case KeyFormatOpenSSH:
		return importOpenSSHPrivateKey(data, passphrase)
	case KeyFormatJwk:
		return importJwk(data)
	default:
		return nil, fmt.Errorf("unsupported key format: %d", format)
	}
}

// ExportPublicKey exports a public key in the specified format.
func ExportPublicKey(key ssh.KeyPair, format KeyFormat) ([]byte, error) {
	if format == KeyFormatDefault {
		format = KeyFormatSSH
	}

	switch format {
	case KeyFormatSSH:
		return exportSSHPublicKey(key)
	case KeyFormatSSH2:
		return exportSSH2PublicKey(key)
	case KeyFormatPkcs1:
		return exportPkcs1PublicKey(key)
	case KeyFormatPkcs8:
		return exportPkcs8PublicKey(key)
	case KeyFormatJwk:
		return exportJwk(key)
	default:
		return nil, fmt.Errorf("unsupported public key export format: %d", format)
	}
}

// ExportPrivateKey exports a private key in the specified format, optionally encrypted.
// passphrase is used for encryption; pass "" for unencrypted export.
func ExportPrivateKey(key ssh.KeyPair, format KeyFormat, passphrase string) ([]byte, error) {
	if !key.HasPrivateKey() {
		return nil, fmt.Errorf("key does not contain a private key")
	}

	if format == KeyFormatDefault {
		format = KeyFormatPkcs8
	}

	switch format {
	case KeyFormatPkcs1:
		if passphrase != "" {
			return nil, fmt.Errorf("pkcs#1 encrypted export is not supported; use PKCS#8 instead")
		}
		return exportPkcs1PrivateKey(key)
	case KeyFormatSec1:
		if passphrase != "" {
			return nil, fmt.Errorf("sec1 encrypted export is not supported; use PKCS#8 instead")
		}
		return exportSec1PrivateKey(key)
	case KeyFormatPkcs8:
		return exportPkcs8PrivateKey(key, passphrase)
	case KeyFormatOpenSSH:
		return exportOpenSSHPrivateKey(key, passphrase)
	case KeyFormatSSH2:
		if passphrase != "" {
			return nil, fmt.Errorf("ssh2 encrypted export is not supported")
		}
		return exportSSH2PrivateKey(key)
	case KeyFormatJwk:
		if passphrase != "" {
			return nil, fmt.Errorf("jwk encrypted export is not supported")
		}
		return exportJwk(key)
	default:
		return nil, fmt.Errorf("unsupported private key export format: %d", format)
	}
}

// ImportKeyFile reads a key from a file, auto-detecting the format.
func ImportKeyFile(path, passphrase string) (ssh.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
	}
	return ImportKey(data, passphrase)
}

// ExportPublicKeyFile exports a public key to a file in the specified format.
func ExportPublicKeyFile(key ssh.KeyPair, path string, format KeyFormat) error {
	data, err := ExportPublicKey(key, format)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ExportPrivateKeyFile exports a private key to a file in the specified format.
func ExportPrivateKeyFile(key ssh.KeyPair, path string, format KeyFormat, passphrase string) error {
	data, err := ExportPrivateKey(key, format, passphrase)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// importFromPEM dispatches to the correct importer based on PEM type.
func importFromPEM(block *pem.Block, passphrase string) (ssh.KeyPair, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		if isEncryptedPEM(block) {
			if passphrase == "" {
				return nil, fmt.Errorf("encrypted key requires a passphrase")
			}
			der, err := decryptPkcs1PEM(block, passphrase)
			if err != nil {
				return nil, err
			}
			return importPkcs1PrivateKey(der)
		}
		return importPkcs1PrivateKey(block.Bytes)

	case "RSA PUBLIC KEY":
		return importPkcs1PublicKey(block.Bytes)

	case "EC PRIVATE KEY":
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

	case "PRIVATE KEY":
		return importPkcs8PrivateKey(block.Bytes)

	case "PUBLIC KEY":
		return importPkcs8PublicKey(block.Bytes)

	case "ENCRYPTED PRIVATE KEY":
		if passphrase == "" {
			return nil, fmt.Errorf("encrypted key requires a passphrase")
		}
		der, err := decryptPkcs8(block.Bytes, passphrase)
		if err != nil {
			return nil, err
		}
		return importPkcs8PrivateKey(der)

	case "OPENSSH PRIVATE KEY":
		return parseOpenSSHPrivateKey(block.Bytes, passphrase)

	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
}

// importPkcs1WithFormat imports PKCS#1 data with PEM decoding.
func importPkcs1WithFormat(data []byte, passphrase string) (ssh.KeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PKCS#1 PEM data")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		if isEncryptedPEM(block) {
			if passphrase == "" {
				return nil, fmt.Errorf("encrypted key requires a passphrase")
			}
			der, err := decryptPkcs1PEM(block, passphrase)
			if err != nil {
				return nil, err
			}
			return importPkcs1PrivateKey(der)
		}
		return importPkcs1PrivateKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return importPkcs1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("not a PKCS#1 PEM type: %s", block.Type)
	}
}

// importPkcs8WithFormat imports PKCS#8 data with PEM decoding.
func importPkcs8WithFormat(data []byte, passphrase string) (ssh.KeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PKCS#8 PEM data")
	}

	switch block.Type {
	case "PRIVATE KEY":
		return importPkcs8PrivateKey(block.Bytes)
	case "PUBLIC KEY":
		return importPkcs8PublicKey(block.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		if passphrase == "" {
			return nil, fmt.Errorf("encrypted key requires a passphrase")
		}
		der, err := decryptPkcs8(block.Bytes, passphrase)
		if err != nil {
			return nil, err
		}
		return importPkcs8PrivateKey(der)
	default:
		return nil, fmt.Errorf("not a PKCS#8 PEM type: %s", block.Type)
	}
}
