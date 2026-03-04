// Copyright (c) Microsoft Corporation. All rights reserved.

package keys

// KeyFormat specifies the format for key import/export.
type KeyFormat int

const (
	// KeyFormatDefault auto-detects on import; uses SSH for public, Pkcs8 for private on export.
	KeyFormatDefault KeyFormat = iota
	// KeyFormatSSH is the SSH public key format: "algorithm base64 [comment]".
	KeyFormatSSH
	// KeyFormatSSH2 is the SSH2/ssh.com format (RFC 4716).
	KeyFormatSSH2
	// KeyFormatPkcs1 is the PKCS#1 RSA format (RFC 8017).
	KeyFormatPkcs1
	// KeyFormatSec1 is the SEC1 EC format (RFC 5915).
	KeyFormatSec1
	// KeyFormatPkcs8 is the PKCS#8 format (RFC 5208).
	KeyFormatPkcs8
	// KeyFormatOpenSSH is the OpenSSH private key format.
	KeyFormatOpenSSH
	// KeyFormatJwk is the JSON Web Key format (RFC 7517).
	KeyFormatJwk
)
