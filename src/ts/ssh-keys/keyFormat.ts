//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * Specifies the format of a public or private key for importing or exporting.
 *
 * (Some formats are not yet implemented.)
 */
export const enum KeyFormat {
	/**
	 * When importing, the format is auto-detected. When exporting, the defaults are:
	 * Ssh for public keys, Pkcs1 for private keys.
	 */
	Default = 0,

	/** SSH public key format. */
	Ssh = 1,

	/**
	 * SSH2 (ssh.com) public or private key format. PEM encoded keys begin with one of:
	 * ---- BEGIN SSH2 PUBLIC KEY ----
	 * ---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
	 */
	Ssh2 = 2,

	/**
	 * PKCS#1 public or private key format. PEM-encoded keys begin with one of:
	 * -----BEGIN RSA PUBLIC KEY-----
	 * -----BEGIN RSA PRIVATE KEY-----
	 */
	Pkcs1 = 3,

	/**
	 * SEC1 private EC key format. PEM-encoded keys begin with:
	 * -----BEGIN EC PRIVATE KEY-----
	 */
	Sec1 = 4,

	/**
	 * PKCS#8 public or private key format. PEM-encoded keys begin with one of:
	 * -----BEGIN PUBLIC KEY-----
	 * -----BEGIN PRIVATE KEY-----
	 * -----BEGIN ENCRYPTED PRIVATE KEY-----
	 */
	Pkcs8 = 5,

	/**
	 * OpenSSH private key format. PEM-encoded keys begin with:
	 * -----BEGIN OPENSSH PRIVATE KEY-----
	 */
	OpenSsh = 6,

	/** JSON Web Key public or private key format. */
	Jwk = 7,
}
