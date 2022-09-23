// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Specifies the format of a public or private key for importing or exporting.
/// </summary>
/// <remarks>
/// Some formats are not yet implemented.
/// </remarks>
public enum KeyFormat
{
	/// <summary>
	/// When importing, the format is auto-detected. When exporting, the defaults are:
	/// <see cref="Ssh" /> for public keys,
	/// <see cref="Pkcs8" /> for private keys.
	/// </summary>
	Default = 0,

	/// <summary>
	/// SSH public key format - https://tools.ietf.org/html/rfc4253#section-6.6
	/// </summary>
	Ssh = 1,

	/// <summary>
	/// SSH2 (ssh.com) public or private key format - https://tools.ietf.org/html/rfc4716
	/// </summary>
	/// <remarks>
	/// Note SSH2 keys use a nonstandard variation of PEM encoding: headers have four hyphens and
	/// a space instead of five hyphens, among other differences. They can be recognized by one
	/// of the following headers:
	/// ---- BEGIN SSH2 PUBLIC KEY ----
	/// ---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
	/// </remarks>
	Ssh2 = 2,

	/// <summary>
	/// Public-Key Cryptography Standards #1 public or private RSA key format -
	/// https://tools.ietf.org/html/rfc8017
	/// </summary>
	/// <remarks>
	/// PEM-encoded PKCS1 keys can be recognized by one of the following headers:
	/// -----BEGIN RSA PUBLIC KEY-----
	/// -----BEGIN RSA PRIVATE KEY-----
	/// </remarks>
	Pkcs1 = 3,

	/// <summary>
	/// SEC1 private EC key format - https://tools.ietf.org/html/rfc5915
	/// </summary>
	/// <remarks>
	/// PEM-encoded SEC1 keys can be recognized by the following header:
	/// -----BEGIN EC PRIVATE KEY-----
	/// </remarks>
	Sec1 = 4,

	/// <summary>
	/// Public-Key Cryptography Standards #8 public or private key format -
	/// https://tools.ietf.org/html/rfc5208
	/// </summary>
	/// <remarks>
	/// PEM-encoded PKCS8 keys can be recognized by one of the following headers:
	/// -----BEGIN PUBLIC KEY-----
	/// -----BEGIN PRIVATE KEY-----
	/// -----BEGIN ENCRYPTED PRIVATE KEY-----
	/// </remarks>
	Pkcs8 = 5,

	/// <summary>
	/// OpenSSH private key format -
	/// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
	/// </summary>
	/// <remarks>
	/// PEM-encoded OpenSSH private keys can be recognized by the following header:
	/// -----BEGIN OPENSSH PRIVATE KEY-----
	/// </remarks>
	OpenSsh = 6,

	/// <summary>
	/// JSON Web Key public or private key format - https://tools.ietf.org/html/rfc7517
	/// </summary>
	Jwk = 7,
}
