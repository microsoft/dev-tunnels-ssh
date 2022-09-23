// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Specifies how formatted key data is encoded into a string or file.
/// </summary>
/// <remarks>
/// Only some <see cref="KeyFormat" /> + <see cref="KeyEncoding" /> combinations are valid.
/// </remarks>
public enum KeyEncoding
{
	/// <summary>
	/// When importing, the encoding is auto-detected. When exporting, the defaults are:
	/// <see cref="SshBase64" /> for <see cref="KeyFormat.Ssh" />,
	/// <see cref="Json" /> for <see cref="KeyFormat.Jwk" />,
	/// <see cref="Pem" /> for other formats.
	/// </summary>
	Default = 0,

	/// <summary>
	/// DER or other binary encoding. Not valid for representation as a string.
	/// </summary>
	Binary = 1,

	/// <summary>
	/// Base64 encoding; same as <see cref="Binary" /> but encoded as base64.
	/// </summary>
	Base64 = 2,

	/// <summary>
	/// PEM encoding. Similar to <see cref="Base64" /> but with header, footer, and line breaks -
	/// https://tools.ietf.org/html/rfc1421
	/// </summary>
	Pem = 3,

	/// <summary>
	/// Base64 encoding with algorithm name prefix and optional comment suffix.
	/// </summary>
	SshBase64 = 4,

	/// <summary>
	/// JSON encoding. Only valid for <see cref="KeyFormat.Jwk" /> format.
	/// </summary>
	Json = 5,
}
