// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Linq;
using Microsoft.DevTunnels.Ssh.Algorithms;

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Auto-detects the format of a key when importing, by trying all the available formatters.
/// </summary>
internal class DefaultKeyFormatter : IKeyFormatter
{
	KeyData IKeyFormatter.Encrypt(KeyData keyData, string passphrase) =>
		throw new InvalidOperationException(
			$"{nameof(DefaultKeyFormatter)} should not be used for encrypting.");
	KeyData IKeyFormatter.Export(IKeyPair keyPair, bool includePrivate) =>
		throw new InvalidOperationException(
			$"{nameof(DefaultKeyFormatter)} should not be used for exporting.");

	public KeyData? Decrypt(KeyData keyData, string? passphrase)
	{
		foreach (var format in KeyPair.Formatters.Keys
			.Where((f) => f != default && f != KeyFormat.Ssh && f != KeyFormat.Jwk))
		{
			var formatter = KeyPair.Formatters[format];
			var decryptedKeyData = formatter.Decrypt(keyData, passphrase);
			if (decryptedKeyData != null)
			{
				return decryptedKeyData;
			}
		}

		return null;
	}

	public IKeyPair? Import(KeyData keyData)
	{
		foreach (var format in KeyPair.Formatters.Keys
			.Where((f) => f != default && f != KeyFormat.Ssh && f != KeyFormat.Jwk))
		{
			var formatter = KeyPair.Formatters[format];
			var keyPair = formatter.Import(keyData);
			if (keyPair != null)
			{
				return keyPair;
			}
		}

		return null;
	}
}
