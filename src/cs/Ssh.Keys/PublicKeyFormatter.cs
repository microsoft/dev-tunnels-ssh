// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Provides import/export of the <see cref="KeyFormat.Ssh" /> public key format.
/// </summary>
public class PublicKeyFormatter : IKeyFormatter
{
	/// <inheritdoc/>
	public IKeyPair? Import(KeyData keyData)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		if (string.IsNullOrEmpty(keyData.KeyType))
		{
			// Try to parse binary data without any key type prefix.
			try
			{
				var reader = new SshDataReader(keyData.Data);
				keyData.KeyType = reader.ReadString(Encoding.ASCII);
			}
			catch (Exception)
			{
				return null;
			}
		}

		if (keyData.KeyType == Rsa.KeyAlgorithmName)
		{
			var keyPair = new Rsa.KeyPair();
			keyPair.SetPublicKeyBytes(keyData.Data);
			keyPair.Comment = keyData.Headers.TryGetValue("Comment", out var comment)
				? comment : null;
			return keyPair;
		}
		else if (keyData.KeyType == ECDsa.ECDsaSha2Nistp256 ||
			keyData.KeyType == ECDsa.ECDsaSha2Nistp384 ||
			keyData.KeyType == ECDsa.ECDsaSha2Nistp521)
		{
			var keyPair = new ECDsa.KeyPair();
			keyPair.SetPublicKeyBytes(keyData.Data);
			keyPair.Comment = keyData.Headers.TryGetValue("Comment", out var comment)
				? comment : null;
			return keyPair;
		}

		return null;
	}

	/// <inheritdoc/>
	public KeyData Export(IKeyPair keyPair, bool includePrivate)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		if (includePrivate)
		{
			throw new NotSupportedException(
				"SSH public key formatter does not support private keys.");
		}

		var keyData = new KeyData();
		keyData.KeyType = keyPair.KeyAlgorithmName;
		keyData.Data = keyPair.GetPublicKeyBytes().ToArray();

		if (!string.IsNullOrEmpty(keyPair.Comment))
		{
			keyData.Headers["Comment"] = keyPair.Comment!;
		}

		return keyData;
	}

	/// <inheritdoc/>
	public KeyData? Decrypt(KeyData keyData, string? passphrase) => keyData;

	/// <inheritdoc/>
	public KeyData Encrypt(KeyData keyData, string? passphrase) =>
		throw new NotSupportedException("SSH public key format does not support encryption.");
}
