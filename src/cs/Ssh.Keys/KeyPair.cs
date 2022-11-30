// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.Keys;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Provides static methods for working with public-private key pairs, particularly
/// importing and exporting from/to various formats for interop with other SSH software.
/// </summary>
/// <remarks>
/// See <see cref="KeyFormat" /> for a description of formats supported for import and export.
/// </remarks>
public static class KeyPair
{
	/// <summary>
	/// Gets a dictionary of formatters for each supported key format.
	/// </summary>
	/// <remarks>
	/// Formatters may be replaced or modified to enable support for different key
	/// formats or algorithms. See <see cref="IKeyFormatter" /> for details.
	/// </remarks>
	public static IDictionary<KeyFormat, IKeyFormatter> Formatters { get; } =
		new Dictionary<KeyFormat, IKeyFormatter>
		{
			[KeyFormat.Default] = new DefaultKeyFormatter(),
			[KeyFormat.Ssh] = new PublicKeyFormatter(),
			[KeyFormat.Ssh2] = new Ssh2KeyFormatter(),
			[KeyFormat.Pkcs1] = new Pkcs1KeyFormatter(),
			[KeyFormat.Sec1] = new Sec1KeyFormatter(),
			[KeyFormat.Pkcs8] = new Pkcs8KeyFormatter(),
			[KeyFormat.OpenSsh] = new OpenSshKeyFormatter(),
			////[KeyFormat.Jwk] = TODO...
		};

	/// <summary>
	/// Exports the public key from a key pair, as a string.
	/// </summary>
	public static string ExportPublicKey(
		IKeyPair keyPair,
		KeyFormat keyFormat = default,
		KeyEncoding keyEncoding = default)
	{
		if (keyEncoding == KeyEncoding.Binary)
		{
			throw new ArgumentException("Cannot export binary key data as string.");
		}

		return Encoding.UTF8.GetString(ExportPublicKeyBytes(keyPair, keyFormat, keyEncoding));
	}

	/// <summary>
	/// Exports the public key from a key pair, to a file.
	/// </summary>
	public static void ExportPublicKeyFile(
		IKeyPair keyPair,
		string keyFile,
		KeyFormat keyFormat = default,
		KeyEncoding keyEncoding = default)
		=> File.WriteAllBytes(keyFile, ExportPublicKeyBytes(keyPair, keyFormat, keyEncoding));

	/// <summary>
	/// Exports the public key from a key pair, to a byte array.
	/// </summary>
	public static byte[] ExportPublicKeyBytes(
		IKeyPair keyPair,
		KeyFormat keyFormat = default,
		KeyEncoding keyEncoding = default)
		=> ExportKeyBytes(keyPair, null, keyFormat, keyEncoding, includePrivate: false);

	/// <summary>
	/// Exports the private key from a key pair, as a string.
	/// </summary>
	/// <exception cref="ArgumentException">The key pair does not have a private key.</exception>
	/// <exception cref="NotSupportedException">A passphrase was supplied, but the specified
	/// <paramref name="keyFormat"/> does not support encryption.</exception>
	public static string ExportPrivateKey(
		IKeyPair keyPair,
		string? passphrase = null,
		KeyFormat keyFormat = default,
		KeyEncoding keyEncoding = default)
	{
		if (keyEncoding == KeyEncoding.Binary)
		{
			throw new ArgumentException("Cannot export binary key data as string.");
		}

		return Encoding.UTF8.GetString(
			ExportPrivateKeyBytes(keyPair, passphrase, keyFormat, keyEncoding));
	}

	/// <summary>
	/// Exports the private key from a key pair, to a file.
	/// </summary>
	/// <exception cref="ArgumentException">The key pair does not have a private key.</exception>
	/// <exception cref="NotSupportedException">A passphrase was supplied, but the specified
	/// <paramref name="keyFormat"/> does not support encryption.</exception>
	public static void ExportPrivateKeyFile(
		IKeyPair keyPair,
		string keyFile,
		string? passphrase = null,
		KeyFormat keyFormat = default,
		KeyEncoding keyEncoding = default)
		=> File.WriteAllBytes(
			keyFile,
			ExportPrivateKeyBytes(keyPair, passphrase, keyFormat, keyEncoding));

	/// <summary>
	/// Exports the private key from a key pair, to a byte array.
	/// </summary>
	/// <exception cref="ArgumentException">The key pair does not have a private key.</exception>
	/// <exception cref="NotSupportedException">A passphrase was supplied, but the specified
	/// <paramref name="keyFormat"/> does not support encryption.</exception>
	public static byte[] ExportPrivateKeyBytes(
		IKeyPair keyPair,
		string? passphrase = null,
		KeyFormat keyFormat = default,
		KeyEncoding keyEncoding = default)
		=> ExportKeyBytes(keyPair, passphrase, keyFormat, keyEncoding, includePrivate: true);

	/// <summary>
	/// Imports a public key or public/private key pair from a string.
	/// </summary>
	/// <exception cref="UnauthorizedAccessException">The private key is encrypted and the
	/// <paramref name="passphrase"/> was missing or incorrect.</exception>
	public static IKeyPair ImportKey(
		string keyString,
		string? passphrase = null,
		KeyFormat keyFormat = default,
		KeyEncoding keyEncoding = default)
		=> ImportKeyBytes(Encoding.UTF8.GetBytes(keyString), passphrase, keyFormat, keyEncoding);

	/// <summary>
	/// Imports a public key or public/private key pair from a file.
	/// </summary>
	/// <exception cref="UnauthorizedAccessException">The private key is encrypted and the
	/// <paramref name="passphrase"/> was missing or incorrect.</exception>
	public static IKeyPair ImportKeyFile(
		string keyFile,
		string? passphrase = null,
		KeyFormat keyFormat = default,
		KeyEncoding keyEncoding = default)
		=> ImportKeyBytes(File.ReadAllBytes(keyFile), passphrase, keyFormat, keyEncoding);

	/// <summary>
	/// Imports a public key or public/private key pair from a byte array.
	/// </summary>
	/// <exception cref="UnauthorizedAccessException">The private key is encrypted and the
	/// <paramref name="passphrase"/> was missing or incorrect.</exception>
	public static IKeyPair ImportKeyBytes(
		byte[] keyBytes,
		string? passphrase = null,
		KeyFormat keyFormat = default,
		KeyEncoding keyEncoding = default)
	{
		if (keyBytes == null) throw new ArgumentNullException(nameof(keyBytes));

		KeyData? keyData = null;
		if (keyEncoding == KeyEncoding.Default || keyEncoding == KeyEncoding.Pem)
		{
			if (!KeyData.TryDecodePemBytes(keyBytes, out keyData) && keyEncoding == KeyEncoding.Pem)
			{
				throw new ArgumentException("Key is not PEM-encoded.");
			}
		}

		if (keyData == null &&
			(keyEncoding == KeyEncoding.Default || keyEncoding == KeyEncoding.Json))
		{
			string? keyString = null;
			try
			{
				keyString = Encoding.UTF8.GetString(keyBytes);
			}
			catch (ArgumentException)
			{
			}

			if (keyString != null && keyString.StartsWith("{", StringComparison.Ordinal))
			{
				throw new NotImplementedException("JWK importing is not implemented.");
			}
			else if (keyEncoding == KeyEncoding.Json)
			{
				throw new ArgumentException("Key is not JSON-formatted.");
			}
		}

		string? keyType = null;
		string? comment = null;

		if (keyData == null && (keyFormat == KeyFormat.Default || keyFormat == KeyFormat.Ssh) &&
			(keyEncoding == KeyEncoding.Default || keyEncoding == KeyEncoding.SshBase64))
		{
			try
			{
				var keyString = Encoding.UTF8.GetString(keyBytes);
				var lines = keyString.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
				if (lines.Length == 1)
				{
					keyString = lines[0];

					var parts = keyString.Split(
						new[] { ' ' }, 3, StringSplitOptions.RemoveEmptyEntries);
					if (parts.Length >= 2 && parts[0].Length < 40)
					{
						keyType = parts[0];
						keyBytes = Encoding.UTF8.GetBytes(parts[1]);
						comment = parts.Length == 3 ? parts[2].TrimEnd() : null;
						keyEncoding = KeyEncoding.Base64;
						keyFormat = KeyFormat.Ssh;
					}
				}
			}
			catch (ArgumentException)
			{
			}

			if (keyType == null && keyEncoding == KeyEncoding.SshBase64)
			{
				throw new ArgumentException("Key does not have SSH algorithm prefix.");
			}
		}

		if (keyData == null &&
			(keyEncoding == KeyEncoding.Default || keyEncoding == KeyEncoding.Base64))
		{
			try
			{
				keyBytes = Convert.FromBase64String(Encoding.UTF8.GetString(keyBytes));
				keyEncoding = KeyEncoding.Binary;
			}
			catch (Exception ex) when (ex is ArgumentException || ex is FormatException)
			{
				if (keyEncoding == KeyEncoding.Base64)
				{
					throw new ArgumentException("Key is not base64-encoded.", ex);
				}
			}
		}

		if (keyEncoding == KeyEncoding.Json)
		{
			throw new NotImplementedException("JSON key import is not implemented.");
		}

		if (keyData == null &&
			(keyEncoding == KeyEncoding.Default || keyEncoding == KeyEncoding.Binary))
		{
			keyData = new KeyData();
			keyData.Data = keyBytes;

			if (keyType != null)
			{
				keyData.KeyType = keyType;
			}

			if (comment != null)
			{
				keyData.Headers["Comment"] = comment;
			}
		}

		if (keyData == null)
		{
			throw new ArgumentException("Failed to decode key.");
		}

		if (keyFormat == KeyFormat.Default && string.IsNullOrEmpty(keyData.KeyType))
		{
			throw new ArgumentException("Specify a key format when importing binary data.");
		}

		if (!Formatters.TryGetValue(keyFormat, out var formatter))
		{
			throw new ArgumentException($"Invalid key format: {keyFormat}");
		}

		keyData = formatter.Decrypt(keyData, passphrase);
		if (keyData == null)
		{
			throw new ArgumentException($"Failed to decrypt key as format: {keyFormat}");
		}

		var keyPair = formatter.Import(keyData);
		if (keyPair == null)
		{
			throw new ArgumentException($"Failed to import key as format: {keyFormat}");
		}

		return keyPair;
	}

	private static byte[] ExportKeyBytes(
		IKeyPair keyPair,
		string? passphrase,
		KeyFormat keyFormat,
		KeyEncoding keyEncoding,
		bool includePrivate)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		if (includePrivate && !keyPair.HasPrivateKey)
		{
			throw new ArgumentException("The key pair object does not contain a private key.");
		}

		if (keyFormat == KeyFormat.Default)
		{
			keyFormat = includePrivate ? KeyFormat.Pkcs8 : KeyFormat.Ssh;
		}

		if (keyEncoding == KeyEncoding.Default)
		{
			keyEncoding = keyFormat switch
			{
				KeyFormat.Ssh => KeyEncoding.SshBase64,
				KeyFormat.Jwk => KeyEncoding.Json,
				_ => KeyEncoding.Pem,
			};
		}

		// Automatically switch between PKCS#1/SEC1 based on key algorithm.
		if (keyFormat == KeyFormat.Pkcs1 && keyPair is ECDsa.KeyPair)
		{
			keyFormat = KeyFormat.Sec1;
		}
		else if (keyFormat == KeyFormat.Sec1 && keyPair is Rsa.KeyPair)
		{
			keyFormat = KeyFormat.Pkcs1;
		}

		if (!Formatters.TryGetValue(keyFormat, out var formatter))
		{
			if (keyFormat == KeyFormat.Jwk)
			{
				throw new NotImplementedException("JWK export is not implemented.");
			}

			throw new ArgumentException($"Invalid key format: {keyFormat}");
		}

		var keyData = formatter.Export(keyPair, includePrivate);
		if (!string.IsNullOrEmpty(passphrase))
		{
			keyData = formatter.Encrypt(keyData, passphrase!);
		}

		return keyEncoding switch
		{
			KeyEncoding.Binary => keyData.Data,
			KeyEncoding.Base64 => Encoding.UTF8.GetBytes(Convert.ToBase64String(keyData.Data)),
			KeyEncoding.SshBase64 => keyData.EncodeSshPublicKeyBytes(),
			KeyEncoding.Pem => keyData.EncodePemBytes(),
			KeyEncoding.Json => throw new NotImplementedException(),
			_ => throw new ArgumentException($"Invalid key encoding: {keyEncoding}"),
		};
	}

	internal static EncryptionAlgorithm GetKeyEncryptionAlgorithm(string algorithm)
	{
		// Different formats may use different casing and hyphens. Normalize before comparing.
		algorithm = algorithm.ToUpperInvariant();
#if NETSTANDARD2_0 || NET4
		algorithm = algorithm.Replace("-", string.Empty);
#else
		algorithm = algorithm.Replace("-", string.Empty, StringComparison.Ordinal);
#endif

		return algorithm switch
		{
			"AES128CBC" => new EncryptionAlgorithm("aes128-cbc", "AES", CipherModeEx.CBC, 128),
			"AES128CTR" => new EncryptionAlgorithm("aes128-ctr", "AES", CipherModeEx.CTR, 128),
			"AES192CBC" => new EncryptionAlgorithm("aes192-cbc", "AES", CipherModeEx.CBC, 192),
			"AES192CTR" => new EncryptionAlgorithm("aes192-ctr", "AES", CipherModeEx.CTR, 192),
			"AES256CBC" => new EncryptionAlgorithm("aes256-cbc", "AES", CipherModeEx.CBC, 256),
			"AES256CTR" => new EncryptionAlgorithm("aes256-ctr", "AES", CipherModeEx.CTR, 256),
			"3DESCBC" => new EncryptionAlgorithm("3des-cbc", "3DES", CipherModeEx.CBC, 192),
			"DESEDE3CBC" => new EncryptionAlgorithm("3des-cbc", "3DES", CipherModeEx.CBC, 192),

			// Justification: CFB is used only for decrypting (importing) keys, not encrypting.
#pragma warning disable CA5358 // Do Not Use Unsafe Cipher Modes
			"DESEDE3CFB" => new EncryptionAlgorithm(
				"3des-cfb", "3DES", System.Security.Cryptography.CipherMode.CFB, 192),
#pragma warning restore CA5358 // Do Not Use Unsafe Cipher Modes

			_ => throw new NotSupportedException($"Key cipher not supported: {algorithm}"),
		};
	}
}
