// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Provides import/export of the <see cref="KeyFormat.Pkcs1" /> key format.
/// </summary>
public class Pkcs1KeyFormatter : IKeyFormatter
{
	private const string PublicKeyType = "RSA PUBLIC KEY";
	private const string PrivateKeyType = "RSA PRIVATE KEY";

	/// <inheritdoc/>
	public IKeyPair? Import(KeyData keyData)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		if (string.IsNullOrEmpty(keyData.KeyType))
		{
			// Automatically determine public or private by reading the first few bytes.
			try
			{
				var reader = new DerReader(keyData.Data);
				reader.ReadInteger();
				reader.ReadInteger();
				keyData.KeyType = reader.Available > 0 ? PrivateKeyType : PublicKeyType;
			}
			catch (Exception)
			{
				return null;
			}
		}

		RSAParameters? parameters = null;
		if (keyData.KeyType == PublicKeyType)
		{
			parameters = ImportRsaPublic(keyData.Data);
		}
		else if (keyData.KeyType == PrivateKeyType)
		{
			parameters = ImportRsaPrivate(keyData.Data);
		}

		if (parameters != null)
		{
			Rsa.KeyPair? keyPair = new Rsa.KeyPair();
			keyPair.ImportParameters(parameters.Value);
			return keyPair;
		}

		return null;
	}

	/// <inheritdoc/>
	public KeyData Export(IKeyPair keyPair, bool includePrivate)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		var keyAlgorithm = keyPair.KeyAlgorithmName;
		if (keyAlgorithm == Rsa.KeyAlgorithmName)
		{
			if (includePrivate)
			{
				return ExportRsaPrivate((Rsa.KeyPair)keyPair);
			}
			else
			{
				return ExportRsaPublic((Rsa.KeyPair)keyPair);
			}
		}
		else
		{
			throw new NotSupportedException(
				$"PKCS#1 format does not support key algorithm: {keyAlgorithm}");
		}
	}

	/// <inheritdoc/>
	public KeyData? Decrypt(KeyData keyData, string? passphrase)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		if (keyData.KeyType == PublicKeyType ||
			(string.IsNullOrEmpty(keyData.KeyType) && string.IsNullOrEmpty(passphrase)))
		{
			return keyData;
		}
		else if (keyData.KeyType == PrivateKeyType ||
			(string.IsNullOrEmpty(keyData.KeyType) && !string.IsNullOrEmpty(passphrase)))
		{
			if (keyData.Headers.TryGetValue("Proc-Type", out var procType) &&
				procType == "4,ENCRYPTED")
			{
				if (string.IsNullOrEmpty(passphrase))
				{
					throw new UnauthorizedAccessException(
						"A passphrase is required to decrypt the key.");
				}

				return DecryptPrivate(keyData, passphrase!);
			}
			else
			{
				return keyData;
			}
		}

		return null;
	}

	/// <inheritdoc/>
	public KeyData Encrypt(KeyData keyData, string passphrase)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		if (keyData.KeyType == PublicKeyType)
		{
			throw new ArgumentException("Public key cannot be encrypted.");
		}
		else if (keyData.KeyType == PrivateKeyType)
		{
			throw new NotSupportedException(
				"PKCS#1 export with passphrase is not supported because the format uses " +
				"a weak key derivation algorithm. Use a different format to export a " +
				"passphrase-protected private key.");
		}
		else
		{
			throw new InvalidOperationException($"Unexpected key type: {keyData.KeyType}");
		}
	}

	private static RSAParameters ImportRsaPublic(Buffer data)
	{
		var reader = new DerReader(data);
		return new RSAParameters
		{
			Modulus = reader.ReadInteger().ToByteArray(unsigned: true),
			Exponent = reader.ReadInteger().ToByteArray(unsigned: true),
		};
	}

	private static RSAParameters ImportRsaPrivate(Buffer data)
	{
		var reader = new DerReader(data);
		reader.ReadInteger(); // skip version

		return new RSAParameters
		{
			Modulus = reader.ReadInteger().ToByteArray(unsigned: true),
			Exponent = reader.ReadInteger().ToByteArray(unsigned: true),
			D = reader.ReadInteger().ToByteArray(unsigned: true),
			P = reader.ReadInteger().ToByteArray(unsigned: true),
			Q = reader.ReadInteger().ToByteArray(unsigned: true),
			DP = reader.ReadInteger().ToByteArray(unsigned: true),
			DQ = reader.ReadInteger().ToByteArray(unsigned: true),
			InverseQ = reader.ReadInteger().ToByteArray(unsigned: true),
		};
	}

	private static KeyData ExportRsaPublic(Rsa.KeyPair keyPair)
	{
		var parameters = keyPair.ExportParameters(false);

		var writer = new DerWriter();
		writer.WriteInteger(BigInt.FromByteArray(parameters.Modulus!, unsigned: true));
		writer.WriteInteger(BigInt.FromByteArray(parameters.Exponent!, unsigned: true));

		var data = writer.ToArray();

		return new KeyData
		{
			KeyType = "RSA PUBLIC KEY",
			Data = data,
		};
	}

	private static KeyData ExportRsaPrivate(Rsa.KeyPair keyPair)
	{
		var parameters = keyPair.ExportParameters(true);

		var writer = new DerWriter();

		writer.WriteInteger(BigInt.FromInt32(0)); // version

		writer.WriteInteger(BigInt.FromByteArray(parameters.Modulus!, unsigned: true));
		writer.WriteInteger(BigInt.FromByteArray(parameters.Exponent!, unsigned: true));
		writer.WriteInteger(BigInt.FromByteArray(parameters.D!, unsigned: true));
		writer.WriteInteger(BigInt.FromByteArray(parameters.P!, unsigned: true));
		writer.WriteInteger(BigInt.FromByteArray(parameters.Q!, unsigned: true));
		writer.WriteInteger(BigInt.FromByteArray(parameters.DP!, unsigned: true));
		writer.WriteInteger(BigInt.FromByteArray(parameters.DQ!, unsigned: true));
		writer.WriteInteger(BigInt.FromByteArray(parameters.InverseQ!, unsigned: true));

		var data = writer.ToArray();

		return new KeyData
		{
			KeyType = "RSA PRIVATE KEY",
			Data = data,
		};
	}

	internal static KeyData DecryptPrivate(KeyData keyData, string passphrase)
	{
		if (!keyData.Headers.TryGetValue("DEK-Info", out var decryptionInfo))
		{
			throw new NotSupportedException("PKCS#1 decryption parameters not found.");
		}

		var decryptionInfoParts = decryptionInfo.Split(',');
		var cipherName = decryptionInfoParts[0];

		var ivHex = decryptionInfoParts[1];
		byte[] iv = new byte[ivHex.Length / 2];
		for (int i = 0; i < iv.Length; i++)
			iv[i] = Convert.ToByte(ivHex.Substring(i * 2, 2), 16);

		var encryption = KeyPair.GetKeyEncryptionAlgorithm(cipherName);

		var key = DeriveDecryptionKey(
			Encoding.UTF8.GetBytes(passphrase), iv, encryption.KeyLength);

		var decryptedKeyData = new KeyData
		{
			KeyType = keyData.KeyType,
			Headers = keyData.Headers,
			Data = new Buffer(keyData.Data.Length).Array,
		};

		decryptedKeyData.Headers.Remove("Proc-Type");
		decryptedKeyData.Headers.Remove("DEK-Info");

		using var decipher = encryption.CreateCipher(isEncryption: false, key, iv);
		decipher.Transform(keyData.Data, decryptedKeyData.Data);

		// The first part of the key should be a DER sequence header.
		if (decryptedKeyData.Data[0] != (byte)(DerType.Constructed | DerType.Sequence))
		{
			throw new UnauthorizedAccessException(
				"Key decryption failed - incorrect passphrase.");
		}

		return decryptedKeyData;
	}

	private static byte[] DeriveDecryptionKey(
		byte[] passphraseBytes, byte[] iv, int keyLength)
	{
		// Reference EVP_BytesToKey() from
		// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/evp/evp_key.c#L74

		// Justification: MD5 is used only for decrypting (importing) keys, not encrypting.
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
		using HashAlgorithm hash = MD5.Create();
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms
#pragma warning restore CA5351 // Do Not Use Broken Cryptographic Algorithms

		const int PKCS5_SALT_LEN = 8;
		var salt = iv.Take(PKCS5_SALT_LEN);

		byte[] key = Array.Empty<byte>();
		while (key.Length < keyLength)
		{
			var digest = hash.ComputeHash(key.Concat(passphraseBytes).Concat(salt).ToArray());
			key = key.Concat(digest).ToArray();
		}

		key = key.Take(keyLength).ToArray();
		return key;
	}
}
