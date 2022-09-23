// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Provides import/export of the <see cref="KeyFormat.Ssh2" /> key format.
/// </summary>
public class Ssh2KeyFormatter : IKeyFormatter
{
	private const string PublicKeyType = "SSH2 PUBLIC KEY";
	private const string PrivateKeyType = "SSH2 ENCRYPTED PRIVATE KEY";
	private const uint Ssh2FileMagicNumber = 0x3f6ff9eb;

	public Ssh2KeyFormatter()
	{
		Importers["rsa-pkcs1v2-oaep"] = ImportRsaKey;
		Importers[Rsa.KeyAlgorithmName] = ImportRsaKey;
		Exporters[Rsa.KeyAlgorithmName] = ExportRsaKey;
	}

	public delegate IKeyPair Importer(
		ref SshDataReader keyReader,
		string? privateKeyInfo);
	public delegate string? Exporter(
		IKeyPair keyPair,
		ref SshDataWriter keyWriter,
		bool includePrivate);

	/// <summary>
	/// Gets a mapping from public key algorithm name or ssh.com algorithm name to import handler
	/// for that algorithm.
	/// </summary>
	public IDictionary<string, Importer> Importers { get; } = new Dictionary<string, Importer>();

	/// <summary>
	/// Gets a mapping from public key algorithm name to export handler for that algorithm.
	/// </summary>
	public IDictionary<string, Exporter> Exporters { get; } = new Dictionary<string, Exporter>();

	/// <inheritdoc/>
	public IKeyPair? Import(KeyData keyData)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		if (string.IsNullOrEmpty(keyData.KeyType))
		{
			// Automatically determine public or private by reading the first few bytes.
			var reader = new SshDataReader(keyData.Data);
			if (reader.ReadUInt32() == Ssh2FileMagicNumber)
			{
				keyData.KeyType = PrivateKeyType;
			}
			else
			{
				string keyAlgorithm;
				try
				{
					reader.Position = 0;
					keyAlgorithm = reader.ReadString(Encoding.ASCII);
				}
				catch (Exception)
				{
					return null;
				}

				if (keyAlgorithm.StartsWith("ssh-", StringComparison.Ordinal))
				{
					keyData.KeyType = PublicKeyType;
				}
			}
		}

		if (keyData.KeyType == PublicKeyType)
		{
			return ImportPublic(keyData);
		}
		else if (keyData.KeyType == PrivateKeyType)
		{
			return ImportPrivate(keyData);
		}

		return null;
	}

	/// <inheritdoc/>
	public KeyData Export(IKeyPair keyPair, bool includePrivate)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		if (includePrivate)
		{
			return ExportPrivate(keyPair);
		}
		else
		{
			return ExportPublic(keyPair);
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
			return DecryptPrivate(keyData, passphrase);
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
			return EncryptPrivate(keyData, passphrase);
		}

		return keyData;
	}

	private IKeyPair ImportPublic(KeyData keyData)
	{
		var keyReader = new SshDataReader(keyData.Data);
		var keyAlgorithm = keyReader.ReadString(Encoding.ASCII);

		if (!Importers.TryGetValue(keyAlgorithm, out var import))
		{
			throw new NotSupportedException(
				$"No SSH2 importer available for key algorithm: {keyAlgorithm}");
		}

		keyReader = new SshDataReader(keyData.Data);
		var keyPair = import(ref keyReader, null);
		keyPair.Comment =
			keyData.Headers.TryGetValue("Comment", out var comment) ? comment : null;
		return keyPair;
	}

	private IKeyPair ImportPrivate(KeyData keyData)
	{
		var reader = new SshDataReader(keyData.Data);
		var magicNumber = reader.ReadUInt32();
		if (magicNumber != 0x3f6ff9eb)
		{
			throw new ArgumentException("Invalid SSH2 private key.");
		}

		var totalLength = reader.ReadUInt32();
		var keyType = reader.ReadString(Encoding.ASCII);
		var cipherName = reader.ReadString(Encoding.ASCII);
		var privateKeyData = reader.ReadBinary();
		var keyReader = new SshDataReader(privateKeyData);

		if (cipherName != "none")
		{
			throw new ArgumentException("Key must be decrypted first.");
		}

		var length = keyReader.ReadUInt32();
		if (length != privateKeyData.Count - 4)
		{
			throw new ArgumentException("Invalid SSH2 private key.");
		}

		var lastOpenBrace = keyType.LastIndexOf('{');
		if (!keyType.EndsWith("}}", StringComparison.Ordinal) || lastOpenBrace < 0)
		{
			throw new ArgumentException($"Invalid SSH2 key type: {keyType}");
		}

		var keyAlgorithm = keyType.Substring(
			lastOpenBrace + 1,
			keyType.Length - 2 - (lastOpenBrace + 1));
		if (!Importers.TryGetValue(keyAlgorithm, out var import))
		{
			throw new NotSupportedException(
				$"No SSH2 importer available for key algorithm: {keyAlgorithm}");
		}

		var keyPair = import(ref keyReader, keyType);
		keyPair.Comment =
			keyData.Headers.TryGetValue("Comment", out var comment) ? comment : null;
		return keyPair;
	}

	private static IKeyPair ImportRsaKey(ref SshDataReader keyReader, string? privateKeyInfo)
	{
		if (privateKeyInfo == null)
		{
			var keyPair = new Rsa.KeyPair();
			keyPair.SetPublicKeyBytes(keyReader.Buffer);
			return keyPair;
		}

		if (privateKeyInfo == "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}")
		{
			var exponent = keyReader.ReadBigInt(lengthInBits: true);
			var d = keyReader.ReadBigInt(lengthInBits: true);
			var modulus = keyReader.ReadBigInt(lengthInBits: true);
			var iq = keyReader.ReadBigInt(lengthInBits: true);
			var q = keyReader.ReadBigInt(lengthInBits: true);
			var p = keyReader.ReadBigInt(lengthInBits: true);

			// dp = d % (p - 1)
			// dq = d % (q - 1)
			var dp = (BigInt)((BigInteger)d % ((BigInteger)p - 1));
			var dq = (BigInt)((BigInteger)d % ((BigInteger)q - 1));

			var parameters = new RSAParameters
			{
				Modulus = modulus.ToByteArray(unsigned: true),
				Exponent = exponent.ToByteArray(unsigned: true),
				D = d.ToByteArray(unsigned: true),
				P = p.ToByteArray(unsigned: true),
				Q = q.ToByteArray(unsigned: true),
				DP = dp.ToByteArray(unsigned: true),
				DQ = dq.ToByteArray(unsigned: true),
				InverseQ = iq.ToByteArray(unsigned: true),
			};
			var keyPair = new Rsa.KeyPair();
			keyPair.ImportParameters(parameters);
			return keyPair;
		}
		else
		{
			throw new NotSupportedException($"SSH2 key type not supported: {privateKeyInfo}");
		}
	}

	private KeyData ExportPublic(IKeyPair keyPair)
	{
		if (!Exporters.TryGetValue(keyPair.KeyAlgorithmName, out var export))
		{
			throw new NotSupportedException(
				$"No SSH2 exporter available for key algorithm: {keyPair.KeyAlgorithmName}");
		}

		var keyWriter = new SshDataWriter();
		export(keyPair, ref keyWriter, includePrivate: false);

		// SSH2 has nonstandard formatting for PEM hyphens and headers.
		var keyData = new KeyData(hyphenCount: 4, quoteHeaders: true, lineLength: 70)
		{
			KeyType = "SSH2 PUBLIC KEY",
			Data = keyWriter.ToBuffer().ToArray(),
		};

		if (!string.IsNullOrEmpty(keyPair.Comment))
		{
			keyData.Headers["Comment"] = keyPair.Comment!;
		}

		return keyData;
	}

	private KeyData ExportPrivate(IKeyPair keyPair)
	{
		if (!Exporters.TryGetValue(keyPair.KeyAlgorithmName, out var export))
		{
			throw new NotSupportedException(
				$"No SSH2 exporter available for key algorithm: {keyPair.KeyAlgorithmName}");
		}

		var keyWriter = new SshDataWriter();
		var keyType = export(keyPair, ref keyWriter, includePrivate: true);
		var cipherName = "none";

		var writer = new SshDataWriter();
		writer.Write(0x3f6ff9eb);
		writer.Write(0U); // Total length placeholder
		writer.Write(keyType!, Encoding.ASCII);
		writer.Write(cipherName, Encoding.ASCII);
		writer.Write((uint)keyWriter.Position + 4);
		writer.WriteBinary(keyWriter.ToBuffer());
		var totalLength = writer.Position;
		writer.Position = 4;
		writer.Write((uint)totalLength);
		writer.Position = totalLength;

		// SSH2 has nonstandard formatting for PEM hyphens and headers.
		var keyData = new KeyData(hyphenCount: 4, quoteHeaders: true, lineLength: 70)
		{
			KeyType = "SSH2 ENCRYPTED PRIVATE KEY",
			Data = writer.ToBuffer().ToArray(),
		};

		if (!string.IsNullOrEmpty(keyPair.Comment))
		{
			keyData.Headers["Comment"] = keyPair.Comment!;
		}

		return keyData;
	}

	private static string? ExportRsaKey(
		IKeyPair keyPair,
		ref SshDataWriter keyWriter,
		bool includePrivate)
	{
		if (!includePrivate)
		{
			keyWriter.Write(keyPair.GetPublicKeyBytes());
			return null;
		}

		var parameters = ((Rsa.KeyPair)keyPair).ExportParameters(true);

		var exponent = BigInt.FromByteArray(parameters.Exponent!, unsigned: true);
		var d = BigInt.FromByteArray(parameters.D!, unsigned: true);
		var modulus = BigInt.FromByteArray(parameters.Modulus!, unsigned: true);
		var iq = BigInt.FromByteArray(parameters.InverseQ!, unsigned: true);
		var q = BigInt.FromByteArray(parameters.Q!, unsigned: true);
		var p = BigInt.FromByteArray(parameters.P!, unsigned: true);

		keyWriter.Write(exponent, lengthInBits: true);
		keyWriter.Write(d, lengthInBits: true);
		keyWriter.Write(modulus, lengthInBits: true);
		keyWriter.Write(iq, lengthInBits: true);
		keyWriter.Write(q, lengthInBits: true);
		keyWriter.Write(p, lengthInBits: true);

		return "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}";
	}

	private static KeyData DecryptPrivate(KeyData keyData, string? passphrase)
	{
		var reader = new SshDataReader(keyData.Data);
		var magicNumber = reader.ReadUInt32();
		if (magicNumber != 0x3f6ff9eb)
		{
			throw new ArgumentException("Invalid SSH2 private key.");
		}

		var totalLength = reader.ReadUInt32();
		var keyType = reader.ReadString(Encoding.ASCII);
		var cipherName = reader.ReadString(Encoding.ASCII);

		if (cipherName == "none")
		{
			return keyData;
		}

		if (string.IsNullOrEmpty(passphrase))
		{
			throw new UnauthorizedAccessException(
				"A passphrase is required to decrypt the key.");
		}

		var privateKeyData = reader.ReadBinary();

		var encryption = KeyPair.GetKeyEncryptionAlgorithm(cipherName);
		var key = DeriveSsh2DecryptionKey(
			Encoding.UTF8.GetBytes(passphrase), encryption.KeyLength);
		var iv = new byte[encryption.BlockLength];
		using var decipher = encryption.CreateCipher(isEncryption: false, key, iv);
		decipher.Transform(privateKeyData, privateKeyData);

		var keyReader = new SshDataReader(privateKeyData);
		uint length = keyReader.ReadUInt32();

		// Length plus length-size, rounded up to block size, should be equal to data length.
		// The data includes random padding (not PKCS#7 padding) up to block size.
		if ((length + 4 + encryption.BlockLength - 1) / encryption.BlockLength *
			encryption.BlockLength != privateKeyData.Count)
		{
			throw new UnauthorizedAccessException(
				"Key decryption failed - incorrect passphrase.");
		}

		// Trim the padding.
		privateKeyData = privateKeyData.Slice(0, (int)length + 4);

		// Reformat as an unencrypted SSH2 key.
		cipherName = "none";

		var writer = new SshDataWriter();
		writer.Write(magicNumber);
		writer.Write(totalLength);
		writer.Write(keyType, Encoding.ASCII);
		writer.Write(cipherName, Encoding.ASCII);
		writer.WriteBinary(privateKeyData);

		return new KeyData
		{
			KeyType = "SSH2 ENCRYPTED PRIVATE KEY",
			Data = writer.ToBuffer().ToArray(),
			Headers = new Dictionary<string, string>(keyData.Headers),
		};
	}

	private static byte[] DeriveSsh2DecryptionKey(byte[] passphraseBytes, int keyLength)
	{
		// Justification: MD5 is used only for decrypting (importing) keys, not encrypting.
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
		using HashAlgorithm hash = MD5.Create();
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms
#pragma warning restore CA5351 // Do Not Use Broken Cryptographic Algorithms

		byte[] key = Array.Empty<byte>();
		byte[] block = Array.Empty<byte>();
		while (key.Length < keyLength)
		{
			block = hash.ComputeHash(passphraseBytes.Concat(block).ToArray());
			key = key.Concat(block).ToArray();
		}

		key = key.Take(keyLength).ToArray();
		return key;
	}

	private static KeyData EncryptPrivate(KeyData keyData, string passphrase)
	{
		throw new NotSupportedException(
			"SSH2 export with passphrase is not supported because the format uses " +
			"a weak key derivation algorithm. Use a different format to export a " +
			"passphrase-protected private key.");
	}
}
