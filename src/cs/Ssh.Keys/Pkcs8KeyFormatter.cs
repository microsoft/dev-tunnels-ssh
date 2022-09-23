// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.IO;
using ECDsa = Microsoft.DevTunnels.Ssh.Algorithms.ECDsa;

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Provides import/export of the <see cref="KeyFormat.Pkcs8" /> key format.
/// </summary>
public class Pkcs8KeyFormatter : IKeyFormatter
{
	private const string PublicKeyType = "PUBLIC KEY";
	private const string PrivateKeyType = "PRIVATE KEY";
	private const string EncryptedPrivateKeyType = "ENCRYPTED PRIVATE KEY";

	public Pkcs8KeyFormatter()
	{
		Importers[Oids.Rsa.Value!] = ImportRsaKey;
		Importers[Oids.EC.Value!] = ImportECKey;
		Exporters[Rsa.KeyAlgorithmName] = ExportRsaKey;
		Exporters[ECDsa.ECDsaSha2Nistp256] = ExportECKey;
		Exporters[ECDsa.ECDsaSha2Nistp384] = ExportECKey;
		Exporters[ECDsa.ECDsaSha2Nistp521] = ExportECKey;
	}

	public delegate IKeyPair Importer(
		Buffer keyBytes,
		ref DerReader oidReader,
		bool includePrivate);
	public delegate Buffer Exporter(
		IKeyPair keyPair,
		ref DerWriter oidWriter,
		bool includePrivate);

	/// <summary>
	/// Gets a mapping from public key algorithm OID to import handler for that algorithm.
	/// </summary>
	public IDictionary<string, Importer> Importers { get; } = new Dictionary<string, Importer>();

	/// <summary>
	/// Gets a mapping from public key algorithm name to export handler for that algorithm.
	/// </summary>
	public IDictionary<string, Exporter> Exporters { get; } = new Dictionary<string, Exporter>();

	/// <summary>
	/// Enables overriding randomness for predictable testing.
	/// </summary>
	public IRandom Random { get; set; } = SshAlgorithms.Random;

	/// <summary>
	/// Gets or sets the number of PBKDF2 iterations used when exporting a passphrase-protected
	/// PKCS#8-formatted key.
	/// </summary>
	/// <remarks>
	/// At least 100,000 iterations are recommended for good security.
	/// </remarks>
	public int Pbkdf2Iterations { get; set; } = 100_000;

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
				if (reader.Peek() == (DerType.Constructed | DerType.Sequence))
				{
					keyData.KeyType = PublicKeyType;
				}
				else if (reader.Peek() == DerType.Integer)
				{
					keyData.KeyType = PrivateKeyType;
				}
			}
			catch (Exception)
			{
				return null;
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
		else if (keyData.KeyType == EncryptedPrivateKeyType)
		{
			throw new InvalidOperationException("Decrypt before importing.");
		}

		return null;
	}

	/// <inheritdoc/>
	public KeyData Export(IKeyPair keyPair, bool includePrivate)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		if (includePrivate)
		{
			if (!keyPair.HasPrivateKey)
			{
				throw new InvalidOperationException(
					"KeyPair object does not contain the private key.");
			}

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

		if (keyData.KeyType == PublicKeyType || keyData.KeyType == PrivateKeyType ||
			(string.IsNullOrEmpty(keyData.KeyType) && string.IsNullOrEmpty(passphrase)))
		{
			return keyData;
		}
		else if (keyData.KeyType == EncryptedPrivateKeyType ||
			(string.IsNullOrEmpty(keyData.KeyType) && !string.IsNullOrEmpty(passphrase)))
		{
			if (string.IsNullOrEmpty(passphrase))
			{
				throw new UnauthorizedAccessException(
					"A passphrase is required to decrypt the key.");
			}

			return DecryptPrivate(keyData, passphrase!);
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
			return EncryptPrivate(keyData, passphrase, Random);
		}
		else if (keyData.KeyType == EncryptedPrivateKeyType)
		{
			throw new InvalidOperationException("Already encrypted.");
		}
		else
		{
			throw new InvalidOperationException($"Unexpected key type: {keyData.KeyType}");
		}
	}

	private IKeyPair ImportPublic(KeyData keyData)
	{
		var reader = new DerReader(keyData.Data);
		var oidReader = reader.ReadSequence();
		var keyAlgorithm = oidReader.ReadObjectIdentifier();
		var keyBytes = reader.ReadBitString();

		if (!Importers.TryGetValue(keyAlgorithm.Value!, out var import))
		{
			throw new NotSupportedException(
				$"No PKCS#8 importer available for key algorithm: {keyAlgorithm.Value}");
		}

		return import(keyBytes, ref oidReader, includePrivate: false);
	}

	private IKeyPair ImportPrivate(KeyData keyData)
	{
		var reader = new DerReader(keyData.Data);
		var version = reader.ReadInteger().ToInt32();
		if (version != 0)
		{
			throw new NotSupportedException($"PKCS#8 format version not supported: {version}");
		}

		var oidReader = reader.ReadSequence();
		var keyAlgorithm = oidReader.ReadObjectIdentifier();
		var keyBytes = reader.ReadOctetString();

		if (!Importers.TryGetValue(keyAlgorithm.Value!, out var import))
		{
			throw new NotSupportedException(
				$"No PKCS#8 importer available for key algorithm: {keyAlgorithm.Value}");
		}

		return import(keyBytes, ref oidReader, includePrivate: true);
	}

	private static IKeyPair ImportRsaKey(
		Buffer keyBytes,
		ref DerReader oidReader,
		bool includePrivate)
	{
		var keyReader = new DerReader(keyBytes);
		if (includePrivate)
		{
			var version = keyReader.ReadInteger().ToInt32();
			if (version != 0)
			{
				throw new NotSupportedException(
					$"PKCS#8 RSA key format version not supported: {version}");
			}
		}

		var parameters = new RSAParameters
		{
			Modulus = keyReader.ReadInteger().ToByteArray(unsigned: true),
			Exponent = keyReader.ReadInteger().ToByteArray(unsigned: true),
		};

		if (includePrivate)
		{
			parameters.D = keyReader.ReadInteger().ToByteArray(unsigned: true);
			parameters.P = keyReader.ReadInteger().ToByteArray(unsigned: true);
			parameters.Q = keyReader.ReadInteger().ToByteArray(unsigned: true);
			parameters.DP = keyReader.ReadInteger().ToByteArray(unsigned: true);
			parameters.DQ = keyReader.ReadInteger().ToByteArray(unsigned: true);
			parameters.InverseQ = keyReader.ReadInteger().ToByteArray(unsigned: true);
		}

		var keyPair = new Rsa.KeyPair();
		keyPair.ImportParameters(parameters);
		return keyPair;
	}

	private static IKeyPair ImportECKey(
		Buffer keyBytes,
		ref DerReader oidReader,
		bool includePrivate)
	{
		var curveOid = oidReader.ReadObjectIdentifier();
		var curve = ECCurve.CreateFromOid(curveOid);

		Buffer publicKeyBytes;
		Buffer privateKeyBytes = Buffer.Empty;
		if (includePrivate)
		{
			var keyReader = new DerReader(keyBytes);
			var version = keyReader.ReadInteger().ToInt32();
			if (version != 1)
			{
				throw new NotSupportedException(
					$"PKCS#8 EC key format version not supported: {version}");
			}

			privateKeyBytes = keyReader.ReadOctetString();

			if (!keyReader.TryReadTagged(1, out var publicKeyReader))
			{
				throw new InvalidOperationException("Failed to read EC public key data.");
			}

			publicKeyBytes = publicKeyReader.ReadBitString();
		}
		else
		{
			publicKeyBytes = keyBytes;
		}

		if (publicKeyBytes.Count % 2 != 1)
		{
			throw new InvalidOperationException(
				$"Unexpected key data length: {publicKeyBytes.Count}");
		}

		// 4 = uncompressed curve format
		var dataFormat = publicKeyBytes[0];
		if (dataFormat != 4)
		{
			throw new InvalidOperationException($"Unexpected curve format: {dataFormat}");
		}

		// X and Y parameters are equal length, after a one-byte header.
		var x = publicKeyBytes.Slice(1, (publicKeyBytes.Count - 1) / 2);
		var y = publicKeyBytes.Slice(1 + x.Count, x.Count);

		var parameters = new ECParameters
		{
			Curve = curve,
			Q = new ECPoint { X = x.ToArray(), Y = y.ToArray() },
			D = privateKeyBytes.Count > 0 ? privateKeyBytes.ToArray() : null,
		};

		var keyPair = new ECDsa.KeyPair();
		keyPair.ImportParameters(parameters);
		return keyPair;
	}

	private KeyData ExportPublic(IKeyPair keyPair)
	{
		if (!Exporters.TryGetValue(keyPair.KeyAlgorithmName, out var export))
		{
			throw new NotSupportedException(
				$"No PKCS#8 exporter available for key algorithm: {keyPair.KeyAlgorithmName}");
		}

		var oidWriter = new DerWriter();
		var keyData = export(keyPair, ref oidWriter, includePrivate: false);

		var writer = new DerWriter();
		writer.WriteSequence(oidWriter);
		writer.WriteBitString(keyData);

		return new KeyData
		{
			KeyType = PublicKeyType,
			Data = writer.ToArray(),
		};
	}

	private KeyData ExportPrivate(IKeyPair keyPair)
	{
		if (!Exporters.TryGetValue(keyPair.KeyAlgorithmName, out var export))
		{
			throw new NotSupportedException(
				$"No PKCS#8 exporter available for key algorithm: {keyPair.KeyAlgorithmName}");
		}

		var oidWriter = new DerWriter();
		var keyData = export(keyPair, ref oidWriter, includePrivate: true);

		var writer = new DerWriter();
		writer.WriteInteger(BigInt.FromInt32(0)); // version
		writer.WriteSequence(oidWriter);
		writer.WriteOctetString(keyData);

		return new KeyData
		{
			KeyType = PrivateKeyType,
			Data = writer.ToArray(),
		};
	}

	private static Buffer ExportRsaKey(
		IKeyPair keyPair,
		ref DerWriter oidWriter,
		bool includePrivate)
	{
		var parameters = ((Rsa.KeyPair)keyPair).ExportParameters(includePrivate);

		oidWriter.WriteObjectIdentifier(Oids.Rsa);
		oidWriter.WriteNull();

		var keyWriter = new DerWriter();
		if (includePrivate)
		{
			keyWriter.WriteInteger(BigInt.FromInt32(0)); // version
		}

		keyWriter.WriteInteger(BigInt.FromByteArray(parameters.Modulus!, unsigned: true));
		keyWriter.WriteInteger(BigInt.FromByteArray(parameters.Exponent!, unsigned: true));

		if (includePrivate)
		{
			keyWriter.WriteInteger(BigInt.FromByteArray(parameters.D!, unsigned: true));
			keyWriter.WriteInteger(BigInt.FromByteArray(parameters.P!, unsigned: true));
			keyWriter.WriteInteger(BigInt.FromByteArray(parameters.Q!, unsigned: true));
			keyWriter.WriteInteger(BigInt.FromByteArray(parameters.DP!, unsigned: true));
			keyWriter.WriteInteger(BigInt.FromByteArray(parameters.DQ!, unsigned: true));
			keyWriter.WriteInteger(BigInt.FromByteArray(parameters.InverseQ!, unsigned: true));
		}

		return keyWriter.ToBuffer();
	}

	private static Buffer ExportECKey(
		IKeyPair keyPair,
		ref DerWriter oidWriter,
		bool includePrivate)
	{
		var parameters = ((ECDsa.KeyPair)keyPair).ExportParameters(includePrivate);

		oidWriter.WriteObjectIdentifier(Oids.EC);
		oidWriter.WriteObjectIdentifier(parameters.Curve.Oid);

		var publicKeyData = new Buffer(1 + parameters.Q.X!.Length + parameters.Q.Y!.Length);
		publicKeyData[0] = (byte)4; // Indicates uncompressed curve format
		Buffer.From(parameters.Q.X).CopyTo(publicKeyData, 1);
		Buffer.From(parameters.Q.Y).CopyTo(publicKeyData, 1 + parameters.Q.X.Length);

		if (includePrivate)
		{
			var keyWriter = new DerWriter();
			keyWriter.WriteInteger(BigInt.FromInt32(1)); // version
			keyWriter.WriteOctetString(parameters.D!);

			var publicKeyWriter = new DerWriter();
			publicKeyWriter.WriteBitString(publicKeyData);
			keyWriter.WriteTagged(1, publicKeyWriter);
			return keyWriter.ToBuffer();
		}
		else
		{
			return publicKeyData;
		}
	}

	private static KeyData DecryptPrivate(KeyData keyData, string passphrase)
	{
#if !SSH_ENABLE_PBKDF2
		// PKCS8 decryption requires PBKDF2 with SHA2. The `Rfc2898DeriveBytes` class does
		// not support overriding the default hash algorithm (SHA1) until .NET Standard 2.1.
		throw new NotSupportedException("PKCS#8 decryption requires a newer version of .NET.");
#else
		var reader = new DerReader(keyData.Data);
		var innerReader = reader.ReadSequence();
		var privateKeyData = reader.ReadOctetString();
		reader = innerReader;

		reader.ReadObjectIdentifier(Oids.Pkcs5PBES2);

		reader = reader.ReadSequence();
		var kdfReader = reader.ReadSequence();
		var algReader = reader.ReadSequence();

		kdfReader.ReadObjectIdentifier(Oids.Pkcs5PBKDF2);

		kdfReader = kdfReader.ReadSequence();
		var salt = kdfReader.ReadOctetString();
		var iterations = kdfReader.ReadInteger().ToInt32();
		kdfReader = kdfReader.ReadSequence();
		kdfReader.ReadObjectIdentifier(Oids.HmacWithSHA256);
		kdfReader.ReadNull();

		var algorithmOid = algReader.ReadObjectIdentifier();
		var iv = algReader.ReadOctetString();

		using var kdf = new Rfc2898DeriveBytes(
			Encoding.UTF8.GetBytes(passphrase),
			salt.ToArray(),
			iterations,
			HashAlgorithmName.SHA256);

		var encryption = GetKeyEncryptionAlgorithm(algorithmOid);
		var key = kdf.GetBytes(encryption.KeyLength);

		using var decipher = encryption.CreateCipher(isEncryption: false, key, iv);
		decipher.Transform(privateKeyData, privateKeyData);

		// The first part of the key should be a DER sequence header.
		if (privateKeyData[0] != (byte)(DerType.Constructed | DerType.Sequence))
		{
			throw new UnauthorizedAccessException("Key decryption failed - incorrect passphrase.");
		}

		return new KeyData
		{
			KeyType = PrivateKeyType,
			Data = privateKeyData.ToArray(),
		};
#endif
	}

	private KeyData EncryptPrivate(KeyData keyData, string passphrase, IRandom random)
	{
#if !SSH_ENABLE_PBKDF2
		// PKCS8 encryption requires PBKDF2 with SHA2. The `Rfc2898DeriveBytes` class does
		// not support overriding the default hash algorithm (SHA1) until .NET Standard 2.1.
		throw new NotSupportedException("PKCS#8 encryption requires a newer version of .NET.");
#else
		var privateKeyData = Buffer.From(keyData.Data).Copy();
		var encryption = GetKeyEncryptionAlgorithm(Oids.Aes256Cbc);

		var salt = new Buffer(8);
		random.GetBytes(salt);

		int iterations = Pbkdf2Iterations;
		using var kdf = new Rfc2898DeriveBytes(
			Encoding.UTF8.GetBytes(passphrase),
			salt.ToArray(),
			iterations,
			HashAlgorithmName.SHA256);

		var key = kdf.GetBytes(encryption.KeyLength);
		var iv = new Buffer(encryption.BlockLength);
		random.GetBytes(iv);

		// Append PKCS#7 padding up to next block boundary.
		var paddingLength = encryption.BlockLength -
			(privateKeyData.Count % encryption.BlockLength);
		var paddedData = new Buffer(privateKeyData.Count + paddingLength);
		privateKeyData.CopyTo(paddedData);
		Array.Fill(paddedData.Array, (byte)paddingLength, privateKeyData.Count, paddingLength);
		privateKeyData = paddedData;

		using var cipher = encryption.CreateCipher(isEncryption: true, key, iv);
		cipher.Transform(privateKeyData, privateKeyData);

		var pbeWriter = new DerWriter();
		pbeWriter.WriteObjectIdentifier(Oids.Pkcs5PBES2);

		var kdfAndAlgWriter = new DerWriter();

		var kdfWriter = new DerWriter();
		kdfWriter.WriteObjectIdentifier(Oids.Pkcs5PBKDF2);
		var kdfParamsWriter = new DerWriter();
		kdfParamsWriter.WriteOctetString(salt);
		kdfParamsWriter.WriteInteger(BigInt.FromInt32(iterations));
		var hmacWriter = new DerWriter();
		hmacWriter.WriteObjectIdentifier(Oids.HmacWithSHA256);
		hmacWriter.WriteNull();
		kdfParamsWriter.WriteSequence(hmacWriter);
		kdfWriter.WriteSequence(kdfParamsWriter);
		kdfAndAlgWriter.WriteSequence(kdfWriter);

		var algWriter = new DerWriter();
		algWriter.WriteObjectIdentifier(Oids.Aes256Cbc);
		algWriter.WriteOctetString(iv);

		kdfAndAlgWriter.WriteSequence(algWriter);
		pbeWriter.WriteSequence(kdfAndAlgWriter);

		var writer = new DerWriter();
		writer.WriteSequence(pbeWriter);
		writer.WriteOctetString(privateKeyData);

		return new KeyData
		{
			KeyType = EncryptedPrivateKeyType,
			Data = writer.ToArray(),
		};
#endif
	}

	private static EncryptionAlgorithm GetKeyEncryptionAlgorithm(Oid algorithmOid)
	{
		// Note algorithms other than AES256 are used only for decrypting (importing) keys.
		if (algorithmOid.Value == Oids.Aes256Cbc.Value)
		{
			return new EncryptionAlgorithm("aes256-cbc", "AES", CipherModeEx.CBC, 256);
		}
		else if (algorithmOid.Value == Oids.Aes192Cbc.Value)
		{
			return new EncryptionAlgorithm("aes192-cbc", "AES", CipherModeEx.CBC, 192);
		}
		else if (algorithmOid.Value == Oids.Aes128Cbc.Value)
		{
			return new EncryptionAlgorithm("aes128-cbc", "AES", CipherModeEx.CBC, 128);
		}
		else if (algorithmOid.Value == Oids.DesEde3Cbc.Value)
		{
			return new EncryptionAlgorithm("3des-cbc", "3DES", CipherModeEx.CBC, 192);
		}
		else
		{
			throw new NotSupportedException($"Key cipher not supported: {algorithmOid.Value}");
		}
	}
}
