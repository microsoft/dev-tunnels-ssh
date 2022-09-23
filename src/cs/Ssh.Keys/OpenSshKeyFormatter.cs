// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.IO;
using ECDsa = Microsoft.DevTunnels.Ssh.Algorithms.ECDsa;

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Provides import/export of the <see cref="KeyFormat.OpenSsh" /> key format.
/// </summary>
public class OpenSshKeyFormatter : IKeyFormatter
{
	private const string PrivateKeyType = "OPENSSH PRIVATE KEY";
	private const int DefaultKdfRounds = 16;

	public OpenSshKeyFormatter()
	{
		Importers[Rsa.KeyAlgorithmName] = ImportRsaKey;
		Exporters[Rsa.KeyAlgorithmName] = ExportRsaKey;
		Importers[ECDsa.ECDsaSha2Nistp256] = ImportECKey;
		Importers[ECDsa.ECDsaSha2Nistp384] = ImportECKey;
		Importers[ECDsa.ECDsaSha2Nistp521] = ImportECKey;
		Exporters[ECDsa.ECDsaSha2Nistp256] = ExportECKey;
		Exporters[ECDsa.ECDsaSha2Nistp384] = ExportECKey;
		Exporters[ECDsa.ECDsaSha2Nistp521] = ExportECKey;
	}

	public delegate IKeyPair Importer(ref SshDataReader keyReader);
	public delegate void Exporter(IKeyPair keyPair, ref SshDataWriter keyWriter);

	/// <summary>
	/// Gets a mapping from public key algorithm name to import handler for that algorithm.
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
	/// Gets or sets the number of key-derivation function rounds used when exporting a
	/// password-protected key.
	/// </summary>
	/// <remarks>
	/// The default value is 16. The required CPU time scales linearly with the number of rounds.
	/// A higher number of rounds makes a brute-force attack on the password more expensive. The
	/// number of rounds used is stored (unencrypted) in the key file, so that the correct value
	/// is known when deriving a decryption key.
	/// </remarks>
	public int KdfRounds { get; set; } = DefaultKdfRounds;

	/// <inheritdoc/>
	public IKeyPair? Import(KeyData keyData)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		if (keyData.KeyType == PrivateKeyType || string.IsNullOrEmpty(keyData.KeyType))
		{
			return ImportPrivate(keyData);
		}

		return null;
	}

	/// <inheritdoc/>
	public KeyData Export(IKeyPair keyPair, bool includePrivate)
	{
		if (keyPair == null) throw new ArgumentNullException(nameof(keyPair));

		if (!includePrivate)
		{
			throw new NotSupportedException("Public-only export is not supported by this format.");
		}

		return ExportPrivate(keyPair, Random);
	}

	/// <inheritdoc/>
	public KeyData? Decrypt(KeyData keyData, string? passphrase)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		if (keyData.KeyType == PrivateKeyType || string.IsNullOrEmpty(keyData.KeyType))
		{
			return DecryptPrivate(keyData, passphrase);
		}

		return null;
	}

	/// <inheritdoc/>
	public KeyData Encrypt(KeyData keyData, string passphrase)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		if (keyData.KeyType == PrivateKeyType)
		{
			return EncryptPrivate(keyData, passphrase, KdfRounds, Random);
		}

		return keyData;
	}

	private IKeyPair ImportPrivate(KeyData keyData)
	{
		// Reference OpenSSH sshkey.c sshkey_private_to_blob2()
		const string openSSHKeyVersion = "openssh-key-v1\0";
		var openSSHKeyVersionBytes = Encoding.ASCII.GetBytes(openSSHKeyVersion);
		if (!openSSHKeyVersionBytes.SequenceEqual(
			keyData.Data.Take(openSSHKeyVersion.Length)))
		{
			throw new NotSupportedException("Unsupported OpenSSH key format.");
		}

		var data = Buffer.From(keyData.Data).Slice(
			openSSHKeyVersion.Length, keyData.Data.Length - openSSHKeyVersion.Length);
		var reader = new SshDataReader(data);

		var cipherName = reader.ReadString(Encoding.ASCII);
		if (cipherName != "none")
		{
			throw new ArgumentException("Key must be decrypted first.");
		}

		reader.ReadString(Encoding.ASCII); // KDF name
		reader.ReadBinary(); // KDF parameters

		var keyCount = reader.ReadUInt32();
		if (keyCount != 1)
		{
			throw new ArgumentException("Invalid key count: " + keyCount);
		}

		reader.ReadBinary(); // Public key data (duplicated below in private key data)

		var privateKeyData = reader.ReadBinary();
		var keyReader = new SshDataReader(privateKeyData);
		keyReader.ReadUInt32(); // check 1
		keyReader.ReadUInt32(); // check 2

		var keyAlgorithmName = keyReader.ReadString(Encoding.ASCII);
		if (!Importers.TryGetValue(keyAlgorithmName, out var import))
		{
			throw new NotSupportedException(
				$"No OpenSSH importer available for key algorithm: {keyAlgorithmName}");
		}

		var keyPair = import(ref keyReader);

		var comment = keyReader.ReadString(Encoding.UTF8);
		keyPair.Comment = comment;

		return keyPair;
	}

	private static IKeyPair ImportRsaKey(ref SshDataReader keyReader)
	{
		var modulus = keyReader.ReadBigInt();
		var exponent = keyReader.ReadBigInt();
		var d = keyReader.ReadBigInt();
		var iq = keyReader.ReadBigInt();
		var p = keyReader.ReadBigInt();
		var q = keyReader.ReadBigInt();

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

	private static IKeyPair ImportECKey(ref SshDataReader keyReader)
	{
		var curveName = keyReader.ReadString(Encoding.ASCII);
		var curve = curveName switch
		{
			"nistp256" => ECCurve.NamedCurves.nistP256,
			"nistp384" => ECCurve.NamedCurves.nistP384,
			"nistp521" => ECCurve.NamedCurves.nistP521,
			_ => throw new NotSupportedException($"EC curve not supported: {curveName}"),
		};

		var publicKeyData = keyReader.ReadBinary();
		if (publicKeyData.Count % 2 != 1)
		{
			throw new InvalidOperationException(
				$"Unexpected key data length: {publicKeyData.Count}");
		}

		var dataFormat = publicKeyData[0];

		// 4 = uncompressed curve format
		if (dataFormat != 4)
		{
			throw new InvalidOperationException($"Unexpected curve format: {dataFormat}");
		}

		// X and Y parameters are equal length, after a one-byte header.
		var x = publicKeyData.Slice(1, (publicKeyData.Count - 1) / 2);
		var y = publicKeyData.Slice(1 + x.Count, x.Count);

		var privateKey = keyReader.ReadBigInt();

		var parameters = new ECParameters
		{
			Curve = curve,
			Q = { X = x.ToArray(), Y = y.ToArray() },
			D = privateKey.ToByteArray(unsigned: true, length: x.Count),
		};
		var keyPair = new ECDsa.KeyPair();
		keyPair.ImportParameters(parameters);
		return keyPair;
	}

	private KeyData ExportPrivate(IKeyPair keyPair, IRandom random)
	{
		// Reference OpenSSH sshkey.c sshkey_private_to_blob2()
		var writer = new SshDataWriter();

		const string openSSHKeyVersion = "openssh-key-v1\0";
		writer.Write(Encoding.ASCII.GetBytes(openSSHKeyVersion));

		string cipherName = "none";
		string kdfName = "none";
		Buffer kdf = Buffer.Empty;
		uint keyCount = 1;

		writer.Write(cipherName, Encoding.ASCII);
		writer.Write(kdfName, Encoding.ASCII);
		writer.WriteBinary(kdf);
		writer.Write(keyCount);

		var publicKey = keyPair.GetPublicKeyBytes();
		writer.WriteBinary(publicKey);

		var keyWriter = new SshDataWriter();

		// Write 8 random check bytes (4 random bytes repeated twice).
		var checkBytes = new Buffer(4);
		random.GetBytes(checkBytes);
		keyWriter.Write(checkBytes);
		keyWriter.Write(checkBytes);
		keyWriter.Write(keyPair.KeyAlgorithmName, Encoding.ASCII);

		if (!Exporters.TryGetValue(keyPair.KeyAlgorithmName, out var export))
		{
			throw new NotSupportedException(
				$"No OpenSSH exporter available for key algorithm: {keyPair.KeyAlgorithmName}");
		}

		export(keyPair, ref keyWriter);

		keyWriter.Write(keyPair.Comment ?? string.Empty, Encoding.UTF8);

		// Pad private key bytes to a block size of 8.
		for (int i = 1; keyWriter.Position % 8 != 0; i++)
		{
			keyWriter.Write((byte)i);
		}

		writer.WriteBinary(keyWriter.ToBuffer());
		var data = writer.ToBuffer().ToArray();

		return new KeyData(lineLength: 70)
		{
			KeyType = PrivateKeyType,
			Data = data,
		};
	}

	private static void ExportRsaKey(IKeyPair keyPair, ref SshDataWriter keyWriter)
	{
		var parameters = ((Rsa.KeyPair)keyPair).ExportParameters(true);
		keyWriter.Write(BigInt.FromByteArray(parameters.Modulus!, unsigned: true));
		keyWriter.Write(BigInt.FromByteArray(parameters.Exponent!, unsigned: true));
		keyWriter.Write(BigInt.FromByteArray(parameters.D!, unsigned: true));
		keyWriter.Write(BigInt.FromByteArray(parameters.InverseQ!, unsigned: true));
		keyWriter.Write(BigInt.FromByteArray(parameters.P!, unsigned: true));
		keyWriter.Write(BigInt.FromByteArray(parameters.Q!, unsigned: true));
	}

	private static void ExportECKey(IKeyPair keyPair, ref SshDataWriter keyWriter)
	{
		var parameters = ((ECDsa.KeyPair)keyPair).ExportParameters(true);

		var curveName = keyPair.KeyAlgorithmName switch
		{
			ECDsa.ECDsaSha2Nistp256 => "nistp256",
			ECDsa.ECDsaSha2Nistp384 => "nistp384",
			ECDsa.ECDsaSha2Nistp521 => "nistp521",
			_ => throw new ArgumentException(
				$"Unknown key algorithm name: {keyPair.KeyAlgorithmName}"),
		};

		keyWriter.Write(curveName, Encoding.ASCII);
		keyWriter.Write((uint)(1 + parameters.Q.X!.Length + parameters.Q.Y!.Length));
		keyWriter.Write((byte)4); // Indicates uncompressed curve format
		keyWriter.Write(parameters.Q.X);
		keyWriter.Write(parameters.Q.Y);
		keyWriter.Write(BigInt.FromByteArray(parameters.D!, unsigned: true));
	}

	private static KeyData DecryptPrivate(KeyData keyData, string? passphrase)
	{
		const string openSSHKeyVersion = "openssh-key-v1\0";
		var openSSHKeyVersionBytes = Encoding.ASCII.GetBytes(openSSHKeyVersion);
		if (!openSSHKeyVersionBytes.SequenceEqual(
			keyData.Data.Take(openSSHKeyVersion.Length)))
		{
			throw new NotSupportedException("Unsupported OpenSSH key format.");
		}

		var data = Buffer.From(keyData.Data).Slice(
			openSSHKeyVersion.Length, keyData.Data.Length - openSSHKeyVersion.Length);

		var reader = new SshDataReader(data);
		var cipherName = reader.ReadString(Encoding.ASCII);
		if (cipherName == "none")
		{
			return keyData;
		}

		if (passphrase == null)
		{
			throw new UnauthorizedAccessException(
				"A passphrase is required to decrypt the key.");
		}

		var kdfName = reader.ReadString(Encoding.ASCII);
		if (kdfName != "bcrypt")
		{
			throw new NotSupportedException(
				"Unsupported key derivation function: " + kdfName);
		}

		var kdfParams = reader.ReadBinary();
		var keyCount = reader.ReadUInt32();
		var publicKey = reader.ReadBinary();

		if (keyCount != 1)
		{
			throw new ArgumentException("Invalid key count: " + keyCount);
		}

		var privateKeyData = reader.ReadBinary();

		var encryption = KeyPair.GetKeyEncryptionAlgorithm(cipherName);

		var kdfReader = new SshDataReader(kdfParams);
		var salt = kdfReader.ReadBinary();
		var rounds = kdfReader.ReadUInt32();
		var keyAndIv = new Buffer(encryption.KeyLength + encryption.BlockLength);
		new BCrypt().Pbkdf(
			Encoding.UTF8.GetBytes(passphrase), salt.ToArray(), (int)rounds, keyAndIv.Array);

		var key = keyAndIv.Slice(0, encryption.KeyLength);
		var iv = keyAndIv.Slice(encryption.KeyLength, encryption.BlockLength);
		using var decipher = encryption.CreateCipher(isEncryption: false, key, iv);
		decipher.Transform(privateKeyData, privateKeyData);

		// The encrypted key starts with a random 4-byte repeated value, meant for
		// checking whether encryption succeeded.
		var keyReader = new SshDataReader(privateKeyData);
		var check1 = keyReader.ReadUInt32();
		var check2 = keyReader.ReadUInt32();
		if (check2 != check1)
		{
			throw new UnauthorizedAccessException("Key decryption failed - incorrect passphrase.");
		}

		// Reformat as unencrypted OpenSSH key data.
		cipherName = "none";
		kdfName = "none";
		kdfParams = Buffer.Empty;

		var writer = new SshDataWriter();
		writer.Write(Encoding.ASCII.GetBytes(openSSHKeyVersion));
		writer.Write(cipherName, Encoding.ASCII);
		writer.Write(kdfName, Encoding.ASCII);
		writer.WriteBinary(kdfParams);
		writer.Write(keyCount);
		writer.WriteBinary(publicKey);
		writer.WriteBinary(privateKeyData);

		return new KeyData(lineLength: 70)
		{
			KeyType = PrivateKeyType,
			Data = writer.ToBuffer().ToArray(),
		};
	}

	private static KeyData EncryptPrivate(
		KeyData keyData,
		string passphrase,
		int kdfRounds,
		IRandom random)
	{
		const string openSSHKeyVersion = "openssh-key-v1\0";
		var openSSHKeyVersionBytes = Encoding.ASCII.GetBytes(openSSHKeyVersion);
		if (!openSSHKeyVersionBytes.SequenceEqual(
			keyData.Data.Take(openSSHKeyVersion.Length)))
		{
			throw new NotSupportedException("Unsupported OpenSSH key format.");
		}

		var data = Buffer.From(keyData.Data).Slice(
			openSSHKeyVersion.Length, keyData.Data.Length - openSSHKeyVersion.Length);
		var reader = new SshDataReader(data);

		var cipherName = reader.ReadString(Encoding.ASCII);
		reader.ReadString(Encoding.ASCII); // KDF name
		reader.ReadBinary(); // KDF parameters
		var keyCount = reader.ReadUInt32();
		var publicKey = reader.ReadBinary();
		var privateKeyData = reader.ReadBinary();

		if (cipherName != "none")
		{
			throw new InvalidOperationException("Key data is already encrypted.");
		}

		cipherName = "aes256-ctr";
		var encryption = new EncryptionAlgorithm(cipherName, "AES", CipherModeEx.CTR, 256);

		var salt = new Buffer(encryption.BlockLength);
		random.GetBytes(salt.Array);

		var kdfName = "bcrypt";
		var kdfWriter = new SshDataWriter();
		kdfWriter.WriteBinary(salt);
		kdfWriter.Write((uint)kdfRounds);
		var kdfParams = kdfWriter.ToBuffer();

		var keyAndIv = new Buffer(encryption.KeyLength + encryption.BlockLength);
		new BCrypt().Pbkdf(
			Encoding.UTF8.GetBytes(passphrase), salt.ToArray(), (int)kdfRounds, keyAndIv.Array);

		var key = keyAndIv.Slice(0, encryption.KeyLength);
		var iv = keyAndIv.Slice(encryption.KeyLength, encryption.BlockLength);
		var cipher = encryption.CreateCipher(isEncryption: true, key, iv);

		if (privateKeyData.Count % cipher.BlockLength != 0)
		{
			// Pad up to the cipher block length.
			var paddedData = new Buffer(privateKeyData.Count + cipher.BlockLength -
				(privateKeyData.Count % cipher.BlockLength));
			privateKeyData.CopyTo(paddedData);

			// Continue padding if was started by the unencrypted key data. This won't work reliably
			// if the unpadded data can end with bytes 1-8. But since the data ends with a comment
			// and neither ASCII nor UTF8 should include one of those bytes, that shouldn't be a
			// problem. (When there is no comment, then the data ends with a 32-bit zero.)
			int i = privateKeyData.Count;
			byte padValue = privateKeyData[i - 1];
			if (padValue == 0 || padValue > 8)
			{
				padValue = 0;
			}

			for (; i < paddedData.Count; i++)
			{
				paddedData[i] = ++padValue;
			}

			privateKeyData = paddedData;
		}

		cipher.Transform(privateKeyData, privateKeyData);

		// Reformat as encrypted OpenSSH key data.
		var writer = new SshDataWriter();
		writer.Write(Encoding.ASCII.GetBytes(openSSHKeyVersion));
		writer.Write(cipherName, Encoding.ASCII);
		writer.Write(kdfName, Encoding.ASCII);
		writer.WriteBinary(kdfParams);
		writer.Write(keyCount);
		writer.WriteBinary(publicKey);
		writer.WriteBinary(privateKeyData);

		return new KeyData(lineLength: 70)
		{
			KeyType = PrivateKeyType,
			Data = writer.ToBuffer().ToArray(),
		};
	}
}
