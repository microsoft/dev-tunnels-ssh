// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.IO;
using ECCurve = System.Security.Cryptography.ECCurve;
using ECParameters = System.Security.Cryptography.ECParameters;
using ECPoint = System.Security.Cryptography.ECPoint;

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Provides import/export of the <see cref="KeyFormat.Sec1" /> key format.
/// </summary>
public class Sec1KeyFormatter : IKeyFormatter
{
	private const string PrivateKeyType = "EC PRIVATE KEY";

	/// <inheritdoc/>
	public IKeyPair? Import(KeyData keyData)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		ECParameters? parameters = null;
		if (keyData.KeyType == PrivateKeyType || string.IsNullOrEmpty(keyData.KeyType))
		{
			parameters = ImportECPrivate(keyData.Data);
		}

		if (parameters != null)
		{
			ECDsa.KeyPair? keyPair = new ECDsa.KeyPair();
			keyPair.ImportParameters(parameters.Value);
			return keyPair;
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

		if (keyPair is ECDsa.KeyPair ecKeyPair)
		{
			return ExportECPrivate(ecKeyPair);
		}
		else
		{
			throw new NotSupportedException(
				$"SEC1 format does not support key algorithm: {keyPair.KeyAlgorithmName}");
		}
	}

	/// <inheritdoc/>
	public KeyData? Decrypt(KeyData keyData, string? passphrase)
	{
		if (keyData == null) throw new ArgumentNullException(nameof(keyData));

		if (keyData.KeyType == PrivateKeyType || string.IsNullOrEmpty(keyData.KeyType))
		{
			if (keyData.Headers.TryGetValue("Proc-Type", out var procType) &&
				procType == "4,ENCRYPTED")
			{
				if (string.IsNullOrEmpty(passphrase))
				{
					throw new UnauthorizedAccessException(
						"A passphrase is required to decrypt the key.");
				}

				return Pkcs1KeyFormatter.DecryptPrivate(keyData, passphrase!);
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

		if (keyData.KeyType == PrivateKeyType)
		{
			throw new NotSupportedException(
				"SEC1 export with passphrase is not supported because the format uses " +
				"a weak key derivation algorithm. Use a different format to export a " +
				"passphrase-protected private key.");
		}
		else
		{
			throw new InvalidOperationException($"Unexpected key type: {keyData.KeyType}");
		}
	}

	private static ECParameters ImportECPrivate(Buffer data)
	{
		var reader = new DerReader(data);

		var version = reader.ReadInteger().ToInt32();
		if (version != 1)
		{
			throw new NotSupportedException($"Unsupported SEC1 format version: {version}");
		}

		var d = reader.ReadOctetString().ToArray(); // Private key

		if (!reader.TryReadTagged(0, out var curveReader))
		{
			throw new InvalidOperationException("SEC1 curve info not found.");
		}

		var curveOid = curveReader.ReadObjectIdentifier();
		var curve = ECCurve.CreateFromOid(curveOid);

		if (!reader.TryReadTagged(1, out var publicKeyReader))
		{
			throw new InvalidOperationException("SEC1 public key data not found.");
		}

		var publicKeyData = publicKeyReader.ReadBitString();
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

		var keyLength = (publicKeyData.Count - 1) / 2;
		var x = publicKeyData.Slice(1, keyLength).ToArray();
		var y = publicKeyData.Slice(1 + keyLength, keyLength).ToArray();

		return new ECParameters
		{
			Curve = curve,
			Q = new ECPoint
			{
				X = x,
				Y = y,
			},
			D = d,
		};
	}

	private static KeyData ExportECPrivate(ECDsa.KeyPair keyPair)
	{
		var parameters = keyPair.ExportParameters(true);

		var writer = new DerWriter();

		writer.WriteInteger(BigInt.FromInt32(1)); // version

		writer.WriteOctetString(parameters.D!);

		var curveWriter = new DerWriter();
		curveWriter.WriteObjectIdentifier(parameters.Curve.Oid);
		writer.WriteTagged(0, curveWriter);

		var publicKeyWriter = new DerWriter();
		var publicKeyData = new Buffer(1 + parameters.Q.X!.Length + parameters.Q.Y!.Length);
		publicKeyData[0] = (byte)4; // Indicates uncompressed curve format
		Buffer.From(parameters.Q.X).CopyTo(publicKeyData, 1);
		Buffer.From(parameters.Q.Y).CopyTo(publicKeyData, 1 + parameters.Q.X.Length);
		publicKeyWriter.WriteBitString(publicKeyData);
		writer.WriteTagged(1, publicKeyWriter);

		var data = writer.ToArray();

		return new KeyData
		{
			KeyType = PrivateKeyType,
			Data = data,
		};
	}
}
