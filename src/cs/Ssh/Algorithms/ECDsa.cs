// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public class ECDsa : PublicKeyAlgorithm
{
	public const string ECDsaSha2Nistp256 = "ecdsa-sha2-nistp256";
	public const string ECDsaSha2Nistp384 = "ecdsa-sha2-nistp384";
	public const string ECDsaSha2Nistp521 = "ecdsa-sha2-nistp521";

	public ECDsa(string name, string hashAlgorithmName)
		: base(
			  name,
			  name, // The key algorithm name is the same (unlike RSA).
			  hashAlgorithmName)
	{
	}

	public override IKeyPair CreateKeyPair()
	{
		return new KeyPair(KeyAlgorithmName);
	}

	public override IKeyPair GenerateKeyPair(int? keySizeInBits = null)
	{
		if (keySizeInBits != null && !this.KeyAlgorithmName.EndsWith(
			"nistp" + keySizeInBits, StringComparison.Ordinal))
		{
			throw new ArgumentException(
				$"Key size {keySizeInBits} does not match algorithm {this.KeyAlgorithmName}");
		}

		return KeyPair.Generate(KeyAlgorithmName);
	}

	public override ISigner CreateSigner(IKeyPair keyPair)
	{
		var ecdsaKeyPair = keyPair as KeyPair;
		if (ecdsaKeyPair == null) throw new ArgumentException("ECDSA key pair object expected.");

		return new SignerVerifier(ecdsaKeyPair, ConvertHashAlgorithmName(HashAlgorithmName));
	}

	public override IVerifier CreateVerifier(IKeyPair keyPair)
	{
		var ecdsaKeyPair = keyPair as KeyPair;
		if (ecdsaKeyPair == null) throw new ArgumentException("ECDSA key pair object expected.");

		return new SignerVerifier(ecdsaKeyPair, ConvertHashAlgorithmName(HashAlgorithmName));
	}

	private static HashAlgorithmName ConvertHashAlgorithmName(string hashAlgorithmName)
	{
		return hashAlgorithmName switch
		{
			HmacAlgorithm.Sha256 => System.Security.Cryptography.HashAlgorithmName.SHA256,
			HmacAlgorithm.Sha384 => System.Security.Cryptography.HashAlgorithmName.SHA384,
			HmacAlgorithm.Sha512 => System.Security.Cryptography.HashAlgorithmName.SHA512,
			_ => throw new ArgumentException(
				"Invalid or unsupported ECDSA hash algorithm: " + hashAlgorithmName,
				nameof(hashAlgorithmName)),
		};
	}

	private static int GetSignatureLength(int keySizeInBits)
	{
		// The signature is double the key size, but formatted as 2 bigints.
		// To each bigint add 4 for the length and 1 for a leading zero.
		var keySizeInBytes = (keySizeInBits + 7) / 8;
		return (4 + 1 + keySizeInBytes) * 2;
	}

#pragma warning disable CA1034 // Nested types should not be visible
	public class KeyPair : IKeyPair
#pragma warning restore CA1034 // Nested types should not be visible
	{
		private string? keyAlgorithmName;
		private ECCurve curve;

		public static KeyPair Generate(string algorithmName)
		{
			var keyPair = new KeyPair(algorithmName);
			keyPair.Algorithm = System.Security.Cryptography.ECDsa.Create(keyPair.curve);
			keyPair.HasPrivateKey = true;
			return keyPair;
		}

		/// <summary>
		/// Creates a new EMPTY key pair object.
		/// </summary>
		/// <remarks>
		/// They key pair object must be initialized via <see cref="ImportParameters" />
		/// before use.
		/// </remarks>
		public KeyPair()
		{
		}

		/// <summary>
		/// Creates a new public-private key pair.
		/// </summary>
		public KeyPair(string keyAlgorithmName)
		{
			KeyAlgorithmName = keyAlgorithmName;
		}

		public string KeyAlgorithmName
		{
			get
			{
				return this.keyAlgorithmName ??
					throw new InvalidOperationException("Key is not present.");
			}
			private set
			{
				this.curve = value switch
				{
					ECDsaSha2Nistp256 => ECCurve.NamedCurves.nistP256,
					ECDsaSha2Nistp384 => ECCurve.NamedCurves.nistP384,
					ECDsaSha2Nistp521 => ECCurve.NamedCurves.nistP521,
					_ => throw new ArgumentException(
						$"Invalid or unsupported ECDSA key algorithm: {value}"),
				};

				if (string.IsNullOrEmpty(this.curve.Oid?.FriendlyName))
				{
					throw new InvalidOperationException("Missing curve name.");
				}

				this.keyAlgorithmName = value;
			}
		}

		public bool HasPrivateKey { get; private set; }

		public string? Comment { get; set; }

		internal System.Security.Cryptography.ECDsa? Algorithm { get; private set; }

		public void SetPublicKeyBytes(Buffer keyBytes)
		{
			var reader = new SshDataReader(keyBytes);

			string algorithmName = reader.ReadString(Encoding.ASCII);
			if (algorithmName != ECDsa.ECDsaSha2Nistp256 &&
				algorithmName != ECDsa.ECDsaSha2Nistp384 &&
				algorithmName != ECDsa.ECDsaSha2Nistp521)
			{
				throw new ArgumentException($"Invalid ECDSA key algorithm: {algorithmName}");
			}

			KeyAlgorithmName = algorithmName;

			string curveName = reader.ReadString(Encoding.ASCII);
			if (!curveName.Equals(this.curve.Oid.FriendlyName, StringComparison.OrdinalIgnoreCase))
			{
				throw new ArgumentException(
					$"Curve name {curveName} does not match key algorithm" +
					$"{algorithmName} ({this.curve.Oid.FriendlyName}).");
			}

			// X and Y parameters are equal length, after a one-byte header.
			Buffer key = reader.ReadBinary();
			var x = key.Slice(1, (key.Count - 1) / 2);
			var y = key.Slice(1 + x.Count, x.Count);
			this.Algorithm = System.Security.Cryptography.ECDsa.Create(new ECParameters
			{
				Curve = this.curve,
				Q = { X = x.ToArray(), Y = y.ToArray() },
			});
			this.HasPrivateKey = false;
		}

		public Buffer GetPublicKeyBytes(string? algorithmName = null)
		{
			if (Algorithm == null)
			{
				throw new InvalidOperationException("Key is not present.");
			}

			var p = Algorithm.ExportParameters(includePrivateParameters: false);
			var writer = new SshDataWriter(new Buffer(50 + p.Q.X!.Length + p.Q.Y!.Length));
			writer.Write(algorithmName ?? KeyAlgorithmName, Encoding.ASCII);
#pragma warning disable CA1308 // Normalize strings to uppercase
			writer.Write(this.curve.Oid.FriendlyName?.ToLowerInvariant() ?? string.Empty, Encoding.ASCII);
#pragma warning restore CA1308 // Normalize strings to uppercase
			writer.Write((uint)(1 + p.Q.X.Length + p.Q.Y.Length));
			writer.Write((byte)4); // Indicates uncompressed curve format
			writer.Write(p.Q.X);
			writer.Write(p.Q.Y);
			return writer.ToBuffer();
		}

		public void ImportParameters(ECParameters parameters)
		{
			if (string.IsNullOrEmpty(parameters.Curve.Oid?.FriendlyName))
			{
				throw new ArgumentException(
					"Parameters must include a curve name.", nameof(parameters));
			}

#pragma warning disable CA1308 // Normalize strings to uppercase
			var curveName = parameters.Curve.Oid!.FriendlyName.ToLowerInvariant();
#pragma warning restore CA1308 // Normalize strings to uppercase
			if (curveName.StartsWith("ecdsa_p", StringComparison.Ordinal) == true)
			{
				curveName = "nistp" + curveName.Substring(7);
			}

			KeyAlgorithmName = curveName switch
			{
				"nistp256" => ECDsaSha2Nistp256,
				"nistp384" => ECDsaSha2Nistp384,
				"nistp521" => ECDsaSha2Nistp521,
				_ => throw new ArgumentException($"Unknown curve: {curveName}"),
			};

			Algorithm = System.Security.Cryptography.ECDsa.Create(parameters);
			HasPrivateKey = parameters.D?.Length > 0;
		}

		public ECParameters ExportParameters(bool includePrivate)
		{
			if (Algorithm == null)
			{
				throw new InvalidOperationException("Key is not present.");
			}

			var parameters = Algorithm.ExportParameters(includePrivate);
			parameters.Curve = this.curve;
			return parameters;
		}

		public void Dispose()
		{
			this.Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing)
			{
				Algorithm?.Dispose();
			}
		}
	}

	private class SignerVerifier : ISigner, IVerifier
	{
		private readonly KeyPair keyPair;
		private readonly HashAlgorithmName hashAlgorithmName;

		public SignerVerifier(KeyPair keyPair, HashAlgorithmName hashAlgorithmName)
		{
			this.keyPair = keyPair;
			this.hashAlgorithmName = hashAlgorithmName;
		}

		public int DigestLength
		{
			get
			{
				var algorithm = this.keyPair.Algorithm;
				if (algorithm == null)
				{
					return 0;
				}
				else
				{
					return GetSignatureLength(algorithm.KeySize);
				}
			}
		}

		public void Sign(Buffer data, Buffer signature)
		{
			var algorithm = this.keyPair.Algorithm;
			if (algorithm == null)
			{
				throw new InvalidOperationException("Key is not present.");
			}

			if (signature.Count != DigestLength)
			{
				throw new ArgumentException("Invalid signature buffer size.");
			}

			Buffer signatureBuffer = algorithm.SignData(
				data.Array,
				data.Offset,
				data.Count,
				this.hashAlgorithmName);
#if DEBUG
			Buffer.TrackAllocation(signatureBuffer.Count);
#endif

			if (signatureBuffer.Count != signature.Count - 10)
			{
				throw new InvalidOperationException(
					$"Unexpected signature size: {signatureBuffer.Count}");
			}

			// Reformat the signature as two big-ints as required by SSH.
			var n = signatureBuffer.Count / 2;
			var x = BigInt.FromByteArray(signatureBuffer.Slice(0, n).ToArray(), unsigned: true);
			var y = BigInt.FromByteArray(signatureBuffer.Slice(n, n).ToArray(), unsigned: true);
			var keySizeInBytes = (algorithm.KeySize + 7) / 8;
			var signatureWriter = new SshDataWriter(signature);
			signatureWriter.WriteBinary(x.ToBuffer(unsigned: true, length: keySizeInBytes + 1));
			signatureWriter.WriteBinary(y.ToBuffer(unsigned: true, length: keySizeInBytes + 1));
		}

		public bool Verify(Buffer data, Buffer signature)
		{
			var algorithm = this.keyPair.Algorithm;
			if (algorithm == null)
			{
				throw new InvalidOperationException("Key is not present.");
			}

			// Reformat the signature integer bytes as required by .NET.
			var signatureReader = new SshDataReader(signature);
			var x = signatureReader.ReadBigInt();
			var y = signatureReader.ReadBigInt();
			var length = (algorithm.KeySize + 7) / 8;
			Buffer xa = x.ToByteArray(unsigned: true, length);
			Buffer ya = y.ToByteArray(unsigned: true, length);
			signature = new Buffer(2 * length);
			xa.CopyTo(signature, 0);
			ya.CopyTo(signature, length);

			return algorithm.VerifyData(
				data.Array,
				data.Offset,
				data.Count,
				signature.ToArray(),
				this.hashAlgorithmName);
		}

		public void Dispose()
		{
			// Do not dispose the key pair - this class does not own it.
		}
	}
}
