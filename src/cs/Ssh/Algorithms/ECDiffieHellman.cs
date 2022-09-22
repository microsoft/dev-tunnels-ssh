// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.DevTunnels.Ssh.IO;

#if SSH_ENABLE_ECDH
namespace Microsoft.DevTunnels.Ssh.Algorithms;

public class ECDiffieHellman : KeyExchangeAlgorithm
{
	public const string EcdhNistp256 = "ecdh-sha2-nistp256";
	public const string EcdhNistp384 = "ecdh-sha2-nistp384";
	public const string EcdhNistp521 = "ecdh-sha2-nistp521";

	private static Type? ImplementationType { get; } = LoadImplementationType();
	private static MethodInfo? DeriveSecretMethod { get; set; }

	public ECDiffieHellman(string name, int keySizeInBits, string hashAlgorithmName)
		: base(
			  name,
			  keySizeInBits,
			  hashAlgorithmName,
			  HmacAlgorithm.GetHashDigestLength(hashAlgorithmName))
	{
	}

	public override bool IsAvailable => ImplementationType != null;

#if NET6_0_OR_GREATER
	[UnconditionalSuppressMessage(
		"Trimming",
		"IL2026:RequiresUnreferencedCode",
		Justification = "Crypto types will no be trimmed because they're referenced elsewhere.")]
#endif
	private static Type? LoadImplementationType()
	{
		var ns = typeof(AsymmetricAlgorithm).Namespace;

		Type? ecdhType;
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			if (Environment.OSVersion.Version.Major >= 10)
			{
				ecdhType = CngAssembly?.GetType($"{ns}.ECDiffieHellmanCng");
			}
			else
			{
				// BCRYPT_KDF_RAW_SECRET is not supported on Windows < 10.
				ecdhType = null;
			}
		}
		else
		{
			ecdhType = OpenSslAssembly?.GetType($"{ns}.ECDiffieHellmanOpenSsl");
			if (ecdhType != null)
			{
				DeriveSecretMethod = ecdhType.GetMethod(
					"DeriveSecretAgreement",
					BindingFlags.Instance | BindingFlags.NonPublic,
					binder: null,
					new[] { typeof(ECDiffieHellmanPublicKey), typeof(IncrementalHash) },
					modifiers: null);
				if (DeriveSecretMethod == null)
				{
					ecdhType = null;
				}
			}
		}

		return ecdhType;
	}

	public override IKeyExchange CreateKeyExchange()
	{
		if (!IsAvailable)
		{
			throw new NotSupportedException("ECDH is not available.");
		}

		return new ECDiffieHellmanKex(this.KeySizeInBits, this.HashAlgorithmName);
	}

	private class ECDiffieHellmanKex : IKeyExchange
	{
		private readonly System.Security.Cryptography.ECDiffieHellman ecdh;
		private readonly HashAlgorithm hash;

		public ECDiffieHellmanKex(int keySizeInBits, string hashAlgorithmName)
		{
			if (hashAlgorithmName == null)
			{
				throw new ArgumentNullException(nameof(hashAlgorithmName));
			}

			this.ecdh = (System.Security.Cryptography.ECDiffieHellman)Activator.CreateInstance(
				ImplementationType!, keySizeInBits)!;

			if (hashAlgorithmName == "SHA2-512")
			{
				this.hash = SHA512.Create();
			}
			else if (hashAlgorithmName == "SHA2-384")
			{
				this.hash = SHA384.Create();
			}
			else if (hashAlgorithmName == "SHA2-256")
			{
				this.hash = SHA256.Create();
			}
			else
			{
				throw new NotSupportedException(
					$"Hash algorithm not supported: {hashAlgorithmName}");
			}
		}

		public int DigestLength => this.hash.HashSize / 8;

		public Buffer StartKeyExchange()
		{
			var p = this.ecdh.ExportParameters(false);
			var writer = new SshDataWriter(new Buffer(1 + p.Q.X!.Length + p.Q.Y!.Length));
			writer.Write((byte)4); // Indicates uncompressed curve format
			writer.Write(p.Q.X);
			writer.Write(p.Q.Y);
			var exchangeValue = writer.ToBuffer();
			return exchangeValue;
		}

		public Buffer DecryptKeyExchange(Buffer exchangeValue)
		{
			// X and Y parameters are equal length, after a one-byte header.
			var x = exchangeValue.Slice(1, (exchangeValue.Count - 1) / 2);
			var y = exchangeValue.Slice(1 + x.Count, x.Count);
			var otherEcdh = (System.Security.Cryptography.ECDiffieHellman)Activator.CreateInstance(
				ImplementationType!, this.ecdh.KeySize)!;
			var p = otherEcdh.ExportParameters(true);
			otherEcdh.ImportParameters(new ECParameters
			{
				Curve = p.Curve,
				Q = new ECPoint
				{
					X = x.ToArray(),
					Y = y.ToArray(),
				},
			});

			BigInt sharedSecret;
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			{
				sharedSecret = DecryptKeyExchangeWithNcrypt(otherEcdh.PublicKey);
			}
			else
			{
				sharedSecret = DecryptKeyExchangeWithOpenSsl(otherEcdh.PublicKey);
			}

			return sharedSecret.ToBuffer();
		}

		private BigInt DecryptKeyExchangeWithNcrypt(ECDiffieHellmanPublicKey otherPublicKey)
		{
			// https://stackoverflow.com/questions/38115602/exporting-shared-secret-as-byte-array-from-bcrypt-secret-handle

			var secretHandle = ((ECDiffieHellmanCng)this.ecdh).DeriveSecretAgreementHandle(
				otherPublicKey);
			using (secretHandle)
			{
				var deriveParameters = new NCrypt.BuffersDescriptor();
				int error = NCrypt.DeriveKey(
					secretHandle,
					NCrypt.KeyDerivationFunctions.RawSecret,
					ref deriveParameters,
					null,
					0,
					out int sharedSecretLength,
					NCrypt.SecretAgreementFlags.None);
				if (error != 0)
				{
					throw new CryptographicException(
						$"Failed to extract CNG ECDH shared secret. Error: {error}");
				}

				var sharedSecretBytes = new byte[sharedSecretLength];
				error = NCrypt.DeriveKey(
					secretHandle,
					NCrypt.KeyDerivationFunctions.RawSecret,
					ref deriveParameters,
					sharedSecretBytes,
					sharedSecretLength,
					out sharedSecretLength,
					NCrypt.SecretAgreementFlags.None);
				if (error != 0)
				{
					throw new CryptographicException(
						$"Failed to extract CNG ECDH shared secret. Error: {error}");
				}
				else if (sharedSecretBytes.Length != ((this.ecdh.KeySize + 7) / 8))
				{
					throw new CryptographicException(
						$"CNG ECDH shared secret is invalid length: {sharedSecretBytes.Length}");
				}

				return BigInt.FromByteArray(sharedSecretBytes, unsigned: true, littleEndian: true);
			}
		}

		private BigInt DecryptKeyExchangeWithOpenSsl(ECDiffieHellmanPublicKey otherPublicKey)
		{
			// The ability to "derive" the raw secret is not exposed in the public API.
			// The private method must be called via reflection.
			var sharedSecretBytes = (byte[]?)DeriveSecretMethod!.Invoke(
				this.ecdh, new object?[] { otherPublicKey, null });
			if (sharedSecretBytes == null)
			{
				throw new CryptographicException(
					"Failed to extract OpenSSL ECDH shared secret.");
			}
			else if (sharedSecretBytes.Length != ((this.ecdh.KeySize + 7) / 8))
			{
				throw new CryptographicException(
					$"OpenSSL ECDH shared secret is invalid length: {sharedSecretBytes.Length}");
			}

			return BigInt.FromByteArray(sharedSecretBytes, unsigned: true);
		}

		public void Sign(Buffer data, Buffer signature)
		{
			if (signature.Count != DigestLength)
			{
				throw new ArgumentException("Invalid signature buffer size.");
			}

			// Lock to avoid crash in Mac crypto due to overlapping HMAC calls.
			lock (this.hash)
			{
#if SSH_ENABLE_SPAN
				if (!this.hash.TryComputeHash(data.Span, signature.Span, out _))
				{
					throw new InvalidOperationException("Failed to compute hash.");
				}
#else
					Buffer result = this.hash.ComputeHash(data.Array, data.Offset, data.Count);
#if DEBUG
					Buffer.TrackAllocation(result.Count);
#endif
					result.CopyTo(signature);
#endif
			}
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
				this.ecdh.Dispose();
				this.hash.Dispose();
			}
		}
	}
}
#endif
