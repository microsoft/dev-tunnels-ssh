// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Security.Cryptography;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public class HmacAlgorithm : SshAlgorithm
{
	public const string Sha512 = "SHA2-512";
	public const string Sha384 = "SHA2-384";
	public const string Sha256 = "SHA2-256";

	private readonly string algorithmName;

	public HmacAlgorithm(string name, string algorithmName, bool encryptThenMac = false)
		: base(name)
	{
		if (string.IsNullOrEmpty(algorithmName)) throw new ArgumentNullException(nameof(algorithmName));

		this.algorithmName = algorithmName;
		KeyLength = GetHashKeyLength(algorithmName);
		DigestLength = GetHashDigestLength(algorithmName);
		EncryptThenMac = encryptThenMac;
	}

	public bool EncryptThenMac { get; }

	public int KeyLength { get; }

	public virtual int DigestLength { get; }

	public virtual IMessageSigner CreateSigner(Buffer key)
	{
		var hash = CreateHash(this.algorithmName, key);
		return new SignerVerifier(hash, EncryptThenMac);
	}

	public virtual IMessageVerifier CreateVerifier(Buffer key)
	{
		var hash = CreateHash(this.algorithmName, key);
		return new SignerVerifier(hash, EncryptThenMac);
	}

	private static KeyedHashAlgorithm CreateHash(string algorithmName, Buffer key)
	{
		if (algorithmName == Sha512)
		{
			var hash = new HMACSHA512();
			hash.Key = key.ToArray();
			return hash;
		}
		else if (algorithmName == Sha384)
		{
			return new HMACSHA384(key.ToArray());
		}
		else if (algorithmName == Sha256)
		{
			return new HMACSHA256(key.ToArray());
		}
		else
		{
			throw new NotSupportedException(
				$"Hash algorithm not supported: {algorithmName}");
		}
	}

	internal static int GetHashKeyLength(string algorithmName)
	{
		if (algorithmName == Sha512)
		{
			return 512 >> 3;
		}
		else if (algorithmName == Sha384)
		{
			return 384 >> 3;
		}
		else if (algorithmName == Sha256)
		{
			return 256 >> 3;
		}
		else
		{
			throw new NotSupportedException(
				$"Hash algorithm not supported: {algorithmName}");
		}
	}

	internal static int GetHashDigestLength(string algorithmName)
	{
		if (algorithmName == Sha512)
		{
			return 512 >> 3;
		}
		else if (algorithmName == Sha384)
		{
			return 384 >> 3;
		}
		else if (algorithmName == Sha256)
		{
			return 256 >> 3;
		}
		else
		{
			throw new NotSupportedException(
				$"Hash algorithm not supported: {algorithmName}");
		}
	}

	private class SignerVerifier : IMessageSigner, IMessageVerifier
	{
		private readonly KeyedHashAlgorithm hash;
#if SSH_ENABLE_SPAN
		private readonly Buffer verifyBuffer;
#endif

		public SignerVerifier(KeyedHashAlgorithm hash, bool encryptThenMac)
		{
			this.hash = hash;
#if SSH_ENABLE_SPAN
			this.verifyBuffer = new Buffer(DigestLength);
#endif
			EncryptThenMac = encryptThenMac;
		}

		public bool EncryptThenMac { get; }

		public bool AuthenticatedEncryption => false;

		public int DigestLength => this.hash.HashSize >> 3;

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

		public bool Verify(Buffer data, Buffer signature)
		{
			if (signature.Count != DigestLength)
			{
				throw new ArgumentException("Invalid signature size.");
			}

			// Lock to avoid crash in Mac crypto due to overlapping HMAC calls.
			lock (this.hash)
			{
#if SSH_ENABLE_SPAN
				if (!this.hash.TryComputeHash(data.Span, this.verifyBuffer.Span, out _))
				{
					throw new InvalidOperationException("Failed to compute hash.");
				}

				return this.verifyBuffer.Equals(signature);
#else
				Buffer verifySignature = this.hash.ComputeHash(data.Array, data.Offset, data.Count);
#if DEBUG
				Buffer.TrackAllocation(verifySignature.Count);
#endif
				return verifySignature.Equals(signature);
#endif
			}
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing)
			{
				this.hash.Dispose();
			}
		}
	}
}
