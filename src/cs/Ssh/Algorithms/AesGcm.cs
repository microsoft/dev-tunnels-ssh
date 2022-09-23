// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

#if SSH_ENABLE_AESGCM
namespace Microsoft.DevTunnels.Ssh.Algorithms;

/// <summary>
/// Implements the AES-GCM cipher for SSH.
/// </summary>
/// <remarks>
/// This cipher works a little bit differently from other ciphers, because it has
/// built-in message authentication. The "tag" produced by encrypting is used in
/// place of the SSH MAC. (The negotiated HMAC algorithm is unused.)
/// </remarks>
public class AesGcm : EncryptionAlgorithm
{
	public override bool IsAvailable
	{
		get
		{
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			{
				return true;
			}
			else
			{
				return OpenSslAssembly != null;
			}
		}
	}

	public AesGcm(string name, int keySizeInBits)
		: base(name, "AES", CipherModeEx.CTR, keySizeInBits)
	{
	}

	public override ICipher CreateCipher(bool isEncryption, Buffer key, Buffer iv)
	{
#pragma warning disable CA2000 // Dispose objects before losing scope
#if SSH_ENABLE_SPAN
		var cipher = new System.Security.Cryptography.AesGcm(key.Span);
#else
			var cipher = new System.Security.Cryptography.AesGcm(key.ToArray());
#endif
#pragma warning restore CA2000 // Dispose objects before losing scope
		return new Cipher(isEncryption, cipher, BlockLength, iv);
	}

	private class Cipher : ICipher, IMessageSigner, IMessageVerifier
	{
		private readonly bool isEncryption;
		private readonly System.Security.Cryptography.AesGcm cipher;
		private readonly Buffer nonce;
		private readonly Buffer tag;
		private bool disposed;

		public Cipher(
			bool isEncryption,
			System.Security.Cryptography.AesGcm cipher,
			int blockLength,
			Buffer iv)
		{
			this.isEncryption = isEncryption;
			this.cipher = cipher;
			this.BlockLength = blockLength;

			// The nonce is initialized from the first 12 bytes of the IV.
			// (The last 8 bytes will be incremented for every encrypt/decrypt invocation,
			// similar to CTR cipher mode.)
			this.nonce = Buffer.From(iv.Slice(0, 12).ToArray());

			// This temporary reusable buffer stores the tag.
			this.tag = new Buffer(16);
		}

		public int BlockLength { get; }

		public int DigestLength { get; } = 16;

		public bool EncryptThenMac => false;

		public bool AuthenticatedEncryption => true;

		/// <summary>
		/// Encrypts or decrypts data using AES-GCM.
		/// </summary>
		/// <param name="input">Input buffer.</param>
		/// <param name="output">Output buffer (may overlap with input).</param>
		/// <exception cref="CryptographicException">Thrown when tag validation failed
		/// during decryption.</exception>
		public void Transform(Buffer input, Buffer output)
		{
			if (this.disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}

			// Associated data is the 32-bit packet length.
			var packetLength = (uint)input.Count;
			var associatedData = new byte[4]
			{
					(byte)(packetLength >> 24),
					(byte)(packetLength >> 16),
					(byte)(packetLength >> 8),
					(byte)packetLength,
			};

#if SSH_ENABLE_SPAN
			if (isEncryption)
			{
				this.cipher.Encrypt(
					this.nonce.Span,
					input.Span,
					output.Span,
					this.tag.Span,
					associatedData);
			}
			else
			{
				this.cipher.Decrypt(
					this.nonce.Span,
					input.Span,
					this.tag.Span,
					output.Span,
					associatedData);
			}
#else
				var outputBuffer = new Buffer(output.Count);

				if (isEncryption)
				{
					this.cipher.Encrypt(
						this.nonce.Array,
						input.ToArray(),
						outputBuffer.Array,
						this.tag.Array,
						associatedData);
				}
				else
				{
					this.cipher.Decrypt(
						this.nonce.Array,
						input.ToArray(),
						this.tag.Array,
						outputBuffer.Array,
						associatedData);
				}

				outputBuffer.CopyTo(output);
#endif

			// Increment the counter (last 8 bytes of the nonce) as a big-endian integer.
			// First increment the last byte, and if it reaches 0 then increment the
			// next-to-last byte, and so on.
			var n = this.nonce.Array;
			var k = 12;
			while (--k >= 4 && ++n[k] == 0)
			{
			}
		}

		/// <summary>
		/// Called after encrypting to get the tag that was produced by encryption.
		/// </summary>
		/// <param name="data">Ignored.</param>
		/// <param name="signature">Buffer that will receive the AES-GCM tag.</param>
		public void Sign(Buffer data, Buffer signature)
		{
			if (signature.Count != this.tag.Count)
			{
				throw new ArgumentException("Invalid AES-GCM tag length.");
			}

			// The tag was produced while encrypting.
			// Note the returned buffer will be re-used by the next transform call.
			this.tag.CopyTo(signature);
		}

		/// <summary>
		/// Called before decrypting to set the tag that will be used to verify
		/// the data during decryption.
		/// </summary>
		/// <param name="data">Ignored.</param>
		/// <param name="signature">The AES-GCM tag.</param>
		/// <returns>This always returns true. In case of an invalid signature (tag),
		/// the decryption will throw a <see cref="CryptographicException" />.</returns>
		public bool Verify(Buffer data, Buffer signature)
		{
			if (signature.Count != this.tag.Count)
			{
				throw new ArgumentException("Invalid AES-GCM tag length.");
			}

			signature.CopyTo(this.tag);
			return true;
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (disposing && !this.disposed)
			{
				this.disposed = true;
				this.cipher.Dispose();
			}
		}
	}
}
#endif
