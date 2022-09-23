// Copyright (c) Microsoft. All rights reserved.

using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public class EncryptionAlgorithm : SshAlgorithm
{
	private readonly string algorithmName;
	private readonly CipherModeEx mode;

	public EncryptionAlgorithm(
		string name,
		string algorithmName,
		CipherMode mode,
		int keySizeInBits)
		: this(name, algorithmName, (CipherModeEx)mode, keySizeInBits)
	{
	}

	public EncryptionAlgorithm(
		string name,
		string algorithmName,
		CipherModeEx mode,
		int keySizeInBits)
		: base(name)
	{
		if (string.IsNullOrEmpty(algorithmName))
		{
			throw new ArgumentNullException(nameof(algorithmName));
		}

		if (!Enum.IsDefined(typeof(CipherMode), (CipherMode)mode) &&
			!Enum.IsDefined(typeof(CipherModeEx), mode))
		{
			throw new InvalidEnumArgumentException(nameof(mode), (int)mode, typeof(CipherModeEx));
		}

		this.algorithmName = algorithmName;
		KeySizeInBits = keySizeInBits;
		this.mode = mode;
		this.BlockLength = GetBlockLength(algorithmName);
	}

	public int KeySizeInBits { get; }

	public int KeyLength => KeySizeInBits / 8;

	public int BlockLength { get; }

	private static int GetBlockLength(string algorithmName)
	{
		if (algorithmName == "AES")
		{
			return 16;
		}
		else if (algorithmName == "DES" || algorithmName == "3DES")
		{
			return 8;
		}
		else
		{
			throw new NotSupportedException(
				$"Encryption algorithm not supported: {algorithmName}");
		}
	}

#if NET6_0_OR_GREATER
	[UnconditionalSuppressMessage(
		"Trimming",
		"IL2026:RequiresUnreferencedCode",
		Justification = "AES is referenced explicitly so is never trimmed; other algorithms are unsupported.")]
#endif
	public virtual ICipher CreateCipher(bool isEncryption, Buffer key, Buffer iv)
	{
		var algorithm = this.algorithmName == "AES" ? Aes.Create()
			: SymmetricAlgorithm.Create(algorithmName);
		if (algorithm == null)
		{
			throw new PlatformNotSupportedException(
				$"Failed to create encryption algorithm: {this.algorithmName}");
		}

		algorithm.Padding = PaddingMode.None;
		algorithm.KeySize = KeySizeInBits;

		ICryptoTransform transform;
		if (this.mode == CipherModeEx.CTR)
		{
			transform = new CtrModeCryptoTransform(algorithm, key, iv);
		}
		else
		{
			algorithm.Mode = (CipherMode)this.mode;
#pragma warning disable CA5401 // Do not use CreateEncryptor with non-default IV
			transform = isEncryption
				? algorithm.CreateEncryptor(key.ToArray(), iv.ToArray())
				: algorithm.CreateDecryptor(key.ToArray(), iv.ToArray());
#pragma warning restore CA5401 // Do not use CreateEncryptor with non-default IV
		}

		return new Cipher(algorithm, transform);
	}

	private class Cipher : ICipher
	{
		private readonly SymmetricAlgorithm algorithm;
		private readonly ICryptoTransform transform;
		private bool disposed;

		public Cipher(SymmetricAlgorithm algorithm, ICryptoTransform transform)
		{
			this.algorithm = algorithm;
			this.transform = transform;
			this.BlockLength = algorithm.BlockSize >> 3;
		}

		public int BlockLength { get; }

		public void Transform(Buffer input, Buffer output)
		{
			if (this.disposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}

			this.transform.TransformBlock(
				input.Array, input.Offset, input.Count, output.Array, output.Offset);
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
				this.transform.Dispose();
				this.algorithm.Dispose();
			}
		}
	}
}
