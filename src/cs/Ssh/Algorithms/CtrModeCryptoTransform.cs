// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Security.Cryptography;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

// Disable the warning about using unsafe cipher mode 'ECB'.
// ECB cipher mode is indeed weak, but it is not actually used.
// .NET does not have a built-in CTR cipher mode implementation, so
// this class implements CTR mode by building on top of ECB. ECB means
// there is no change to the IV between encrypted blocks. CTR cipher
// mode is one way to resolve that issue, by transforming the IV with
// a "counter" for each block. (CBC is an alternative, which transforms
// the IV using the previous block cipher text instead.) A weakness
// in CTR mode is that it could allow an attacker to change the
// ciphertext (and thus the resulting plaintext) in a way that is
// undetectable by decryption. But that is completely mitigated by a
// message integrity check like HMAC, which is part of the SSH protocol.
#pragma warning disable CA5358 // Do Not Use Unsafe Cipher Modes

public class CtrModeCryptoTransform : ICryptoTransform
{
	private readonly ICryptoTransform transform;
	private readonly byte[] iv;
	private readonly byte[] block;

	public CtrModeCryptoTransform(SymmetricAlgorithm algorithm, Buffer key, Buffer iv)
	{
		if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));

		algorithm.Mode = CipherMode.ECB;
		algorithm.Padding = PaddingMode.None;

#pragma warning disable CA5401 // Do not use CreateEncryptor with non-default IV
		this.transform = algorithm.CreateEncryptor(key.ToArray(), iv.ToArray());
#pragma warning restore CA5401 // Do not use CreateEncryptor with non-default IV

		// Make a copy of the IV because it will be mutated as the counter.
		this.iv = iv.Copy().Array;

		this.block = new Buffer(algorithm.BlockSize >> 3).Array;
		InputBlockSize = algorithm.BlockSize;
		OutputBlockSize = algorithm.BlockSize;
	}

	public bool CanReuseTransform => true;

	public bool CanTransformMultipleBlocks => true;

	public int InputBlockSize { get; }

	public int OutputBlockSize { get; }

	public int TransformBlock(
		byte[] inputBuffer,
		int inputOffset,
		int inputCount,
		byte[] outputBuffer,
		int outputOffset)
	{
		if (inputBuffer == null) throw new ArgumentNullException(nameof(inputBuffer));
		if (outputBuffer == null) throw new ArgumentNullException(nameof(outputBuffer));

		var written = 0;
		var bytesPerBlock = InputBlockSize >> 3;
		if (inputCount % bytesPerBlock != 0)
		{
			throw new ArgumentException("Transform input must be a multiple of block size.");
		}

		for (var i = 0; i < inputCount; i += bytesPerBlock)
		{
			// Transform the IV (plus counter for this block), writing into a temporary buffer.
			written += this.transform.TransformBlock(
				this.iv, 0, bytesPerBlock, this.block, 0);

			// Xor input with the tmporary buffer to produce the CTR-transformed output.
			for (var j = 0; j < bytesPerBlock; j++)
			{
				outputBuffer[outputOffset + i + j] =
					(byte)(this.block[j] ^ inputBuffer[inputOffset + i + j]);
			}

			// Increment the counter that is combined with the IV as a big-endian integer.
			// First increment the last byte, and if it reaches 0 then increment the
			// next-to-last byte, and so on.
			var k = this.iv.Length;
			while (--k >= 0 && ++this.iv[k] == 0)
			{
			}
		}

		return written;
	}

	byte[] ICryptoTransform.TransformFinalBlock(
		byte[] inputBuffer, int inputOffset, int inputCount)
	{
		// This method is not called anywhere by SSH code.
		throw new NotImplementedException();
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
			this.transform.Dispose();
			Array.Clear(this.iv, 0, this.iv.Length);
			Array.Clear(this.block, 0, this.block.Length);
		}
	}
}
