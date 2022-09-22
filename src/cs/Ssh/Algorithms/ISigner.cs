// Copyright (c) Microsoft. All rights reserved.

using System;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public interface ISigner : IDisposable
{
	/// <summary>
	/// Gets the length in bytes of a digest (signature) created by this signer.
	/// </summary>
	int DigestLength { get; }

	/// <summary>
	/// Signs data.
	/// </summary>
	/// <param name="data">Data to be signed.</param>
	/// <param name="signature">Buffer that receives the signature, must be exactly
	/// <see cref="DigestLength" /> size.</param>
	/// <exception cref="ArgumentException">The signature buffer is not exactly
	/// <see cref="DigestLength" /> size.</exception>
	/// <exception cref="InvalidOperationException">The key pair does not include
	/// a private key, that is required for signing.</exception>
	void Sign(Buffer data, Buffer signature);
}

public interface IMessageSigner : ISigner, IHmacInfo
{
}
