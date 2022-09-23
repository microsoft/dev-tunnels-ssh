// Copyright (c) Microsoft. All rights reserved.

using System;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public interface IVerifier : IDisposable
{
	/// <summary>
	/// Gets the length in bytes of a digest (signature) expected by this verifier.
	/// </summary>
	int DigestLength { get; }

	/// <summary>
	/// Checks if a signature is valid against the given data.
	/// </summary>
	/// <param name="data">Data that was previously signed.</param>
	/// <param name="signature">Signature to be validated.</param>
	/// <returns>True if the signature is valid, else false.</returns>
	bool Verify(Buffer data, Buffer signature);
}

public interface IMessageVerifier : IVerifier, IHmacInfo
{
}
