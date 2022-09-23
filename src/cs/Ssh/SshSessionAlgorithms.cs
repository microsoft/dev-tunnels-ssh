// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.DevTunnels.Ssh.Algorithms;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Algorithms that are negotiated between server and client for a session.
/// </summary>
internal class SshSessionAlgorithms : IDisposable
{
	public string? PublicKeyAlgorithmName { get; set; }

	public ICipher? Decipher { get; set; }

	public ICipher? Cipher { get; set; }

	public ISigner? Signer { get; set; }

	public IVerifier? Verifier { get; set; }

	public IMessageSigner? MessageSigner { get; set; }

	public IMessageVerifier? MessageVerifier { get; set; }

	public CompressionAlgorithm? Compressor { get; set; }

	public CompressionAlgorithm? Decompressor { get; set; }

	public void Dispose()
	{
		Dispose(true);
	}

	protected virtual void Dispose(bool disposing)
	{
		if (disposing)
		{
			Decipher?.Dispose();
			Cipher?.Dispose();
			Signer?.Dispose();
			Verifier?.Dispose();
			Compressor?.Dispose();
			Decompressor?.Dispose();
		}
	}
}
