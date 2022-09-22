// Copyright (c) Microsoft. All rights reserved.

using System;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public abstract class CompressionAlgorithm : SshAlgorithm, IDisposable
{
	protected CompressionAlgorithm(string name)
		: base(name)
	{
	}

	public abstract Buffer Compress(Buffer input);

	public abstract Buffer Decompress(Buffer input);

	public void Dispose()
	{
		Dispose(true);
		GC.SuppressFinalize(this);
	}

	protected abstract void Dispose(bool disposing);
}
