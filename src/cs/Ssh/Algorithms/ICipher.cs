// Copyright (c) Microsoft. All rights reserved.

using System;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public interface ICipher : IDisposable
{
	int BlockLength { get; }

	void Transform(Buffer input, Buffer output);
}
