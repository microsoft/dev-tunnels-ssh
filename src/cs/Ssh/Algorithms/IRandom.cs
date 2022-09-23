// Copyright (c) Microsoft. All rights reserved.

using System.Security.Cryptography;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public interface IRandom
{
	/// <summary>
	/// Fills a buffer with cryptographically random bytes.
	/// </summary>
	void GetBytes(Buffer buffer);
}
