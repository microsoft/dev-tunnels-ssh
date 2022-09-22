// Copyright (c) Microsoft. All rights reserved.

using System.Security.Cryptography;

namespace Microsoft.DevTunnels.Ssh.Algorithms;
#pragma warning disable CA1008 // Enums should have zero value
public enum CipherModeEx
#pragma warning restore CA1008 // Enums should have zero value
{
	CBC = CipherMode.CBC,
	CTR = 10,
}
