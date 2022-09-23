// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public interface IHmacInfo
{
	/// <summary>
	/// Gets a value indicating whether the encrypted bytes are signed/verified (EtM)
	/// or the unencrypted bytes are signed/verified (EaM / original SSH protocol).
	/// </summary>
	bool EncryptThenMac { get; }

	/// <summary>
	/// Gets a value indicating whether this HMAC is part of authenticated encryption
	/// with associated data (AEAD).
	/// </summary>
	bool AuthenticatedEncryption { get; }
}
