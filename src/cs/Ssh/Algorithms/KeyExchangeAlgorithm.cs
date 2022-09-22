// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public abstract class KeyExchangeAlgorithm : SshAlgorithm
{
	protected KeyExchangeAlgorithm(
		string name,
		int keySizeInBits,
		string hashAlgorithmName,
		int hashDigestLength)
		: base(name)
	{
		this.KeySizeInBits = keySizeInBits;
		this.HashAlgorithmName = hashAlgorithmName;
		this.HashDigestLength = hashDigestLength;
	}

	public int KeySizeInBits { get; }
	public string HashAlgorithmName { get; }
	public int HashDigestLength { get; }

	public abstract IKeyExchange CreateKeyExchange();
}
