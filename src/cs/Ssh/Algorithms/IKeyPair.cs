// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public interface IKeyPair : IDisposable
{
	string KeyAlgorithmName { get; }

	bool HasPrivateKey { get; }

	string? Comment { get; set; }

	void SetPublicKeyBytes(Buffer keyBytes);

	Buffer GetPublicKeyBytes(string? algorithmName = null);
}

/// <summary>
/// Given a public key, provides the corresponding private key.
/// </summary>
/// <seealso cref="SshClientCredentials" />
/// <seealso cref="SshServerCredentials" />
public delegate Task<IKeyPair?> PrivateKeyProvider(
	IKeyPair publicKey,
	CancellationToken cancellation);
