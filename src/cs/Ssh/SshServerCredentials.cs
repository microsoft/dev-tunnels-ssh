// Copyright (c) Microsoft. All rights reserved.

using System.Collections.Generic;
using Microsoft.DevTunnels.Ssh.Algorithms;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Defines credentials and/or credential callbacks for authenticating an SSH server session.
/// </summary>
/// <seealso cref="SshServerSession.Credentials" />
public class SshServerCredentials
{
	/// <summary>
	/// Creates a new credentials object containing one or more public keys.
	/// </summary>
	/// <remarks>
	/// The key pair objects may optionally include the private keys; alternatively loading of the
	/// private keys may be delayed until requested, if a <see cref="PrivateKeyProvider"/>
	/// is specified.
	///
	/// If neither a password, nor public keys, nor any provider callback are specified, then
	/// the client will attempt to authenticate with only the username, which may or may not be
	/// allowed by the server.
	///
	/// If both public key and password credentials are set, then public key authentication
	/// will be attempted first.
	/// </remarks>
	public SshServerCredentials(params IKeyPair[] publicKeys)
	{
		PublicKeys = new List<IKeyPair>(publicKeys);
	}

	public ICollection<IKeyPair> PublicKeys { get; } = new List<IKeyPair>();

	public PrivateKeyProvider? PrivateKeyProvider { get; set; }

#pragma warning disable CA2225 // Operator overloads have named alternates
	public static implicit operator SshServerCredentials(IKeyPair[] publicKeys)
	{
		return new SshServerCredentials(publicKeys);
	}
#pragma warning restore CA2225 // Operator overloads have named alternates
}
