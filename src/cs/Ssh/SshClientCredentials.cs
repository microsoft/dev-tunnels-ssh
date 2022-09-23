// Copyright (c) Microsoft. All rights reserved.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Provides a username and password for client authentication.
/// </summary>
/// <remarks>
/// If no username/password is available or the user cancels, a null result
/// may be returned. If the session disconnects before this callback returns,
/// the cancellation token will be cancelled.
/// </remarks>
public delegate Task<(string, string?)?> PasswordCredentialProvider(
	CancellationToken cancellation);

/// <summary>
/// Defines credentials and/or credential callbacks for authenticating an SSH client session.
/// </summary>
/// <seealso cref="SshClientSession.AuthenticateAsync" />
public class SshClientCredentials
{
	/// <summary>
	/// Creates a new credentials object with optional callback that provides a username and
	/// password when required.
	/// </summary>
	public SshClientCredentials(PasswordCredentialProvider? passwordProvider = null)
	{
		PasswordProvider = passwordProvider;
	}

	/// <summary>
	/// Creates a new credentials object containing a pre-set username or username and password.
	/// </summary>
	/// <remarks>
	/// A <see cref="PasswordProvider" /> callback may be set instead of supplying a username
	/// and password up front.
	///
	/// If neither a password, nor public keys, nor any provider callback are specified, then
	/// the client will attempt to authenticate with only the username, which may or may not be
	/// allowed by the server.
	///
	/// If both public key and password credentials are set, then public key authentication
	/// will be attempted first.
	/// </remarks>
	public SshClientCredentials(string username, string? password = null)
	{
		Username = username;
		Password = password;
	}

	/// <summary>
	/// Creates a new credentials object containing a username and one or more public keys.
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
	public SshClientCredentials(string username, params IKeyPair[] publicKeys)
	{
		Username = username;
		PublicKeys = new List<IKeyPair>(publicKeys);
	}

	public string? Username { get; set; }

	public string? Password { get; set; }

	public PasswordCredentialProvider? PasswordProvider { get; set; }

	public ICollection<IKeyPair> PublicKeys { get; } = new List<IKeyPair>();

	public PrivateKeyProvider? PrivateKeyProvider { get; set; }

#pragma warning disable CA2225 // Operator overloads have named alternates
	public static implicit operator SshClientCredentials(
		(string Username, string Password) passwordCredentials)
	{
		return new SshClientCredentials(
			passwordCredentials.Username, passwordCredentials.Password);
	}

	public static implicit operator SshClientCredentials(
		(string Username, IKeyPair PublicKey) publicKeyCredentials)
	{
		return new SshClientCredentials(
			publicKeyCredentials.Username, publicKeyCredentials.PublicKey);
	}
#pragma warning restore CA2225 // Operator overloads have named alternates
}
