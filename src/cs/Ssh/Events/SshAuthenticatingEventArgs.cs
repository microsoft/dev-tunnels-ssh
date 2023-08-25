// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Events;

/// <summary>
/// Indicates the type of authentication being requested by an SSH client or server when an
/// <see cref="SshSession.Authenticating"/> event is raised.
/// </summary>
/// <seealso cref="SshAuthenticatingEventArgs" />
public enum SshAuthenticationType
{
	/// <summary>
	/// The client is attempting to authenticate without any credentials, or with only a username,
	/// or is merely checking what authentication methods are supported by the server.
	/// </summary>
	/// <remarks>
	/// This event is raised by an <see cref="SshServerSession"/> when the client requests
	/// authentication using the "none" method. With this method, all of the credential properties
	/// in the <see cref="SshAuthenticatingEventArgs" /> are null.
	///
	/// If the server app wishes to allow the client to authenticate with only a username, it may
	/// return a principal for the user. Othwerwise, the "none" authentication method fails, and
	/// the client may make a follow-up attempt to authenticate _with_ credentials.
	/// </remarks>
	ClientNone = 0,

	/// <summary>
	/// The client is attempting to authenticate with a client host public key.
	/// </summary>
	/// <remarks>
	/// This event is raised by an <see cref="SshServerSession"/> when the client requests
	/// authentication using the "hostbased" method. The authentication handler must verify that
	/// the public key actually belongs to the client host name, _and_ that the network address
	/// the client connected from matches that host name, before returning a user principal to
	/// indicate successful authentication.
	/// </remarks>
	ClientHostBased = 1,

	/// <summary>
	/// The client is attempting to authenticate with a username and password credential.
	/// </summary>
	/// <remarks>
	/// This event is raised by an <see cref="SshServerSession"/> when the client requests
	/// authentication using the "password" method. The authentication handler must verify that
	/// the username and password match known credentials on the server, before returning a user
	/// principal to indicate successful authentication.
	/// </remarks>
	ClientPassword = 2,

	/// <summary>
	/// The client is querying whether authentication may be possible for a specified username and
	/// public key without yet proving they have the private key.
	/// </summary>
	/// <remarks>
	/// This event is raised by an <see cref="SshServerSession"/> when the client requests
	/// authentication using the "publickey" method _without_ providing a signature. The
	/// authentication handler must verify that the username and public key match known
	/// credentials on the server. If they match, an _unauthenticated_ principal should be
	/// returned. That indicates to the client that they may proceed to actually authenticate
	/// using that username and public key.
	/// </remarks>
	ClientPublicKeyQuery = 3,

	/// <summary>
	/// The client is attempting to authenticate with a username and public key credential.
	/// </summary>
	/// <remarks>
	/// This event is raised by an <see cref="SshServerSession"/> when the client requests
	/// authentication using the "publickey" method, including a signature that proves they have
	/// the private key. The authentication handler must verify that the username and public key
	/// match known credentials on the server, before returning a user principal to indicate
	/// successful authentication.
	/// </remarks>
	ClientPublicKey = 4,

	/// <summary>
	/// The client is attempting to authenticate with interactive prompts.
	/// </summary>
	/// <remarks>
	/// This event is raised by an <see cref="SshServerSession"/> when the client requests
	/// authentication using the "keyboard-interactive" method. The event may be raised multiple
	/// times for the same client to facilitate multi-step authentication.
	/// </remarks>
	ClientInteractive = 5,

	/// <summary>
	/// The server is attempting to authenticate with a public key credential.
	/// </summary>
	/// <remarks>
	/// This event is raised by an <see cref="SshClientSession"/> when the server requests
	/// authentication by providing a signature that proves it has the private key. The client
	/// authentication handler must verify that the public key matches known public key(s) for
	/// that server. Or if not known (often the case for the first time connecting to that server)
	/// it may prompt the user to consent, and then save the public key for later reference. To
	/// indicate successful authentication, the client authentication handler returns a principal
	/// that represents the server.
	/// </remarks>
	ServerPublicKey = 10,
}

/// <summary>
/// Arguments for the <see cref="SshSession.Authenticating"/> event that is raised when a client
/// or server is requesting authentication.
/// </summary>
/// <remarks>
/// See <see cref="SshAuthenticationType" /> for a description of the different authentication
/// methods and how they map to properties in this event-args object.
///
/// After validating the credentials, the event handler must set the
/// <see cref="AuthenticationTask" /> property to a task that resolves to a principal object
/// to indicate successful authentication. That principal will then be associated with the
/// session as the <see cref="SshSession.Principal" /> property.
/// </remarks>
[DebuggerDisplay("{ToString(),nq}")]
[DebuggerStepThrough]
public class SshAuthenticatingEventArgs
{
	public SshAuthenticatingEventArgs(
		SshAuthenticationType authenticationType,
		string? username = null,
		string? password = null,
		IKeyPair? publicKey = null,
		string? clientHostname = null,
		string? clientUsername = null,
		CancellationToken cancellation = default)
	{
		bool Validate(
			bool usernameRequired = false,
			bool passwordRequired = false,
			bool publicKeyRequired = false,
			bool clientHostnameRequired = false,
			bool clientUsernameRequired = false)
		{
			// This is intentionally not checking for empty strings. The authentication handler
			// should determine whether any non-null string values are valid.
			if ((username != null) != usernameRequired) return false;
			if ((password != null) != passwordRequired) return false;
			if ((publicKey != null) != publicKeyRequired) return false;
			if ((clientHostname != null) != clientHostnameRequired) return false;
			if ((clientUsername != null) != clientUsernameRequired) return false;
			return true;
		}

		if (!(authenticationType switch
		{
			SshAuthenticationType.ClientNone => Validate(true),
			SshAuthenticationType.ClientHostBased => Validate(true, false, true, true, true),
			SshAuthenticationType.ClientPassword => Validate(true, true),
			SshAuthenticationType.ClientPublicKeyQuery =>
				Validate(usernameRequired: true, publicKeyRequired: true),
			SshAuthenticationType.ClientPublicKey =>
				Validate(usernameRequired: true, publicKeyRequired: true),
			SshAuthenticationType.ServerPublicKey => Validate(publicKeyRequired: true),
			_ => throw new ArgumentException(
				$"Invalid authentication type: {authenticationType}", nameof(authenticationType)),
		}))
		{
			throw new ArgumentException(
				$"Invalid arguments for authentication type: {authenticationType}");
		}

		AuthenticationType = authenticationType;
		Username = username;
		Password = password;
		PublicKey = publicKey;
		ClientHostname = clientHostname;
		ClientUsername = clientUsername;
		Cancellation = cancellation;
	}

	public SshAuthenticatingEventArgs(
		SshAuthenticationType authenticationType,
		string? username,
		AuthenticationInfoRequestMessage? infoRequest,
		AuthenticationInfoResponseMessage? infoResponse,
		CancellationToken cancellation = default)
	{
		if (authenticationType != SshAuthenticationType.ClientInteractive)
		{
			throw new ArgumentException(
				$"Authentication type {SshAuthenticationType.ClientInteractive} expected.");
		}

		AuthenticationType = authenticationType;
		Username = username;
		InfoRequest = infoRequest;
		InfoResponse = infoResponse;
		Cancellation = cancellation;
	}

	/// <summary>
	/// Indicates the type of authentication being requested, which determines which credential
	/// properties are valid.
	/// </summary>
	public SshAuthenticationType AuthenticationType { get; }

	/// <summary>
	/// Gets the client's username on the server; valid for client password authentication, client
	/// public-key authentication, or client host-based authentication.
	///
	/// </summary>
	public string? Username { get; }

	/// <summary>
	/// Gets the client's password for the server; valid only for client password authentication.
	/// </summary>
	public string? Password { get; }

	/// <summary>
	/// Gets the server or client public key; valid for server authentication, client public-key
	/// authentication, or client host-based authentication.
	/// </summary>
	public IKeyPair? PublicKey { get; }

	/// <summary>
	/// Gets the client's host name; only valid for host-based authentication.
	/// </summary>
	public string? ClientHostname { get; }

	/// <summary>
	/// Gets the client's username on their client host; only valid for host-based authentication.
	/// </summary>
	public string? ClientUsername { get; }

	/// <summary>
	/// Gets or sets a request more information for interactive authentication.
	/// </summary>
	/// <remarks>
	/// The server may set this property when handling an interactive authenticating event to prompt
	/// for information/credentials. The client may read this property when handling an interactive
	/// authenticating event to determine what prompts to show and what information is requested.
	/// </remarks>
	public AuthenticationInfoRequestMessage? InfoRequest { get; set; }

	/// <summary>
	/// Gets or sets the client's responses to interactive prompts; valid only for interactive
	/// authentication when information was previously requested via <see cref="InfoRequest"/>.
	/// </summary>
	public AuthenticationInfoResponseMessage? InfoResponse { get; set; }

	/// <summary>
	/// Gets a token that is cancelled if the session ends before the authentication handler
	/// completes.
	/// </summary>
	public CancellationToken Cancellation { get; internal set; }

	/// <summary>
	/// Gets or sets a task to be filled in by the event handler to indicate whether async
	/// authentication is successful.
	/// </summary>
	/// <remarks>
	/// The authentication event handler must set this value to a task that resolves to a non-null
	/// principal object to indicate successful authentication of the server or client. Either a
	/// null task or a task that resolves to null indicates an authentication failure.
	/// </remarks>
	public Task<ClaimsPrincipal?>? AuthenticationTask { get; set; }

	public override string ToString()
	{
		if (InfoRequest != null)
		{
			return $"Info request: {InfoRequest.Name}";
		}
		else if (InfoResponse != null)
		{
			return $"Username: {Username}, Info response";
		}
		else if (Username != null)
		{
			return $"Username: {Username}, Key: {PublicKey?.KeyAlgorithmName ?? "password"}";
		}
		else
		{
			return $"Key: {PublicKey?.KeyAlgorithmName ?? "password"}";
		}
	}
}
