// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Messages;

/// <summary>
/// Defines constants for standard authentication methods.
/// </summary>
/// <seealso cref="SshSessionConfiguration.AuthenticationMethods" />
public static class AuthenticationMethods
{
	public const string None = "none";
	public const string PublicKey = "publickey";
	public const string Password = "password";
	public const string HostBased = "hostbased";
	public const string KeyboardInteractive = "keyboard-interactive";
}
