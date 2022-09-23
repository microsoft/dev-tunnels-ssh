// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Messages;

internal static class AuthenticationMethods
{
	public const string None = "none";
	public const string PublicKey = "publickey";
	public const string Password = "password";
	public const string HostBased = "hostbased";
}
