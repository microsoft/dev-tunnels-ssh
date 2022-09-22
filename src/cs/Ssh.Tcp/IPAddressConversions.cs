// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Net;

namespace Microsoft.DevTunnels.Ssh.Tcp;

internal static class IPAddressConversions
{
	/// <summary>
	/// Converts from an SSH-protocol address string to an IPAddress object.
	/// </summary>
	public static IPAddress FromString(string? address)
	{
		if (string.IsNullOrEmpty(address))
		{
			// SSH uses an empty address to indicate "both IPv4-any and IPv6-any",
			// while .NET does not have an IPAddress constant for that. The default
			// TCP listener factory treats this value as dual-mode anyway,
			// meaning there's no way to actually listen on only IPv4-any.
			// It would be strange for an application to actually want to exclude
			// IPv6 like that, so this should be a reasonable limitation of this library.
			return IPAddress.Any;
		}
		else if (address == "localhost")
		{
			// SSH uses a "localhost" address to indicate "both IPv4-loopback and
			// IPv6-loopback", while .NET does not have an IPAddress constant for that.
			// The port forwarding implementation treats this value as dual-mode,
			// though unlike "any" dual loopback requires 2 TCP listener instances.
			return IPAddress.Loopback;
		}
		else if (IPAddress.TryParse(address, out var value))
		{
			return value;
		}
		else
		{
			throw new ArgumentException("Invalid IP address: " + address);
		}
	}

	/// <summary>
	/// Converts from an IPAddress object to an SSH-protocol address string.
	/// </summary>
	public static string ToString(IPAddress address)
	{
		if (address == null)
		{
			return null!;
		}
		else if (address.Equals(IPAddress.Any))
		{
			return string.Empty;
		}
		else if (address.Equals(IPAddress.Loopback))
		{
			return "localhost";
		}
		else
		{
			return address.ToString();
		}
	}
}
