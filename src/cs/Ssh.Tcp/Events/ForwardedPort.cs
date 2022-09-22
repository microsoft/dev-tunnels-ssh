// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;

namespace Microsoft.DevTunnels.Ssh.Tcp.Events;

/// <summary>
/// Represents a port being forwarded over an SSH session.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
public class ForwardedPort : IEquatable<ForwardedPort>
{
	private readonly bool isRemote;

	internal ForwardedPort(int? localPort, int? remotePort, bool isRemote)
	{
		if (localPort == null && remotePort == null)
		{
			throw new ArgumentNullException(
				nameof(localPort), "Local and remote ports cannot both be null.");
		}
		else if (!isRemote && remotePort == null)
		{
			// The remote port number should always be known for locally forwarded ports.
			throw new ArgumentNullException(nameof(remotePort));
		}

		if (localPort == 0)
		{
			throw new ArgumentOutOfRangeException(nameof(localPort), "Local port must not be 0.");
		}
		else if (remotePort == 0)
		{
			throw new ArgumentOutOfRangeException(nameof(remotePort), "Remote port must not be 0.");
		}

		LocalPort = localPort;
		RemotePort = remotePort;
		this.isRemote = isRemote;
	}

	/// <summary>
	/// Gets the port number on the local side, or null if this is a remotely forwarded port
	/// for which there is no local TCP listener.
	/// </summary>
	public int? LocalPort { get; }

	/// <summary>
	/// Gets the port number on the remote side, or null if this is a remotely forwarded port
	/// and the remote port number is not known.
	/// </summary>
	public int? RemotePort { get; }

	/// <summary>
	/// Gets a string representation of the forwarded port, which includes both
	/// local and remote port numbers if present.
	/// </summary>
	/// <remarks>
	/// An arrow shows the direction of connections (channel open requests).
	/// Once connections are opened, data may flow in both directions.
	/// </remarks>
	public override string ToString()
	{
		var arrow = this.isRemote ? "->" : "<-";

		if (LocalPort == null)
		{
			return $"{arrow}{RemotePort}";
		}
		else if (RemotePort == null)
		{
			return $"{LocalPort}{arrow}";
		}
		else
		{
			return $"{LocalPort}{arrow}{RemotePort}";
		}
	}

	public static bool operator ==(ForwardedPort? a, ForwardedPort? b)
	{
		return object.ReferenceEquals(a, null) ? object.ReferenceEquals(b, null) : a.Equals(b);
	}

	public static bool operator !=(ForwardedPort? a, ForwardedPort? b)
	{
		return !(a == b);
	}

	/// <inheritdoc/>
	public bool Equals(ForwardedPort? other)
	{
		if (object.ReferenceEquals(other, null))
		{
			return false;
		}

		return LocalPort == other.LocalPort &&
			RemotePort == other.RemotePort &&
			this.isRemote == other.isRemote;
	}

	/// <inheritdoc/>
	public override bool Equals(object? obj)
	{
		return obj is ForwardedPort forwardedPort && Equals(forwardedPort);
	}

	/// <inheritdoc/>
	public override int GetHashCode()
	{
		return (LocalPort?.GetHashCode() ?? 0) ^ (RemotePort?.GetHashCode() ?? 0);
	}
}
