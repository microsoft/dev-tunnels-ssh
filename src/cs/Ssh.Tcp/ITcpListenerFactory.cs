// Copyright (c) Microsoft. All rights reserved.

using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Interface for a factory that can create a TCP listener for an SSH server
/// or SSH port-forwarding.
/// </summary>
public interface ITcpListenerFactory
{
	/// <summary>
	/// Creates and starts a TCP listener for the specified local network address and port
	/// number.
	/// </summary>
	/// <param name="remotePort">The remote port that this local port will connect to (if known).
	/// </param>
	/// <param name="localIPAddress">Local IP address to listen on.</param>
	/// <param name="localPort">Requested local port to listen on, or 0 to use a random
	/// available port number.</param>
	/// <param name="canChangeLocalPort">True if the factory is allowed to select a different
	/// local port number than the one that was requested; if false then the factory must either
	/// use the requested port or throw an exception.</param>
	/// <param name="trace">Trace source.</param>
	/// <param name="cancellation">Cancellation token.</param>
	/// <returns>TCP listener object that has started listening.</returns>
	/// <exception cref="SocketException">Creating or starting the listener failed.</exception>
	/// <remarks>
	/// The <paramref name="localIPAddress" /> may be any of the following values:
	///  - `IPAddress.Loopback`: Bind to IPv4 and IPv6 loopback interfaces.
	///  - `IPAddress.IPv6Loopback`: Bind to only the IPv6 loopback interfaces.
	///  - `IPAddress.Any`: Bind to all IPv4 and IPv6 interfaces.
	///  - `IPAddress.IPv6Any`: Bind to only IPv6 interfaces.
	///  - Any other IP address: Bind to the interface with the specified IP address.
	/// <para />
	/// The factory implementation may choose an alternate port number instead of the requested
	/// <paramref name="localPort"/> value, for instance if the requested port is in-use or the
	/// current process does not have permission to listen on it. In that case the caller will
	/// obtain the actual port from the returned listener's
	/// <see cref="TcpListener.LocalEndpoint"/> property.
	/// </remarks>
	Task<TcpListener> CreateTcpListenerAsync(
		int? remotePort,
		IPAddress localIPAddress,
		int localPort,
		bool canChangeLocalPort,
		TraceSource trace,
		CancellationToken cancellation);
}
