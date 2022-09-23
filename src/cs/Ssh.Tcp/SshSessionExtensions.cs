// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Tcp;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// <see cref="SshSession" /> extension methods for port-forwarding.
/// </summary>
/// <remarks>
/// Use <see cref="SshSessionConfiguration.AddService" /> on both client and server side
/// configurations to add the <see cref="PortForwardingService" /> used by these methods.
/// </remarks>
public static class SshSessionExtensions
{
	/// <summary>
	/// Sends a request to the remote side to listen on a port and forward incoming connections
	/// as SSH channels of type 'forwarded-tcpip', which will then be relayed to the same port
	/// number on the local side.
	/// </summary>
	/// <param name="session">SSH session that initiates the forwarding.</param>
	/// <param name="remoteIPAddress">IP address of the interface to bind to on the remote
	/// side.</param>
	/// <param name="port">The port number to forward. (Must not be 0.)</param>
	/// <param name="cancellation">Cancellation token for the request; note this cannot
	/// cancel forwarding once it has started; use the returned disposable do do that.</param>
	/// <returns>A disposable object that when disposed will cancel forwarding the port, or
	/// null if the request was rejected by the remote side, possibly because the port
	/// was already in use.</returns>
	/// <remarks>
	/// The <paramref name="remoteIPAddress" /> may be any of the following values:
	///  - `IPAddress.Loopback`: Bind to IPv4 and IPv6 loopback interfaces.
	///  - `IPAddress.IPv6Loopback`: Bind to only the IPv6 loopback interfaces.
	///  - `IPAddress.Any`: Bind to all IPv4 and IPv6 interfaces.
	///  - `IPAddress.IPv6Any`: Bind to only IPv6 interfaces.
	///  - Any other IP address: Bind to the interface with the specified IP address.
	/// <para />
	/// Disposing the returned object does not close any channels currently forwarding
	/// connections; it only sends a request to the remote side to stop listening on the remote
	/// port.
	/// </remarks>
	public static Task<RemotePortForwarder?> ForwardFromRemotePortAsync(
		this SshSession session,
		IPAddress remoteIPAddress,
		int port,
		CancellationToken cancellation = default)
	{
		return ForwardFromRemotePortAsync(
			session, remoteIPAddress, port, IPAddress.Loopback.ToString(), port, cancellation);
	}

	/// <summary>
	/// Sends a request to the remote side to listen on a port and forward incoming connections
	/// as SSH channels of type 'forwarded-tcpip', which will then be relayed to a specified
	/// local port.
	/// </summary>
	/// <param name="session">SSH session that initiates the forwarding.</param>
	/// <param name="remoteIPAddress">IP address of the interface to bind to on the remote
	/// side.</param>
	/// <param name="remotePort">The remote port to listen on, or 0 to choose an
	/// available port. (The chosen port can then be obtained via the
	/// <see cref="RemotePortConnector.RemotePort" /> property on the returned object.)</param>
	/// <param name="localHost">The destination hostname or IP address for forwarded
	/// connections, to be resolved on the local side. WARNING: Avoid using the hostname
	/// `localhost` as the destination host; use `127.0.0.1` or `::1` instead. OpenSSH does not
	/// recognize `localhost` as a valid destination host, and it can be slower anyway due to
	/// a bug in .NET Core: https://github.com/dotnet/runtime/issues/31085 </param>
	/// <param name="localPort">The destination port for forwarded connections.
	/// (Must not be 0.)</param>
	/// <param name="cancellation">Cancellation token for the request; note this cannot
	/// cancel forwarding once it has started; use the returned disposable do do that.</param>
	/// <returns>A disposable object that when disposed will cancel forwarding the port, or
	/// null if the request was rejected by the remote side, possibly because the remote port
	/// was already in use.</returns>
	/// <remarks>
	/// The <paramref name="remoteIPAddress" /> may be any of the following values:
	///  - `IPAddress.Loopback`: Bind to IPv4 and IPv6 loopback interfaces.
	///  - `IPAddress.IPv6Loopback`: Bind to only the IPv6 loopback interfaces.
	///  - `IPAddress.Any`: Bind to all IPv4 and IPv6 interfaces.
	///  - `IPAddress.IPv6Any`: Bind to only IPv6 interfaces.
	///  - Any other IP address: Bind to the interface with the specified IP address.
	/// <para />
	/// Disposing the returned object does not close any channels currently forwarding
	/// connections; it only sends a request to the remote side to stop listening on the remote
	/// port.
	/// </remarks>
	public static async Task<RemotePortForwarder?> ForwardFromRemotePortAsync(
		this SshSession session,
		IPAddress remoteIPAddress,
		int remotePort,
		string localHost,
		int localPort,
		CancellationToken cancellation = default)
	{
		var pfs = GetPortForwardingService(session);
		return await pfs.ForwardFromRemotePortAsync(
			remoteIPAddress, remotePort, localHost, localPort, cancellation).ConfigureAwait(false);
	}

	/// <summary>
	/// Starts listening on a local port and forwards incoming connections as SSH channels
	/// of type 'direct-tcpip', which will then be relayed to the same port number on the
	/// remote side, regardless of whether the remote side has explicitly forwarded that port.
	/// </summary>
	/// <param name="session">SSH session that initiates the forwarding.</param>
	/// <param name="localIPAddress">IP address of the interface to bind to on the local
	/// side.</param>
	/// <param name="port">The port number to forward. (Must not be 0.)</param>
	/// <param name="cancellation">Cancellation token for the request; note this cannot
	/// cancel forwarding once it has started; use the returned disposable do do that.</param>
	/// <returns>A disposable object that when disposed will cancel forwarding the port.</returns>
	/// <exception cref="SocketException">The local port is already in use.</exception>
	/// <remarks>
	/// The <paramref name="localIPAddress" /> may be any of the following values:
	///  - `IPAddress.Loopback`: Bind to IPv4 and IPv6 loopback interfaces.
	///  - `IPAddress.IPv6Loopback`: Bind to only the IPv6 loopback interfaces.
	///  - `IPAddress.Any`: Bind to all IPv4 and IPv6 interfaces.
	///  - `IPAddress.IPv6Any`: Bind to only IPv6 interfaces.
	///  - Any other IP address: Bind to the interface with the specified IP address.
	/// <para />
	/// Disposing the returned object does not close any channels currently forwarding
	/// connections; it only stops listening on the local port.
	/// </remarks>
	public static Task<LocalPortForwarder> ForwardToRemotePortAsync(
		this SshSession session,
		IPAddress localIPAddress,
		int port,
		CancellationToken cancellation = default)
	{
		return ForwardToRemotePortAsync(
			session, localIPAddress, port, IPAddress.Loopback.ToString(), port, cancellation);
	}

	/// <summary>
	/// Starts listening on a local port and forwards incoming connections as SSH channels
	/// of type 'direct-tcpip', which will then be relayed to a specified remote port,
	/// regardless of whether the remote side has explicitly forwarded that port.
	/// </summary>
	/// <param name="session">SSH session that initiates the forwarding.</param>
	/// <param name="localIPAddress">IP address of the interface to bind to on the local
	/// side.</param>
	/// <param name="localPort">The local port number to lsiten on, or 0 to choose an
	/// available port. (The chosen port can then be obtained via the
	/// <see cref="LocalPortForwarder.LocalPort" /> property on the returned object.)</param>
	/// <param name="remoteHost">The destination hostname or IP address for forwarded
	/// connections, to be resolved on the remote side. WARNING: Avoid using the hostname
	/// `localhost` as the destination host; use `127.0.0.1` or `::1` instead. OpenSSH does not
	/// recognize `localhost` as a valid destination host, and it can be slower anyway due to
	/// a bug in .NET Core: https://github.com/dotnet/runtime/issues/31085 </param>
	/// <param name="remotePort">The destination port for forwarded connections.
	/// (Must not be 0.)</param>
	/// <param name="cancellation">Cancellation token for the request; note this cannot
	/// cancel forwarding once it has started; use the returned disposable do do that.</param>
	/// <returns>A disposable object that when disposed will cancel forwarding the port.</returns>
	/// <exception cref="SocketException">The local port is already in use.</exception>
	/// <remarks>
	/// The <paramref name="localIPAddress" /> may be any of the following values:
	///  - `IPAddress.Loopback`: Bind to IPv4 and IPv6 loopback interfaces.
	///  - `IPAddress.IPv6Loopback`: Bind to only the IPv6 loopback interfaces.
	///  - `IPAddress.Any`: Bind to all IPv4 and IPv6 interfaces.
	///  - `IPAddress.IPv6Any`: Bind to only IPv6 interfaces.
	///  - Any other IP address: Bind to the interface with the specified IP address.
	/// <para />
	/// Disposing the returned object does not close any channels currently forwarding
	/// connections; it only stops listening on the local port.
	/// </remarks>
	public static async Task<LocalPortForwarder> ForwardToRemotePortAsync(
		this SshSession session,
		IPAddress localIPAddress,
		int localPort,
		string remoteHost,
		int remotePort,
		CancellationToken cancellation = default)
	{
		var pfs = GetPortForwardingService(session);
		return await pfs.ForwardToRemotePortAsync(
			localIPAddress, localPort, remoteHost, remotePort, cancellation).ConfigureAwait(false);
	}

	/// <summary>
	/// Sends a request to the remote side to listen on a port and forward incoming connections
	/// as SSH channels of type 'forwarded-tcpip', which will then be relayed as local streams.
	/// </summary>
	/// <param name="session">SSH session that initiates the forwarding.</param>
	/// <param name="remoteIPAddress">IP address of the interface to bind to on the remote
	/// side.</param>
	/// <param name="remotePort">The remote port to listen on, or 0 to choose an
	/// available port. (The chosen port can then be obtained via the
	/// <see cref="RemotePortConnector.RemotePort" /> property on the returned object.)</param>
	/// <param name="cancellation">Cancellation token for the request; note this cannot
	/// cancel forwarding once it has started; use the returned disposable do do that.</param>
	/// <returns>A disposable object that when disposed will cancel forwarding the port, or
	/// null if the request was rejected by the remote side, possibly because the remote port
	/// was already in use.</returns>
	/// <remarks>
	/// Listen to the <see cref="RemotePortStreamer.StreamOpened" /> event to receive streams.
	/// </remarks>
	public static async Task<RemotePortStreamer?> StreamFromRemotePortAsync(
		this SshSession session,
		IPAddress remoteIPAddress,
		int remotePort,
		CancellationToken cancellation = default)
	{
		var pfs = GetPortForwardingService(session);
		return await pfs.StreamFromRemotePortAsync(remoteIPAddress, remotePort, cancellation)
			.ConfigureAwait(false);
	}

	/// <summary>
	/// Opens a stream for an SSH channel of type 'direct-tcpip' that is relayed to remote port,
	/// regardless of whether the remote side has explicitly forwarded that port.
	/// </summary>
	/// <param name="session">SSH session that initiates the forwarding.</param>
	/// <param name="remoteHost">The destination hostname or IP address for the forwarded
	/// stream, to be resolved on the remote side. WARNING: Avoid using the hostname
	/// `localhost` as the destination host; use `127.0.0.1` or `::1` instead. OpenSSH does not
	/// recognize `localhost` as a valid destination host, and it can be slower anyway due to
	/// a bug in .NET Core: https://github.com/dotnet/runtime/issues/31085 </param>
	/// <param name="remotePort">The destination port for the forwarded stream.
	/// (Must not be 0.)</param>
	/// <param name="cancellation">Cancellation token for the request; note this cannot
	/// cancel streaming once it has started; dipose the returned stream for that.</param>
	/// <returns>A stream that is relayed to the remote port.</returns>
	/// <exception cref="SshChannelException">The streaming channel could not be opened,
	/// either because it was rejected by the remote side, or the remote connection failed.
	/// </exception>
	public static async Task<SshStream> StreamToRemotePortAsync(
		this SshSession session,
		string remoteHost,
		int remotePort,
		CancellationToken cancellation = default)
	{
		var pfs = GetPortForwardingService(session);
		return await pfs.StreamToRemotePortAsync(remoteHost, remotePort, cancellation)
			.ConfigureAwait(false);
	}

	/// <summary>
	/// Opens a stream for an SSH channel of type 'forwarded-tcpip' that is relayed to a remote
	/// port. The port must have been explicitly forwarded by the remote side.
	/// </summary>
	/// <param name="session">SSH session that initiates the forwarding.</param>
	/// <param name="forwardedPort">Remote port number that was forwarded.</param>
	/// <param name="cancellation">Cancellation token for the request; note this cannot
	/// cancel streaming once it has started; dipose the returned stream for that.</param>
	/// <returns>A stream that is relayed to the remote forwarded port.</returns>
	/// <exception cref="InvalidOperationException">The requested port is not (yet)
	/// forwarded.</exception>
	/// <exception cref="SshChannelException">The streaming channel could not be opened,
	/// either because it was rejected by the remote side, or the remote connection failed.
	/// </exception>
	/// <remarks>
	/// It may be necessary to call <see cref="WaitForForwardedPortAsync" /> before this method
	/// to ensure the port is ready for connections. Attempting to connect before the other side
	/// has forwarded the port may result in an <see cref="InvalidOperationException" />.
	/// </remarks>
	public static async Task<SshStream> ConnectToForwardedPortAsync(
		this SshSession session,
		int forwardedPort,
		CancellationToken cancellation = default)
	{
		var pfs = GetPortForwardingService(session);
		return await pfs.ConnectToForwardedPortAsync(forwardedPort, cancellation)
			.ConfigureAwait(false);
	}

	/// <summary>
	/// Waits asynchronously for the remote side to forward an expected port number.
	/// </summary>
	/// <param name="session">SSH session that initiates the forwarding.</param>
	/// <param name="forwardedPort">Remote port number that is expected to be forwarded.</param>
	/// <param name="cancellation">Token that can be used to cancel waiting.</param>
	/// <returns>A task that completes when the expected port number has been forwarded.</returns>
	/// <exception cref="ObjectDisposedException">The session was closed while waiting.</exception>
	/// <remarks>
	/// A common pattern for some applications may be to call this method just before
	/// <see cref="ConnectToForwardedPortAsync" />.
	/// </remarks>
	public static async Task WaitForForwardedPortAsync(
		this SshSession session,
		int forwardedPort,
		CancellationToken cancellation = default)
	{
		var pfs = GetPortForwardingService(session);
		await pfs.WaitForForwardedPortAsync(forwardedPort, cancellation)
			.ConfigureAwait(false);
	}

	private static PortForwardingService GetPortForwardingService(SshSession? session)
	{
		if (session == null) throw new ArgumentNullException(nameof(session));
		try
		{
			return session.ActivateService<PortForwardingService>();
		}
		catch (KeyNotFoundException ex)
		{
			throw new SshChannelException(
				"The port-forwarding service is not configured for this session.", ex);
		}
	}
}
