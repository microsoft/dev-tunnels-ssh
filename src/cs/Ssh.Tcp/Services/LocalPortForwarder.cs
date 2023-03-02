// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Services;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Listens on a local port and forwards incoming connections as SSH channels.
/// </summary>
public class LocalPortForwarder : SshService
{
	private readonly PortForwardingService pfs;
	private readonly string channelType;
	private TcpListener? listener;
	private TcpListener? listener2;
	private readonly CancellationTokenSource disposeCancellationSource;

	internal LocalPortForwarder(
		PortForwardingService pfs,
		SshSession session,
		string channelType,
		IPAddress localIPAddress,
		int localPort,
		string? remoteHost = null,
		int? remotePort = null)
		: base(session)
	{
		this.pfs = pfs ?? throw new ArgumentNullException(nameof(pfs));
		this.channelType = channelType ?? throw new ArgumentNullException(nameof(channelType));
		LocalIPAddress = localIPAddress;
		LocalPort = localPort;
		RemoteHost = remoteHost;

		// The remote port defaults to the same as the local port, if the remote port
		// was unspecified and a specific (nonzero) local port was specified. Whether
		// or not a specific local port was specified, the local port may be changed
		// by the TCP listener factory. In that case the remote port does not change.
		RemotePort = remotePort ?? (localPort != 0 ? localPort : null);

		this.disposeCancellationSource = new CancellationTokenSource();
	}

	/// <summary>
	/// IP address of the local network interface the forwarder is listening on.
	/// </summary>
	public IPAddress LocalIPAddress { get; }

	/// <summary>
	/// Local port that the forwarder is listening on.
	/// </summary>
	public int LocalPort { get; private set; }

	/// <summary>
	/// Remote forwarding target host, or null if this forwarding was requested
	/// by the remote side (without specifying the remote target).
	/// </summary>
	public string? RemoteHost { get; }

	/// <summary>
	/// Remote forwarding target port, or null if this forwarding was requested
	/// by the remote side (without specifying the remote target).
	/// </summary>
	public int? RemotePort { get; }

	internal async Task StartForwardingAsync(CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		var listenAddress = LocalIPAddress;
		try
		{
			var trace = this.pfs.Session.Trace;
			this.listener = await this.pfs.TcpListenerFactory.CreateTcpListenerAsync(
				listenAddress, LocalPort, trace, cancellation)
				.ConfigureAwait(false);

			LocalPort = ((IPEndPoint)this.listener.LocalEndpoint).Port;

			// The SSH protocol specifies that "localhost" or "" (any) should be dual-mode.
			// So 2 TCP listener instances are required in those cases.
			if (Socket.OSSupportsIPv6 &&
				(LocalIPAddress.Equals(IPAddress.Loopback) ||
				LocalIPAddress.Equals(IPAddress.Any)))
			{
				// Call the factory again to create another listener, but this time with the
				// corresponding IPv6 local address, and not allowing a port change.
				listenAddress = LocalIPAddress.Equals(IPAddress.Any) ?
					IPAddress.IPv6Any : IPAddress.IPv6Loopback;
				try
				{
					this.listener2 = await this.pfs.TcpListenerFactory.CreateTcpListenerAsync(
						listenAddress, LocalPort, trace, cancellation)
						.ConfigureAwait(false);
				}
				catch (SocketException sockex)
				when (sockex.SocketErrorCode == SocketError.AddressNotAvailable)
				{
					// The OS may support IPv6 while there actually no network interfaces
					// with an IPv6 address. Treat this the same as if IPv6 is unsupported.
					var message = sockex.Message;
					Session.Trace.TraceEvent(
						TraceEventType.Warning,
						SshTraceEventIds.PortForwardServerListening,
						$"{nameof(PortForwardingService)} failed to listen on {listenAddress}:{LocalPort}: {message}");

					// Do not rethrow, just skip IPv6 in this case.
				}
			}
		}
		catch (SocketException sockex)
		{
			var message = sockex.Message;
			Session.Trace.TraceEvent(
				TraceEventType.Error,
				SshTraceEventIds.PortForwardServerListenFailed,
				$"{nameof(PortForwardingService)} failed to listen on {listenAddress}:{LocalPort}: {message}");
			this.listener?.Stop();
			throw;
		}

		AcceptConnections();

		Session.Trace.TraceEvent(
			TraceEventType.Information,
			SshTraceEventIds.PortForwardServerListening,
			$"{nameof(PortForwardingService)} listening on {LocalIPAddress}:{LocalPort}.");
		if (this.listener2 != null)
		{
			Session.Trace.TraceEvent(
				TraceEventType.Information,
				SshTraceEventIds.PortForwardServerListening,
				$"{nameof(PortForwardingService)} also listening on {listenAddress}:{LocalPort}.");
		}
	}

	private async void AcceptConnections()
	{
		try
		{
			var acceptTasks = new Task<TcpClient?>[this.listener2 == null ? 1 : 2];
			acceptTasks[0] = this.AcceptConnectionAsync(this.listener);
			if (this.listener2 != null)
			{
				acceptTasks[1] = this.AcceptConnectionAsync(this.listener2);
			}

			var cancellation = this.disposeCancellationSource.Token;
			while (true)
			{
				var acceptedTask = await Task.WhenAny(acceptTasks).ConfigureAwait(false);
				var tcpClient = await acceptedTask.ConfigureAwait(false);
				if (tcpClient == null)
				{
					break;
				}

				if (acceptedTask == acceptTasks[0])
				{
					acceptTasks[0] = this.AcceptConnectionAsync(this.listener);
				}
				else
				{
					acceptTasks[1] = this.AcceptConnectionAsync(this.listener2);
				}

				SshChannel? channel;
				var originatorEndPoint = tcpClient.Client.RemoteEndPoint as IPEndPoint;
				try
				{
					channel = await this.pfs.OpenChannelAsync(
						Session,
						this.channelType,
						originatorEndPoint,
						RemoteHost ?? IPAddressConversions.ToString(LocalIPAddress),
						RemotePort ?? LocalPort,
						cancellation).ConfigureAwait(false);
				}
				catch (SshChannelException)
				{
					// The channel could not be opened. (The exception was already traced.)
					tcpClient.Client.Abort();
					continue;
				}
				catch (SshConnectionException)
				{
					// The session was disconnected.
					tcpClient.Client.Abort();
					break;
				}
				catch (ObjectDisposedException)
				{
					// The session was disposed.
					tcpClient.Client.Abort();
					break;
				}
				catch (OperationCanceledException)
				when (this.disposeCancellationSource.IsCancellationRequested)
				{
					// The port-forwarder was disposed.
					tcpClient.Client.Abort();
					break;
				}

				// The PortForwardingService takes ownership of the ChannelForwarder.
#pragma warning disable CA2000 // Dispose objects before losing scope
				var channelForwarder = new ChannelForwarder(this.pfs, channel, tcpClient);
#pragma warning restore CA2000 // Dispose objects before losing scope
				this.pfs.AddChannelForwarder(channelForwarder);
			}
		}
		catch (Exception ex)
		{
			// Catch all exceptions in this async void method.
			Session.Trace.TraceEvent(
				TraceEventType.Error,
				SshTraceEventIds.UnknownError,
				$"{nameof(PortForwardingService)} unexpected error accepting connections: {ex}");
		}
	}

	private async Task<TcpClient?> AcceptConnectionAsync(TcpListener? listener)
	{
		if (listener == null)
		{
			return null;
		}

		TcpClient tcpClient;
		try
		{
			tcpClient = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
		}
		catch (SocketException)
		when (this.disposeCancellationSource.IsCancellationRequested)
		{
			// The listener was disposed.
			return null;
		}
		catch (ObjectDisposedException)
		when (this.disposeCancellationSource.IsCancellationRequested)
		{
			// The listener was disposed.
			return null;
		}

		tcpClient.Client.ConfigureSocketOptionsForSsh();

		var originatorEndPoint = tcpClient.Client.RemoteEndPoint as IPEndPoint;
		var originatorAddress = originatorEndPoint?.Address?.ToString() ?? "<unknown>";
		Session.Trace.TraceEvent(
			TraceEventType.Verbose,
			SshTraceEventIds.PortForwardConnectionAccepted,
			$"{nameof(PortForwardingService)} accepted connection from: {originatorAddress}");
		return tcpClient;
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			try
			{
				this.disposeCancellationSource.Cancel();
			}
			catch (ObjectDisposedException) { }

			try
			{
				// Note stopping the listener does NOT disconnect any already-accepted sockets.
				this.listener?.Stop();
				this.listener2?.Stop();
			}
			catch (ObjectDisposedException) { }

			this.disposeCancellationSource.Dispose();
		}

		base.Dispose(disposing);
	}
}
