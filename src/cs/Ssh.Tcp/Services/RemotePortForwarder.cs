// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Receives SSH channels forwarded from a remote port and forwards them on to a local port.
/// </summary>
public class RemotePortForwarder : RemotePortConnector
{
	private readonly PortForwardingService pfs;

	internal RemotePortForwarder(
		PortForwardingService pfs,
		SshSession session,
		IPAddress remoteIPAddress,
		int remotePort,
		string localHost,
		int localPort)
		: base(session, remoteIPAddress, remotePort)
	{
		this.pfs = pfs ?? throw new ArgumentNullException(nameof(pfs));
		LocalHost = localHost;
		LocalPort = localPort;
	}

	/// <summary>
	/// Forwarding target host. Typically the loopback address ("127.0.0.1" or "::1") but
	/// may also be another hostname or IP address to be resolved locally.
	/// </summary>
	public string LocalHost { get; }

	/// <summary>
	/// Forwarding target port.
	/// </summary>
	public int LocalPort { get; }

	internal async override Task OnChannelOpeningAsync(
		SshChannelOpeningEventArgs request,
		CancellationToken cancellation)
	{
		await ForwardChannelAsync(
			this.pfs,
			request,
			LocalHost,
			LocalPort,
			RemotePort,
			Session.Trace,
			cancellation).ConfigureAwait(false);
	}

	internal static async Task ForwardChannelAsync(
		PortForwardingService pfs,
		SshChannelOpeningEventArgs request,
		string localHost,
		int localPort,
		int? remotePort,
		TraceSource trace,
		CancellationToken cancellation)
	{
		var channel = request.Channel;

		// The ChannelForwarder takes ownership of the TcpClient; it will be disposed
		// when the PortForwardingService is disposed. And the channel will be disposed when the
		// connection ends, so the SshStream does not need to be disposed separately.
#pragma warning disable CA2000 // Dispose objects before losing scope
		var tcpClient = new TcpClient();

		// The event handler may return a transformed channel stream.
		var forwardedStream = await pfs.OnForwardedPortConnectingAsync(
			remotePort ?? localPort, isIncoming: true, new SshStream(channel), cancellation)
			.ConfigureAwait(false);
#pragma warning restore CA2000 // Dispose objects before losing scope

		if (forwardedStream == null)
		{
			// The event handler rejected the connection.
			request.FailureReason = SshChannelOpenFailureReason.ConnectFailed;
			return;
		}

		using var cancellationRegistration = cancellation.CanBeCanceled ?
			cancellation.Register(tcpClient.Dispose) : default;

		try
		{
#if NET5_0 || NET6_0
			await tcpClient.ConnectAsync(localHost, localPort, cancellation)
#else
			await tcpClient.ConnectAsync(localHost, localPort)
#endif
					.ConfigureAwait(false);
		}
		catch (ObjectDisposedException) when (cancellation.IsCancellationRequested)
		{
			request.FailureReason = SshChannelOpenFailureReason.ConnectFailed;
			request.FailureDescription = "Session closed.";
			cancellation.ThrowIfCancellationRequested();
			throw;
		}
		catch (SocketException sockex)
		{
			var traceErrorMessage = $"{nameof(PortForwardingService)} forwarded channel " +
				$"#{channel.ChannelId} connection to {localHost}:{localPort} failed: {sockex.Message}";
			trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.PortForwardConnectionFailed,
				traceErrorMessage);
			tcpClient.Dispose();
			request.FailureReason = SshChannelOpenFailureReason.ConnectFailed;
			request.FailureDescription = sockex.Message;
			return;
		}

		tcpClient.Client.ConfigureSocketOptionsForSsh();

		StreamForwarder streamForwarder;
		try
		{
			// The PortForwardingService takes ownership of the StreamForwarder; it will be disposed
			// when the PortForwardingService is disposed.
#pragma warning disable CA2000 // Dispose objects before losing scope
			streamForwarder = new StreamForwarder(
				tcpClient.GetStream(), forwardedStream, channel.Trace);
#pragma warning restore CA2000 // Dispose objects before losing scope
		}
		catch (ObjectDisposedException ex)
		{
			// The TCP connection was closed immediately after it was opened. Close the channel.
			await channel.CloseAsync(cancellation).ConfigureAwait(false);
			request.FailureReason = SshChannelOpenFailureReason.ConnectFailed;
			request.FailureDescription = ex.Message;
			return;
		}

		var traceMessage = $"{nameof(PortForwardingService)} forwarded channel " +
			$"#{channel.ChannelId} connection to {localHost}:{localPort}.";
		trace.TraceEvent(
			TraceEventType.Verbose,
			SshTraceEventIds.PortForwardConnectionOpened,
			traceMessage);
		pfs.AddStreamForwarder(streamForwarder);
	}
}
