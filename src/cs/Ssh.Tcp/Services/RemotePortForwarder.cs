// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
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

		// The StreamForwarder takes ownership of the TcpClient; it will be disposed
		// when the PortForwardingService is disposed. And the channel will be disposed when the
		// connection ends, so the SshStream does not need to be disposed separately.
#pragma warning disable CA2000 // Dispose objects before losing scope

		TcpClient tcpClient;
		TcpClient? tcpClient2 = null;
		if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			if (IPAddress.TryParse(localHost, out var localAddress))
			{
				tcpClient = new TcpClient(localAddress.AddressFamily);
			}
			else
			{
				// Work around a bug in .NET on Windows: https://github.com/dotnet/runtime/issues/31085
				// If a hostname such as "localhost" was specified (rather than an IP address), first
				// try to connect to the hostname with IPv6, then fallback to IPv4.
				tcpClient = new TcpClient(AddressFamily.InterNetworkV6);
				tcpClient2 = new TcpClient(AddressFamily.InterNetwork);
			}
		}
		else
		{
			tcpClient = new TcpClient();
		}

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
			cancellation.Register(() =>
			{
				tcpClient.Dispose();
				tcpClient2?.Dispose();
			}) : default;

		try
		{
			tcpClient = await ConnectTcpClientAsync(
				tcpClient, tcpClient2, localHost, localPort, cancellation).ConfigureAwait(false);
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
			var traceErrorMessage = $"{nameof(PortForwardingService)} connection " +
				$" to {localHost}:{localPort} failed: {sockex.Message}";
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
			// The TCP connection was closed immediately after it was opened.
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

	/// <summary>
	/// Connects a TCP client or fallback TCP client, and returns the connected client instance.
	/// </summary>
	/// <remarks>
	/// While .NET can automatically attempt to connect to multiple resolved IP addresses,
	/// it is very slow to do so. See https://github.com/dotnet/runtime/issues/31085.
	///
	/// This method is a basic implementation of the "Happy Eyeballs" algorithm described in
	/// https://datatracker.ietf.org/doc/html/rfc8305. Effectively this enables fast connections
	/// to either 127.0.0.1 or ::1 when 'localhost' is specified as the hostname.
	/// </remarks>
	private static async Task<TcpClient> ConnectTcpClientAsync(
		TcpClient tcpClient,
		TcpClient? tcpClient2,
		string host,
		int port,
#pragma warning disable CA1801 // Review unused parameters
		CancellationToken cancellation)
#pragma warning restore CA1801 // Review unused parameters
	{
#if NET5_0 || NET6_0
		var connectTask = tcpClient.ConnectAsync(host, port, cancellation);
#else
		var connectTask = tcpClient.ConnectAsync(host, port);
#endif

		if (tcpClient2 == null)
		{
			// There is no fallback TCP client. Just await the result of the first connection attempt.
			await connectTask.ConfigureAwait(false);
			return tcpClient;
		}

		// Try to connect with the first TCP client. But if it fails or takes longer than
		// the delay time then try the second one and return whichever one connects first.

		// Use a short delay when connecting to localhost. Otherwise use the recommended delay
		// according to https://datatracker.ietf.org/doc/html/rfc8305#section-5
		var connectionAttemptDelay = (host == "localhost" ? 10 : 250);

		// Note Task.WhenAny() never throws; it returns whichever task completed or faulted first.
		var completedOrFaultedTask = await Task.WhenAny(
			connectTask, Task.Delay(connectionAttemptDelay, cancellation)).ConfigureAwait(false);
		if (completedOrFaultedTask == connectTask)
		{
			if (!completedOrFaultedTask.IsFaulted)
			{
				// The first connection attempt succeeded before the attempt delay elapsed.
				// There's no need to try the second TCP client.
				tcpClient2.Dispose();
				return tcpClient;
			}
			else
			{
				// The first connection attempt failed before the attempt delay elapsed.
				// Just try the second TCP client, which may or may not succeed.
				tcpClient.Dispose();
				return await ConnectTcpClientAsync(tcpClient2, null, host, port, cancellation)
					.ConfigureAwait(false);
			}
		}
		else
		{
			cancellation.ThrowIfCancellationRequested();

			// The first connection attempt did not succeed or fail before the connection delay
			// elapsed. Start the fallback connection attempt, and return whichever TCP client
			// succeeds first (if any).
#if NET5_0 || NET6_0
			var connectTask2 = tcpClient2.ConnectAsync(host, port, cancellation);
#else
			var connectTask2 = tcpClient2.ConnectAsync(host, port);
#endif

			completedOrFaultedTask = await Task.WhenAny(connectTask, connectTask2)
				.ConfigureAwait(false);
			if (completedOrFaultedTask == connectTask)
			{
				if (!completedOrFaultedTask.IsFaulted)
				{
					// The first connection attempt succeeded before the second one.
					tcpClient2.Dispose();
					return tcpClient;
				}
				else
				{
					// The first connection attempt failed (after the attempt delay elapsed).
					// Just wait for the second one, which may or may not succeed.
					tcpClient.Dispose();
					await connectTask2.ConfigureAwait(false);
					return tcpClient2;
				}
			}
			else
			{
				if (!completedOrFaultedTask.IsFaulted)
				{
					// The second connection attempt succeeded before the first one.
					tcpClient.Dispose();
					return tcpClient2;
				}
				else
				{
					// The second connection attempt failed.
					// Just wait for the first one, which may or may not succeed.
					tcpClient2.Dispose();
					await connectTask.ConfigureAwait(false);
					return tcpClient;
				}
			}
		}
	}
}
