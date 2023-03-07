// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Services;
using Microsoft.DevTunnels.Ssh.Tcp.Events;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Implements the standard SSH port-forwarding protocol.
/// </summary>
[ServiceActivation(SessionRequest = PortForwardRequestType)]
[ServiceActivation(SessionRequest = CancelPortForwardRequestType)]
[ServiceActivation(ChannelType = PortForwardChannelType)]
[ServiceActivation(ChannelType = ReversePortForwardChannelType)]
public class PortForwardingService : SshService
{
	internal const string PortForwardRequestType = "tcpip-forward";
	internal const string CancelPortForwardRequestType = "cancel-tcpip-forward";
	internal const string PortForwardChannelType = "forwarded-tcpip";
	internal const string ReversePortForwardChannelType = "direct-tcpip";

	private bool disposed;

	/// <summary>
	/// Maps from FORWARDED port number to the object that manages listening for incoming
	/// connections for that port and forwarding them through the session.
	/// </summary>
	/// <remarks>
	/// Note the actual local source port number used may be different from the forwarded port
	/// number if the local TCP listener factory chose a different port. The forwarded port number
	/// is used to identify the port in any messages exchanged between client and server.
	/// </remarks>
	private readonly IDictionary<int, LocalPortForwarder> localForwarders =
		new Dictionary<int, LocalPortForwarder>();

	/// <summary>
	/// Maps from FORWARDED port numbers to the object that manages relaying forwarded connections
	/// from the session to a local port.
	/// </summary>
	/// <remarks>
	/// Note the actual local destination port number used may be different from the forwarded port
	/// number. The forwarded port number is used to identify the port in any messages exchanged
	/// between client and server.
	/// </remarks>
	private readonly IDictionary<int, RemotePortConnector> remoteConnectors =
		new Dictionary<int, RemotePortConnector>();

	/// <summary>
	/// Collection of objects that manage forwarding traffic on individual channels.
	/// </summary>
	/// <remarks>
	/// There may be 0 to multiple channel forawarders per forwarded port.
	/// </remarks>
	private readonly ICollection<ChannelForwarder> channelForwarders = new List<ChannelForwarder>();

	public PortForwardingService(SshSession session)
		: base(session)
	{
	}

	/// <summary>
	/// Gets or sets a value that controls whether the port-forwarding service listens on
	/// local TCP sockets to accept connections for ports that are forwarded from the remote side.
	/// </summary>
	/// <remarks>
	/// The default is true.
	/// <para/>
	/// This property is typically initialized before connecting a session (if not keeping the
	/// default). It may be changed at any time while the session is connected, and the new value
	/// will affect any newly forwarded ports after that, but not previously-forwarded ports.
	/// <para/>
	/// Regardless of whether this is enabled, connections to forwarded ports can be made using
	/// <see cref="ConnectToForwardedPortAsync" />.
	/// </remarks>
	public bool AcceptLocalConnectionsForForwardedPorts { get; set; } = true;

	/// <summary>
	/// Gets or sets a value that controls whether the port-forwarding service accepts
	/// 'direct-tcpip' channel open requests and forwards the channel connections to the local port.
	/// </summary>
	/// <remarks>
	/// The default is true.
	/// <para/>
	/// This property is typically initialized before connecting a session (if not keeping the
	/// default). It may be changed at any time while the session is connected, and the new value
	/// will affect any new connection requests after that, but not previously-forwarded ports.
	/// <para/>
	/// Regardless of whether this is enabled, the remote side can open 'forwarded-tcpip' channels
	/// to connect to ports that were explicitly forwarded by this side.
	/// </remarks>
	public bool AcceptRemoteConnectionsForNonForwardedPorts { get; set; } = true;

	/// <summary>
	/// Gets the collection of ports that are currently being forwarded from the remote side
	/// to the local side.
	/// </summary>
	/// <remarks>
	/// Ports are added to this collection when <see cref="ForwardFromRemotePortAsync" /> or
	/// <see cref="StreamFromRemotePortAsync" /> is called (and the other side accepts the
	/// 'tcpip-forward' request), and then are removed when the <see cref="RemotePortForwarder" />
	/// is disposed (which also sends a 'cancel-tcpip-forward' message).
	/// <para/>
	/// Each forwarded port may have 0 or more active connections (channels).
	/// <para/>
	/// The collection does not include direct connections initiated via
	/// <see cref="ForwardToRemotePortAsync" /> or <see cref="StreamToRemotePortAsync" />.
	/// <para/>
	/// Local forwarded ports may or may not have local TCP listeners automatically set up,
	/// depending on the value of <see cref="AcceptLocalConnectionsForForwardedPorts" />.
	/// </remarks>
	public ForwardedPortsCollection LocalForwardedPorts { get; } = new ForwardedPortsCollection();

	/// <summary>
	/// Gets the collection of ports that are currently being forwarded from the local side
	/// to the remote side.
	/// </summary>
	/// <remarks>
	/// Ports are added to this collection when the port-forwarding service handles a
	/// 'tcpip-forward' request message, and removed when it receives a 'cancel-tcpip-forward'
	/// request message.
	/// <para/>
	/// Each forwarded port may have 0 or more active connections (channels).
	/// <para/>
	/// The collection does not include direct connections initiated via
	/// <see cref="ForwardToRemotePortAsync" /> or <see cref="StreamToRemotePortAsync" />.
	/// </remarks>
	public ForwardedPortsCollection RemoteForwardedPorts { get; } = new ForwardedPortsCollection();

	/// <summary>
	/// Gets or sets a factory for creating TCP listeners.
	/// </summary>
	/// <remarks>
	/// Applications may override this factory to provide custom logic for selecting
	/// local port numbers to listen on for port-forwarding.
	/// <para/>
	/// This factory is not used when <see cref="AcceptLocalConnectionsForForwardedPorts" /> is
	/// set to false.
	/// </remarks>
	public ITcpListenerFactory TcpListenerFactory { get; set; }
		= new DefaultTcpListenerFactory();

	/// <summary>
	/// Sends a request to the remote side to listen on a port and forward incoming connections
	/// as SSH channels of type 'forwarded-tcpip', which will then be relayed to a specified
	/// local port.
	/// </summary>
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
	/// <param name="localPort">The destination port for forwarded connections.</param>
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
	public async Task<RemotePortForwarder?> ForwardFromRemotePortAsync(
		IPAddress remoteIPAddress,
		int remotePort,
		string localHost,
		int localPort,
		CancellationToken cancellation)
	{
		if (remoteIPAddress == null) throw new ArgumentNullException(nameof(remoteIPAddress));
		if (remotePort < 0) throw new ArgumentOutOfRangeException(nameof(remotePort));
		if (string.IsNullOrEmpty(localHost)) throw new ArgumentNullException(nameof(localHost));
		if (localPort <= 0) throw new ArgumentOutOfRangeException(nameof(localPort));

		if (LocalForwardedPorts.Any((p) => p.LocalPort == localPort))
		{
			throw new InvalidOperationException($"Local port {localPort} is already forwarded.");
		}
		else if (remotePort > 0 && LocalForwardedPorts.Any((p) => p.RemotePort == remotePort))
		{
			throw new InvalidOperationException($"Remote port {remotePort} is already forwarded.");
		}

		var forwarder = new RemotePortForwarder(
			this,
			Session,
			remoteIPAddress,
			remotePort,
			localHost,
			localPort);

		if (!(await forwarder.RequestAsync(cancellation).ConfigureAwait(false)))
		{
			forwarder.Dispose();
			return null;
		}

		remotePort = forwarder.RemotePort;
		var remoteEndPoint = new IPEndPoint(remoteIPAddress, remotePort);
		lock (this.remoteConnectors)
		{
			// The remote port is the port sent in the message to the other side,
			// so the connector is indexed on that port number, rather than the local port.
			this.remoteConnectors.Add(remotePort, forwarder);
		}

		var forwardedPort = new ForwardedPort(localPort, remotePort, isRemote: false);
		LocalForwardedPorts.AddPort(forwardedPort);
		forwarder.Disposed += (_, _) =>
		{
			LocalForwardedPorts.RemovePort(forwardedPort);
			lock (this.remoteConnectors)
			{
				this.remoteConnectors.Remove(remotePort);
			}
		};

		return forwarder;
	}

	/// <summary>
	/// Starts listening on a local port and forwards incoming connections as SSH channels
	/// of type 'direct-tcpip', which will then be relayed to a specified remote port,
	/// regardless of whether the remote side has explicitly forwarded that port.
	/// </summary>
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
	public async Task<LocalPortForwarder> ForwardToRemotePortAsync(
		IPAddress localIPAddress,
		int localPort,
		string remoteHost,
		int remotePort,
		CancellationToken cancellation)
	{
		if (localIPAddress == null) throw new ArgumentNullException(nameof(localIPAddress));
		if (localPort < 0) throw new ArgumentOutOfRangeException(nameof(localPort));
		if (string.IsNullOrEmpty(remoteHost)) throw new ArgumentNullException(nameof(remoteHost));
		if (remotePort <= 0) throw new ArgumentOutOfRangeException(nameof(remotePort));

		lock (this.localForwarders)
		{
			if (this.localForwarders.ContainsKey(remotePort))
			{
				throw new InvalidOperationException($"Port {remotePort} is already forwarded.");
			}
		}

		var forwarder = new LocalPortForwarder(
			this,
			Session,
			ReversePortForwardChannelType,
			localIPAddress,
			localPort,
			remoteHost,
			remotePort);
		await forwarder.StartForwardingAsync(cancellation).ConfigureAwait(false);

		// The remote port is the port sent in the message to the other side,
		// so the forwarder is indexed on that port number, rather than the local port.
		lock (this.localForwarders)
		{
			this.localForwarders.Add(remotePort, forwarder);
		}

		forwarder.Disposed += (_, _) =>
		{
			lock (this.localForwarders)
			{
				this.localForwarders.Remove(remotePort);
			}
		};
		return forwarder;
	}

	/// <summary>
	/// Sends a request to the remote side to listen on a port and forward incoming connections
	/// as SSH channels of type 'forwarded-tcpip', which will then be relayed as local streams.
	/// </summary>
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
	public async Task<RemotePortStreamer?> StreamFromRemotePortAsync(
		IPAddress remoteIPAddress,
		int remotePort,
		CancellationToken cancellation)
	{
		if (remoteIPAddress == null) throw new ArgumentNullException(nameof(remoteIPAddress));
		if (remotePort < 0) throw new ArgumentOutOfRangeException(nameof(remotePort));

		var streamer = new RemotePortStreamer(Session, remoteIPAddress, remotePort);

		if (!(await streamer.RequestAsync(cancellation).ConfigureAwait(false)))
		{
			streamer.Dispose();
			return null;
		}

		remotePort = streamer.RemotePort;
		var remoteEndPoint = new IPEndPoint(remoteIPAddress, remotePort);
		lock (this.remoteConnectors)
		{
			// The remote port is the port sent in the message to the other side,
			// so the connector is indexed on that port number. (There is no local port anyway.)
			this.remoteConnectors.Add(remotePort, streamer);
		}

		var forwardedPort = new ForwardedPort(localPort: null, remotePort, isRemote: false);
		LocalForwardedPorts.AddPort(forwardedPort);
		streamer.Disposed += (_, _) =>
		{
			LocalForwardedPorts.RemovePort(forwardedPort);
			lock (this.remoteConnectors)
			{
				this.remoteConnectors.Remove(remotePort);
			}
		};

		return streamer;
	}

	/// <summary>
	/// Opens a stream for an SSH channel of type 'direct-tcpip' that is relayed to remote port,
	/// regardless of whether the remote side has explicitly forwarded that port.
	/// </summary>
	/// <param name="remoteHost">The destination host for forwarded connections; typically
	/// "localhost" but may be a hostname to be resolved on the remote side.</param>
	/// <param name="remotePort">The destination port for forwarded connections.
	/// (Must not be 0.)</param>
	/// <param name="cancellation">Cancellation token for the request; note this cannot
	/// cancel streaming once it has started; dipose the returned stream for that.</param>
	/// <returns>A stream that is relayed to the remote port.</returns>
	/// <exception cref="SshChannelException">The streaming channel could not be opened,
	/// either because it was rejected by the remote side, or the remote connection failed.
	/// </exception>
	public async Task<SshStream> StreamToRemotePortAsync(
		string remoteHost,
		int remotePort,
		CancellationToken cancellation)
	{
		if (string.IsNullOrEmpty(remoteHost)) throw new ArgumentNullException(nameof(remoteHost));
		if (remotePort <= 0) throw new ArgumentOutOfRangeException(nameof(remotePort));

		var channel = await OpenChannelAsync(
			Session,
			ReversePortForwardChannelType,
			originatorEndPoint: null,
			remoteHost,
			remotePort,
			cancellation).ConfigureAwait(false);

		return new SshStream(channel);
	}

	/// <summary>
	/// Opens a stream for an SSH channel of type 'forwarded-tcpip' that is relayed to a remote
	/// port. The port must have been explicitly forwarded by the remote side.
	/// </summary>
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
	public async Task<SshStream> ConnectToForwardedPortAsync(
		int forwardedPort,
		CancellationToken cancellation)
	{
		if (forwardedPort <= 0) throw new ArgumentOutOfRangeException(nameof(forwardedPort));

		var channel = await OpenChannelAsync(
			Session,
			PortForwardChannelType,
			originatorEndPoint: null,
			host: IPAddress.Loopback.ToString(),
			forwardedPort,
			cancellation).ConfigureAwait(false);

		return new SshStream(channel);
	}

	/// <summary>
	/// Waits asynchronously for the remote side to forward an expected port number.
	/// </summary>
	/// <param name="forwardedPort">Remote port number that is expected to be forwarded.</param>
	/// <param name="cancellation">Token that can be used to cancel waiting.</param>
	/// <returns>A task that completes when the expected port number has been forwarded.</returns>
	/// <exception cref="ObjectDisposedException">The session was closed while waiting.</exception>
	/// <remarks>
	/// A common pattern for some applications may be to call this method just before
	/// <see cref="ConnectToForwardedPortAsync" />.
	/// </remarks>
	public async Task WaitForForwardedPortAsync(
		int forwardedPort,
		CancellationToken cancellation)
	{
		if (RemoteForwardedPorts.Any((p) => p.RemotePort == forwardedPort))
		{
			// It's already forwarded, so there's no need to wait.
			return;
		}

		var waitCompletion = new TaskCompletionSource<bool>(
			TaskCreationOptions.RunContinuationsAsynchronously);

		EventHandler<ForwardedPortEventArgs> portForwardedHandler = (_, e) =>
		{
			if (e.Port.RemotePort == forwardedPort)
			{
				waitCompletion.TrySetResult(true);
			}
		};
		EventHandler<SshSessionClosedEventArgs> sessionClosedHandler = (_, _) =>
		{
			waitCompletion.TrySetException(new ObjectDisposedException("The session was closed."));
		};

		CancellationTokenRegistration? cancellationRegistration = null;
		if (cancellation.CanBeCanceled)
		{
			cancellation.ThrowIfCancellationRequested();
			cancellationRegistration = cancellation.Register(() => waitCompletion.TrySetCanceled());
		}

		try
		{
			RemoteForwardedPorts.PortAdded += portForwardedHandler;
			Session.Closed += sessionClosedHandler;

			// Avoid a potential timing issue by checking again after setting up the event-handler.
			if (RemoteForwardedPorts.Any((p) => p.RemotePort == forwardedPort))
			{
				waitCompletion.TrySetResult(true);
			}

			await waitCompletion.Task.ConfigureAwait(false);
		}
		finally
		{
			RemoteForwardedPorts.PortAdded -= portForwardedHandler;
			Session.Closed -= sessionClosedHandler;
			cancellationRegistration?.Dispose();
		}
	}

	protected override async Task OnSessionRequestAsync(
		SshRequestEventArgs<SessionRequestMessage> request,
		CancellationToken cancellation)
	{
		if (request == null)
		{
			throw new ArgumentNullException(nameof(request));
		}
		else if (request.RequestType != PortForwardRequestType &&
			request.RequestType != CancelPortForwardRequestType)
		{
			throw new ArgumentException("Unexpected request type: " + request.RequestType);
		}

		var portForwardRequest = request.Request.ConvertTo<PortForwardRequestMessage>();

		SshMessage? response = null;
		int? localPort = null;
		var localIPAddress = IPAddressConversions.FromString(portForwardRequest.AddressToBind);
		if (localIPAddress == null)
		{
			var address = portForwardRequest.AddressToBind;
			Session.Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.PortForwardRequestInvalid,
				$"{nameof(PortForwardingService)} failed to parse address: {address}");
		}
		else if (request.RequestType == PortForwardRequestType && portForwardRequest.Port != 0 &&
			this.localForwarders.ContainsKey((int)portForwardRequest.Port))
		{
			string message = $"{nameof(PortForwardingService)} blocking attempt to re-forward " +
				$"already-forwarded port {portForwardRequest.Port}.";
			Session.Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.PortForwardRequestInvalid,
				message);
		}
		else
		{
			var args = new SshRequestEventArgs<SessionRequestMessage>(
				request.RequestType!, portForwardRequest, Session.Principal);
			await base.OnSessionRequestAsync(args, cancellation).ConfigureAwait(false);

			if (args.IsAuthorized)
			{
				if (request.RequestType == PortForwardRequestType)
				{
					try
					{
						localPort = await StartForwardingAsync(
							localIPAddress,
							(int)portForwardRequest.Port,
							cancellation)
							.ConfigureAwait(false);
					}
					catch (SocketException)
					{
						// The exception is already traced.
					}

					if (localPort != null)
					{
						// The chosen local port may be different from the requested port. Use the
						// requested port in the response, unless the request was for a random port.
						response = new PortForwardSuccessMessage
						{
							Port = portForwardRequest.Port == 0 ? (uint)localPort.Value :
								portForwardRequest.Port,
						};
					}
				}
				else if (request.RequestType == CancelPortForwardRequestType)
				{
					if (await CancelForwardingAsync((int)portForwardRequest.Port, cancellation)
						.ConfigureAwait(false))
					{
						response = new SessionRequestSuccessMessage();
					}
				}
			}
		}

		request.ResponseTask = Task.FromResult(response ?? new SessionRequestFailureMessage());

		if (response is PortForwardSuccessMessage portForwardResponse)
		{
			request.ResponseContinuation = (_) =>
			{
				// Add to the collection (and raise event) after sending the response,
				// to ensure event-handlers can immediately open a channel.
				var forwardedPort = new ForwardedPort(
					localPort: localPort ?? (int)portForwardResponse.Port,
					remotePort: (int)portForwardResponse.Port,
					isRemote: true);
				RemoteForwardedPorts.AddPort(forwardedPort);

				return Task.CompletedTask;
			};
		}
	}

	private async Task<int?> StartForwardingAsync(
		IPAddress localIPAddress,
		int remotePort,
		CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();

		if (AcceptLocalConnectionsForForwardedPorts)
		{
			// The local port is initially set to the remote port, but it may change
			// when starting forwarding, if there was a conflict.
			int localPort = remotePort;

			var forwarder = new LocalPortForwarder(
				this,
				Session,
				PortForwardChannelType,
				localIPAddress,
				localPort,
				remoteHost: null,
				remotePort == 0 ? null : remotePort);

			await forwarder.StartForwardingAsync(cancellation).ConfigureAwait(false);
			localPort = forwarder.LocalPort;
			if (remotePort == 0)
			{
				// The other side requested a random port. Reply with the chosen port number.
				remotePort = localPort;
			}

			// The remote port is the port referenced in exchanged messages,
			// so the forwarder is indexed on that port number, rather than the local port.
			lock (this.localForwarders)
			{
				if (localForwarders.ContainsKey(remotePort))
				{
					// The forwarder (TCP listener factory) chose a port that is already forwarded.
					// This can happen (though its' very unlikely) if a random port was requested.
					// Returning null here causes the forward request to be rejected.
					forwarder.Dispose();
					return null;
				}

				this.localForwarders.Add(remotePort, forwarder);
			}

			forwarder.Disposed += (_, _) =>
			{
				var forwardedPort = new ForwardedPort(localPort, remotePort, isRemote: true);
				RemoteForwardedPorts.RemovePort(forwardedPort);
				lock (this.localForwarders)
				{
					this.localForwarders.Remove(remotePort);
				}
			};

			return forwarder.LocalPort;
		}
		else if (remotePort != 0)
		{
			return remotePort;
		}
		else
		{
			return null;
		}
	}

	private Task<bool> CancelForwardingAsync(
		int forwardedPort,
		CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();

		LocalPortForwarder? forwarder;
		lock (this.localForwarders)
		{
			if (!this.localForwarders.TryGetValue(forwardedPort, out forwarder))
			{
				return Task.FromResult(false);
			}

			localForwarders.Remove(forwardedPort);
		}

		forwarder.Dispose();
		return Task.FromResult(true);
	}

	protected override async Task OnChannelOpeningAsync(
		SshChannelOpeningEventArgs request,
		CancellationToken cancellation)
	{
		if (request == null)
		{
			throw new ArgumentNullException(nameof(request));
		}

		string? channelType = request.Request.ChannelType;
		if (channelType != PortForwardChannelType && channelType != ReversePortForwardChannelType)
		{
			request.FailureReason = SshChannelOpenFailureReason.UnknownChannelType;
			return;
		}

		RemotePortConnector? remoteConnector = null;
		var portForwardMessage = request.Request as PortForwardChannelOpenMessage ??
			request.Request.ConvertTo<PortForwardChannelOpenMessage>();
		if (request.IsRemoteRequest)
		{
			if (channelType == PortForwardChannelType)
			{
				var remoteIPAddress = IPAddressConversions.FromString(portForwardMessage.Host);
				var remoteEndPoint = new IPEndPoint(remoteIPAddress, (int)portForwardMessage.Port);

				// There's a potential race condition at this point if the other side tried to
				// open a channel immediately after forwarding started. Poll for a short time
				// to give a chance for the remote connector to be added to the collection by
				// ForwardFromRemotePortAsync() or StreamFromRemotePortAsync().
				for (int i = 0; i < 20 && remoteConnector == null; i++)
				{
					lock (this.remoteConnectors)
					{
						this.remoteConnectors.TryGetValue(
							(int)portForwardMessage.Port, out remoteConnector);
					}

					if (remoteConnector == null)
					{
						await Task.Delay(10, cancellation).ConfigureAwait(false);
					}
				}

				if (remoteConnector == null)
				{
					var errorMessage = $"{nameof(PortForwardingService)} received forwarding " +
						$"channel for {remoteEndPoint} that was not requested.";
					Session.Trace.TraceEvent(
						TraceEventType.Warning,
						SshTraceEventIds.PortForwardChannelInvalid,
						errorMessage);
					request.FailureDescription = errorMessage;
					request.FailureReason = SshChannelOpenFailureReason.ConnectFailed;
					return;
				}
			}
			else if (!AcceptRemoteConnectionsForNonForwardedPorts)
			{
				var errorMessage = "The session has disabled connections to non-forwarded ports.";
				Session.Trace.TraceEvent(
					TraceEventType.Warning,
					SshTraceEventIds.PortForwardChannelOpenFailed,
					errorMessage);
				request.FailureDescription = errorMessage;
				request.FailureReason = SshChannelOpenFailureReason.AdministrativelyProhibited;
				return;
			}
		}

		var portForwardRequest = new SshChannelOpeningEventArgs(
			portForwardMessage, request.Channel, request.IsRemoteRequest);
		await base.OnChannelOpeningAsync(portForwardRequest, cancellation).ConfigureAwait(false);

		request.FailureReason = portForwardRequest.FailureReason;
		request.FailureDescription = portForwardRequest.FailureDescription;
		if (request.FailureReason != SshChannelOpenFailureReason.None || !request.IsRemoteRequest)
		{
			return;
		}

		if (remoteConnector != null)
		{
			// The forwarding was initiated by this session.
			await remoteConnector.OnChannelOpeningAsync(request, cancellation)
				.ConfigureAwait(false);
			var remoteForwarder = remoteConnector as RemotePortForwarder;
			var forwardedPort = new ForwardedPort(
				localPort: remoteForwarder?.LocalPort,
				remotePort: remoteForwarder?.RemotePort ?? (int)portForwardMessage.Port,
				isRemote: false);
			LocalForwardedPorts.AddChannel(forwardedPort, request.Channel);
		}
		else
		{
			// The forwarding was initiated by the remote session.
			await RemotePortForwarder.ForwardChannelAsync(
				this,
				request,
				portForwardMessage.Host,
				(int)portForwardMessage.Port,
				Session.Trace,
				cancellation).ConfigureAwait(false);
		}
	}

	internal async Task<SshChannel> OpenChannelAsync(
		SshSession session,
		string channelType,
		IPEndPoint? originatorEndPoint,
		string host,
		int port,
		CancellationToken cancellation)
	{
		ForwardedPort? forwardedPort = null;
		if (channelType == PortForwardChannelType)
		{
			forwardedPort = RemoteForwardedPorts.FirstOrDefault(
				(p) => p.RemotePort == port || (p.RemotePort == null && p.LocalPort == port));
			if (forwardedPort is null)
			{
				throw new InvalidOperationException($"Port {port} is not being forwarded.");
			}
		}

		var originatorAddress = originatorEndPoint?.Address?.ToString() ?? string.Empty;
		var openMessage = new PortForwardChannelOpenMessage
		{
			ChannelType = channelType,
			OriginatorIPAddress = originatorAddress,
			OriginatorPort = (uint)(originatorEndPoint?.Port ?? 0),
			Host = host,
			Port = (uint)port,
		};

		var trace = this.Session.Trace;

		SshChannel channel;
		try
		{
			channel = await session.OpenChannelAsync(openMessage, null, cancellation)
				.ConfigureAwait(false);
			var traceMessage = $"{nameof(PortForwardingService)} opened {channelType} channel " +
				$"#{channel.ChannelId} for {host}:{port}.";
			trace.TraceEvent(
				TraceEventType.Information,
				SshTraceEventIds.PortForwardChannelOpened,
				traceMessage);
		}
		catch (Exception ex)
		{
			var traceErrorMessage = $"{nameof(PortForwardingService)} failed to open " +
				$"{channelType} channel for {host}:{port}: {ex.Message}";
			trace.TraceEvent(
				TraceEventType.Error,
				SshTraceEventIds.PortForwardChannelOpenFailed,
				traceErrorMessage);
			throw;
		}

		if (channelType == PortForwardChannelType)
		{
			RemoteForwardedPorts.AddChannel(forwardedPort!, channel);
		}

		return channel;
	}

	internal void AddChannelForwarder(ChannelForwarder channelForwarder)
	{
		if (this.disposed)
		{
			channelForwarder.Dispose();
		}
		else
		{
			lock (this.channelForwarders)
			{
				this.channelForwarders.Add(channelForwarder);
			}
		}
	}

	internal void RemoveChannelForwarder(ChannelForwarder channelForwarder)
	{
		lock (this.channelForwarders)
		{
			this.channelForwarders.Remove(channelForwarder);
		}
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing && !this.disposed)
		{
			this.disposed = true;

			var disposables = new List<IDisposable>();

			lock (this.channelForwarders)
			{
				disposables.AddRange(this.channelForwarders);
				this.channelForwarders.Clear();
			}

			lock (this.localForwarders)
			{
				disposables.AddRange(this.localForwarders.Values);
				this.localForwarders.Clear();
			}

			lock (this.remoteConnectors)
			{
				disposables.AddRange(this.remoteConnectors.Values);
				this.remoteConnectors.Clear();
			}

			foreach (var disposable in disposables)
			{
				disposable.Dispose();
			}
		}

		base.Dispose(disposing);
	}
}
