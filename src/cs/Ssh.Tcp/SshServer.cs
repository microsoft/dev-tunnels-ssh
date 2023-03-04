// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Enables accepting SSH sessions on a TCP socket.
/// </summary>
/// <remarks>
/// It's possible to create an `SshServerSession` over any `Stream` instance;
/// this class is merely a convenient helper that manages creating sessions
/// over `Stream` instances obtained from a `TcpListener`.
/// </remarks>
public class SshServer : IDisposable
{
	private readonly SshSessionConfiguration config;
	private readonly CancellationTokenSource disposeCancellationSource;
	private readonly object sessionsLock = new object();
	private readonly List<SshServerSession> sessions;
	private readonly List<SshServerSession>? reconnectableSessions;
	private readonly TraceSource trace;

	public SshServer(SshSessionConfiguration config, TraceSource trace)
	{
		if (config == null) throw new ArgumentNullException(nameof(config));
		if (trace == null) throw new ArgumentNullException(nameof(trace));

		this.config = config;
		this.trace = trace;
		this.disposeCancellationSource = new CancellationTokenSource();
		this.sessions = new List<SshServerSession>();

		if (config.ProtocolExtensions.Contains(SshProtocolExtensionNames.SessionReconnect))
		{
			this.reconnectableSessions = new List<SshServerSession>();
		}
	}

	public IReadOnlyCollection<SshServerSession> Sessions => this.sessions;

	public event EventHandler<SshAuthenticatingEventArgs>? SessionAuthenticating;
	public event EventHandler<SshServerSession>? SessionOpened;
	public event EventHandler<SshRequestEventArgs<SessionRequestMessage>>? SessionRequest;
	public event EventHandler<SshChannelOpeningEventArgs>? ChannelOpening;
	public event EventHandler<SshRequestEventArgs<ChannelRequestMessage>>? ChannelRequest;
	public event EventHandler<Exception>? ExceptionRasied;

	public SshServerCredentials Credentials { get; set; } = new SshServerCredentials();

	/// <summary>
	/// Gets or sets a factory for creating TCP listeners.
	/// </summary>
	/// <remarks>
	/// Applications may override this factory to provide custom logic for selecting
	/// local port numbers to listen on for port-forwarding.
	/// </remarks>
	public ITcpListenerFactory TcpListenerFactory { get; set; }
		= new DefaultTcpListenerFactory();

	public async Task AcceptSessionsAsync(
		int localPort,
		IPAddress? localAddress = null)
	{
		localAddress ??= IPAddress.Any;
		string portPrefix = localAddress.Equals(IPAddress.Any) ?
			"port " : localAddress.ToString() + ":";

		TcpListener listener;
		try
		{
			listener = await TcpListenerFactory.CreateTcpListenerAsync(
				localAddress,
				localPort,
				canChangePort: false,
				this.trace,
				CancellationToken.None)
				.ConfigureAwait(false);
		}
		catch (SocketException sockex)
		{
			this.trace.TraceEvent(
				TraceEventType.Error,
				SshTraceEventIds.ServerListenFailed,
				$"{nameof(SshServer)} failed to listen on {portPrefix}{localPort}: {sockex.Message}");
			throw;
		}

		localPort = ((IPEndPoint)listener.LocalEndpoint).Port;

		using (this.disposeCancellationSource.Token.Register(listener.Stop))
		{
			this.trace.TraceEvent(
				TraceEventType.Information,
				SshTraceEventIds.ServerListening,
				$"{nameof(SshServer)} listening on {portPrefix}{localPort}.");
			try
			{
				while (true)
				{
					var stream = await AcceptConnectionAsync(listener).ConfigureAwait(false);
					if (stream == null)
					{
						// The server was disposed.
						break;
					}

					this.trace.TraceEvent(
						TraceEventType.Information,
						SshTraceEventIds.ServerClientConnected,
						$"{nameof(SshServer)} client connected.");

					var session = new SshServerSession(
						this.config, this.reconnectableSessions, this.trace);
					session.Credentials = Credentials;

					lock (this.sessionsLock)
					{
						this.sessions.Add(session);
					}

					session.Authenticating += (s, e) =>
					{
						SessionAuthenticating?.Invoke(s, e);
					};
					session.Request += (s, e) =>
					{
						SessionRequest?.Invoke(s, e);
					};
					session.ChannelOpening += (s, e) =>
					{
						ChannelOpening?.Invoke(this, e);
						if (e.FailureReason == SshChannelOpenFailureReason.None)
						{
							e.Channel.Request += (cs, ce) =>
							{
								ChannelRequest?.Invoke(cs, ce);
							};
						}
					};
					session.Closed += (s, e) =>
					{
						lock (this.sessionsLock)
						{
							this.sessions.Remove(session);
						}
					};
					SessionOpened?.Invoke(this, session);

					var task = Task.Run(async () =>
					{
						try
						{
							await session.ConnectAsync(stream, CancellationToken.None).ConfigureAwait(false);
						}
						catch (SshConnectionException ex)
						{
							await session.CloseAsync(ex.DisconnectReason, ex).ConfigureAwait(false);
							ExceptionRasied?.Invoke(this, ex);
						}
						catch (Exception ex)
						{
							await session.CloseAsync(SshDisconnectReason.ProtocolError, ex)
							.ConfigureAwait(false);
							ExceptionRasied?.Invoke(this, ex);
						}
					});
				}
			}
			catch (Exception ex)
			{
				ExceptionRasied?.Invoke(this, ex);
			}
			finally
			{
				listener.Stop();
			}
		}
	}

	protected virtual async Task<Stream?> AcceptConnectionAsync(TcpListener listener)
	{
		TcpClient tcpClient;
		try
		{
			tcpClient = await Task.Run(() => listener.AcceptTcpClientAsync())
				.ConfigureAwait(false);
		}
		catch (SocketException) when (this.disposeCancellationSource.IsCancellationRequested)
		{
			// The server was disposed.
			return null;
		}
		catch (ObjectDisposedException) when (this.disposeCancellationSource.IsCancellationRequested)
		{
			// The server was disposed.
			return null;
		}

		tcpClient.Client.ConfigureSocketOptionsForSsh();

		NetworkStream stream = tcpClient.GetStream();
		return stream;
	}

	public void Dispose()
	{
		this.Dispose(true);
		GC.SuppressFinalize(this);
	}

	protected virtual void Dispose(bool disposing)
	{
		if (disposing)
		{
			this.disposeCancellationSource.Cancel();
			this.disposeCancellationSource.Dispose();

			foreach (SshServerSession serverSession in this.sessions.ToArray())
			{
				serverSession.Dispose();
			}

			lock (this.sessionsLock)
			{
				this.sessions.Clear();
			}
		}
	}
}
