// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Enables opening an SSH session over a TCP connection.
/// </summary>
/// <remarks>
/// It's possible to create an `SshClientSession` over any `Stream` instance;
/// this class is merely a convenient helper that manages creating a session
/// over a `Stream` obtained from a `TcpClient`.
/// </remarks>
public class SshClient : IDisposable
{
	private const int DefaultServerPort = 22;

	private readonly SshSessionConfiguration config;
	private readonly object sessionsLock = new object();
	private readonly List<SshClientSession> sessions;
	private readonly TraceSource trace;

	public SshClient(SshSessionConfiguration config, TraceSource trace)
	{
		if (config == null) throw new ArgumentNullException(nameof(config));
		if (trace == null) throw new ArgumentNullException(nameof(trace));

		this.config = config;
		this.trace = trace;
		this.sessions = new List<SshClientSession>();
	}

	public IReadOnlyCollection<SshClientSession> Sessions => this.sessions;

	public event EventHandler<Exception>? ExceptionRaised;

	public async Task<SshClientSession> OpenSessionAsync(
		string serverHost,
		int serverPort = DefaultServerPort,
		CancellationToken cancellation = default)
	{
		(var stream, var ipAddress) = await this.OpenConnectionAsync(
			serverHost, serverPort, cancellation).ConfigureAwait(false);
		var session = new SshClientSession(this.config, this.trace);

		lock (this.sessionsLock)
		{
			this.sessions.Add(session);
		}

		session.RemoteIPAddress = ipAddress;
		session.Closed += (s, e) =>
		{
			if (e.Exception != null)
			{
				ExceptionRaised?.Invoke(this, e.Exception);
			}

			lock (this.sessionsLock)
			{
				this.sessions.Remove(session);
			}
		};

		try
		{
			await session.ConnectAsync(stream, cancellation).ConfigureAwait(false);
		}
		catch (SshConnectionException ex)
		{
			await session.CloseAsync(ex.DisconnectReason, ex).ConfigureAwait(false);
			throw;
		}
		catch (Exception ex)
		{
			await session.CloseAsync(SshDisconnectReason.ProtocolError, ex).ConfigureAwait(false);
			throw;
		}

		return session;
	}

	protected virtual async Task<(Stream Stream, IPAddress? RemomoteIPAddress)> OpenConnectionAsync(
		string host, int port, CancellationToken cancellation)
	{
#pragma warning disable CA2000 // Dispose objects before losing scope
		var tcpClient = new TcpClient();
#pragma warning restore CA2000 // Dispose objects before losing scope

#if NET5_0 || NET6_0
		await tcpClient.ConnectAsync(host, port, cancellation)
#else
		await tcpClient.ConnectAsync(host, port)
#endif
				.ConfigureAwait(false);

		tcpClient.Client.ConfigureSocketOptionsForSsh();

		NetworkStream stream = tcpClient.GetStream();
		IPAddress? ipAddress = 
			tcpClient.Client.RemoteEndPoint is IPEndPoint ipEndpoint? ipEndpoint.Address : null;
		return (stream, ipAddress);
	}

	public async Task ReconnectSessionAsync(
		SshClientSession session, string host, int port, CancellationToken cancellation = default)
	{
		if (session == null) throw new ArgumentNullException(nameof(session));

		(var stream, _) = await this.OpenConnectionAsync(host, port, cancellation)
			.ConfigureAwait(false);
		await session.ReconnectAsync(stream, cancellation).ConfigureAwait(false);
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
			foreach (SshClientSession clientSession in this.sessions.ToArray())
			{
				clientSession.Dispose();
			}

			lock (this.sessionsLock)
			{
				this.sessions.Clear();
			}
		}
	}
}
