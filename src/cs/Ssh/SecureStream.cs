// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Establishes an end-to-end encrypted two-way authenticated data stream over an underlying
/// transport stream, using the SSH protocol but providing simplified interface that is limited to
/// a single duplex stream (channel).
/// </summary>
/// <remarks>
/// This class is a complement to <see cref="MultiChannelStream"/>, which provides only the
/// channel-multiplexing functions of SSH.
///
/// To establish a secure connection, the two sides first establish an insecure transport stream
/// over a pipe, socket, or anything else. Then they encrypt and authenticate the connection
/// before beginning to send and receive data.
/// </remarks>
public class SecureStream : Stream
{
	/// <summary>
	/// Creates a secure stream over an underlying transport stream, using client credentials
	/// to authenticate.
	/// </summary>
	/// <param name="transportStream">Underlying (insecure) transport stream.</param>
	/// <param name="clientCredentials">Client authentication credentials.</param>
	/// <param name="enableReconnect">True to enable SSH reconnection; default is false.</param>
	/// <param name="trace">Optional trace source for SSH protocol tracing.</param>
	public SecureStream(
		Stream transportStream,
		SshClientCredentials clientCredentials,
		bool enableReconnect = false,
		TraceSource? trace = null)
	{
		this.TransportStream = transportStream ??
			throw new ArgumentNullException(nameof(transportStream));
		this.Session = new SshClientSession(
			enableReconnect ?
				SshSessionConfiguration.DefaultWithReconnect : SshSessionConfiguration.Default,
			trace ?? new TraceSource(nameof(SecureStream)));

		this.Session.Authenticating += OnSessionAuthenticating;
		this.Session.Disconnected += OnSessionDisconnected;
		this.Session.Closed += OnSessionClosed;

		this.ClientCredentials = clientCredentials ??
			throw new ArgumentNullException(nameof(clientCredentials));
	}

	/// <summary>
	/// Creates a secure stream over an underlying transport stream, using server credentials
	/// to authenticate.
	/// </summary>
	/// <param name="transportStream">Underlying (insecure) transport stream.</param>
	/// <param name="serverCredentials">Server authentication credentials.</param>
	/// <param name="reconnectableSessions">Optional collection that tracks secure-stream
	/// server sessions available for reconnection; if null then reconnection is disabled.</param>
	/// <param name="trace">Optional trace source for SSH protocol tracing.</param>
	public SecureStream(
		Stream transportStream,
		SshServerCredentials serverCredentials,
		ICollection<SshServerSession>? reconnectableSessions = null,
		TraceSource? trace = null)
	{
		this.TransportStream = transportStream ??
			throw new ArgumentNullException(nameof(transportStream));
		this.Session = new SshServerSession(
			reconnectableSessions != null ?
				SshSessionConfiguration.DefaultWithReconnect : SshSessionConfiguration.Default,
			reconnectableSessions,
			trace ?? new TraceSource(nameof(SecureStream)));

		this.Session.Authenticating += OnSessionAuthenticating;
		this.Session.Disconnected += OnSessionDisconnected;
		this.Session.Closed += OnSessionClosed;

		this.ServerCredentials = serverCredentials ??
			throw new ArgumentNullException(nameof(serverCredentials));
	}

	/// <summary>
	/// Gets the underlying transport stream for the secure stream.
	/// </summary>
	protected Stream TransportStream { get; private set; }

	/// <summary>
	/// Gets the SSH session that implements the secure protocol.
	/// </summary>
	protected SshSession Session { get; private set; }

	/// <summary>
	/// Gets the client credentials, or null if this is the server side.
	/// </summary>
	protected SshClientCredentials? ClientCredentials { get; }

	/// <summary>
	/// Gets the server credentials, or null if this is the client side.
	/// </summary>
	protected SshServerCredentials? ServerCredentials { get; }

	/// <summary>
	/// Gets the secured stream established by this instance.
	/// </summary>
	protected SshStream? Stream { get; set; }

	/// <summary>
	/// Gets a completion source that completes when the stream is fully connected.
	/// </summary>
	/// <remarks>
	/// Stream async read/write operations use this to wait for the connection.
	/// </remarks>
	protected TaskCompletionSource<bool> ConnectCompletion { get; } = new ();

	/// <summary>
	/// Event raised when the secure stream is authenticating the client or server.
	/// </summary>
	public event EventHandler<SshAuthenticatingEventArgs>? Authenticating;

	/// <summary>
	/// Event raised when the secure stream is disconnected while reconnection is enabled.
	/// </summary>
	/// <remarks>
	/// After this is raised, a secure stream client application should call
	/// <see cref="ReconnectAsync" />  with a new stream. (The secure stream server handles
	/// reconnections automatically during the session handshake.)
	/// </remarks>
	public event EventHandler<EventArgs>? Disconnected;

	/// <summary>
	/// Gets a value indicating whether the session is closed.
	/// </summary>
	public bool IsClosed =>
		this.Session.IsClosed;

	/// <summary>
	/// Event that is raised when underlying ssh session is closed.
	/// </summary>
	/// <remarks>
	/// The event is raised before the session stream is closed.
	/// The stream will be closed after the event handler.
	/// </remarks>
	public event EventHandler<SshSessionClosedEventArgs>? Closed;

	/// <summary>
	/// Limits the amount of time that ConnectAsync() may wait for the initial
	/// session handshake (version exchange).
	/// </summary>
	public TimeSpan? ConnectTimeout
	{
		get => this.Session.ConnectTimeout;
		set => this.Session.ConnectTimeout = value;
	}

	/// <summary>
	/// Initiates the SSH session over the transport stream by exchanging initial messages with the
	/// remote peer. Waits for the protocol version exchange, key exchange, authentication, and
	/// opened channel. Additional message processing is kicked off as a background task chain.
	/// </summary>
	/// <exception cref="SshConnectionException">The connection failed due to a protocol
	/// error.</exception>
	/// <exception cref="TimeoutException">The ConnectTimeout property is set and the initial
	/// version exchange could not be completed within the timeout.</exception>
	public async Task ConnectAsync(CancellationToken cancellation = default)
	{
		if (Authenticating == null)
		{
			throw new InvalidOperationException(
				"An Authenticating event handler must be registered before connecting.");
		}

		try
		{
			if (this.ServerCredentials != null)
			{
				var serverSession = (SshServerSession)this.Session;
				serverSession.Credentials = this.ServerCredentials;
			}

			await this.Session.ConnectAsync(this.TransportStream, cancellation).ConfigureAwait(false);

			SshChannel? channel = null;
			if (this.ClientCredentials != null)
			{
				var clientSession = (SshClientSession)this.Session;
				if (!(await clientSession.AuthenticateServerAsync(cancellation).ConfigureAwait(false)))
				{
					throw new SshConnectionException(
						"Server authentication failed.", SshDisconnectReason.HostKeyNotVerifiable);
				}

				if (!(await clientSession.AuthenticateClientAsync(
					this.ClientCredentials, cancellation).ConfigureAwait(false)))
				{
					throw new SshConnectionException(
						"Client authentication failed.", SshDisconnectReason.NoMoreAuthMethodsAvailable);
				}

				channel = await this.Session.OpenChannelAsync(cancellation).ConfigureAwait(false);
			}
			else
			{
				channel = await this.Session.AcceptChannelAsync(cancellation).ConfigureAwait(false);
			}

			this.Stream = CreateStream(channel);
			channel.Closed += (_, _) =>
			{
				this.Dispose();
			};
		}
		catch (ObjectDisposedException) when (this.Session.IsClosed)
		{
			// The session was closed while waiting for the channel.
			// This can happen in reconnect scenarios.
			this.Dispose();
			this.ConnectCompletion.TrySetResult(false);
		}
		catch (Exception ex)
		{
			var disconnectReason = (ex as SshConnectionException)?.DisconnectReason ??
				SshDisconnectReason.ProtocolError;
			await this.Session.CloseAsync(disconnectReason, ex).ConfigureAwait(false);
			this.ConnectCompletion.TrySetException(ex);
			throw;
		}

		this.ConnectCompletion.TrySetResult(true);
	}

	/// <summary>
	/// Re-initiates the SSH session over a NEW transport stream by exchanging initial messages
	/// with the remote server. Waits for the secure reconnect handshake to complete. Additional
	/// message processing is kicked off as a background task chain.
	/// </summary>
	/// <exception cref="SshConnectionException">The connection failed due to a protocol
	/// error.</exception>
	/// <exception cref="TimeoutException">The ConnectTimeout property is set and the initial
	/// version exchange could not be completed within the timeout.</exception>
	/// <remarks>
	/// Applies only to a secure stream client. (The secure stream server handles reconnections
	/// automatically during the session handshake.)
	/// </remarks>
	public async Task ReconnectAsync(
		Stream transportStream,
		CancellationToken cancellation = default)
	{
		if (!(this.Session is SshClientSession clientSession))
		{
			throw new InvalidOperationException("Cannot reconnect SecureStream server.");
		}

		this.TransportStream = transportStream ??
			throw new ArgumentNullException(nameof(transportStream));
		await clientSession.ReconnectAsync(this.TransportStream, cancellation).ConfigureAwait(false);
	}

	/// <summary>
	/// Creates a stream instance for a channel. May be overridden to create a
	/// <see cref="SshStream" /> subclass.
	/// </summary>
	protected virtual SshStream CreateStream(SshChannel channel)
	{
		return new SshStream(channel);
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			bool sessionWasConnected = this.Session.IsConnected || this.Session.IsClosed;

			if (!this.Session.IsClosed)
			{
				this.Session.Trace.TraceEvent(
					TraceEventType.Verbose,
					SshTraceEventIds.ChannelClosed,
					$"{nameof(SecureStream)} {this.Session} closing.");
			}

			this.Stream?.Dispose();
			this.Session.Dispose();

			if (!sessionWasConnected)
			{
				// If the session did not connect yet, it doesn't know about the stream and
				// won't dispose it. So dispose it here.
				this.TransportStream.Dispose();
			}
		}

		base.Dispose(disposing);
	}

	/// <summary>
	/// Close the SSH session with <see cref="SshDisconnectReason.None"/> reason and dispose the underlying transport stream.
	/// </summary>
	public async Task CloseAsync()
	{
		// Disposing the session closes the channel, which causes this SecureStream to be disposed.
		await this.Session.CloseAsync(
			SshDisconnectReason.None, this.Session.GetType().Name + " disposed").ConfigureAwait(false);
		this.Session.Dispose();

#if !NETSTANDARD2_0 && !NET4
		await this.TransportStream.DisposeAsync().ConfigureAwait(false);
#else
		this.TransportStream.Dispose();
#endif
	}

	/// <summary>
	/// The SSH software name and version of the remote client,
	/// parsed when a connection is made to the server
	/// </summary>
	public SshVersionInfo? RemoteVersion => this.Session.RemoteVersion;

	private void OnSessionAuthenticating(object? sender, SshAuthenticatingEventArgs e)
	{
		Authenticating?.Invoke(this, e);
	}

	private void OnSessionDisconnected(object? sender, EventArgs e)
	{
		Disconnected?.Invoke(this, e);
	}

	private void OnSessionClosed(object? sender, SshSessionClosedEventArgs e)
	{
		this.Session.Closed -= OnSessionClosed;
		Closed?.Invoke(this, e);
	}

	public override bool CanRead => true;

	public override bool CanWrite => true;

	public override void Flush()
	{
		this.Stream?.Flush();
	}

	private SshStream ConnectedStream
		=> this.Stream ?? throw new InvalidOperationException("Stream is not connected.");

	public override int Read(byte[] buffer, int offset, int count)
	{
		return ConnectedStream.Read(buffer, offset, count);
	}

	public override void Write(byte[] buffer, int offset, int count)
	{
		ConnectedStream.Write(buffer, offset, count);
	}

#pragma warning disable CA1835 // Use Memory<> Stream overloads

	public override async Task<int> ReadAsync(
		byte[] buffer, int offset, int count, CancellationToken cancellation)
	{
		if (!(await this.ConnectCompletion.Task.ConfigureAwait(false)))
		{
			return 0;
		}

		return await ConnectedStream.ReadAsync(buffer, offset, count, cancellation)
			.ConfigureAwait(false);
	}

	public override async Task WriteAsync(
		byte[] buffer, int offset, int count, CancellationToken cancellation)
	{
		if (!(await this.ConnectCompletion.Task.ConfigureAwait(false)))
		{
			throw new ObjectDisposedException(nameof(SecureStream));
		}

		await ConnectedStream.WriteAsync(buffer, offset, count, cancellation)
			.ConfigureAwait(false);
	}

#pragma warning restore CA1835

	#region Seek / position / length are not supported

	public override bool CanSeek => false;

	public override long Length => throw new NotSupportedException();

	public override long Position
	{
		get => throw new NotSupportedException();
		set => throw new NotSupportedException();
	}

	public override long Seek(long offset, SeekOrigin origin)
	{
		throw new NotSupportedException();
	}

	public override void SetLength(long value)
	{
		throw new NotSupportedException();
	}

	#endregion
}
