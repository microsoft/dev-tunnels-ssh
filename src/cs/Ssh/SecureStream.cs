// Copyright (c) Microsoft. All rights reserved.

using System;
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
	private readonly Stream transportStream;
	private readonly SshSession session;
	private readonly SshClientCredentials? clientCredentials;
	private readonly SshServerCredentials? serverCredentials;
	private SshStream? stream;
	private readonly TaskCompletionSource<bool> connectCompletion = new ();

	/// <summary>
	/// Creates a secure stream over an underlying transport stream, using client credentials
	/// to authenticate.
	/// </summary>
	/// <param name="transportStream">Underlying (insecure) transport stream.</param>
	/// <param name="clientCredentials">Client authentication credentials.</param>
	/// <param name="trace">Optional trace source for SSH protocol tracing.</param>
	public SecureStream(
		Stream transportStream,
		SshClientCredentials clientCredentials,
		TraceSource? trace = null)
	{
		this.transportStream = transportStream ??
			throw new ArgumentNullException(nameof(transportStream));
		this.session = new SshClientSession(
			SshSessionConfiguration.Default,
			trace ?? new TraceSource(nameof(SecureStream)));

		this.session.Authenticating += OnSessionAuthenticating;
		this.session.Closed += OnSessionClosed;

		this.clientCredentials = clientCredentials ??
			throw new ArgumentNullException(nameof(clientCredentials));
	}

	/// <summary>
	/// Creates a secure stream over an underlying transport stream, using server credentials
	/// to authenticate.
	/// </summary>
	/// <param name="transportStream">Underlying (insecure) transport stream.</param>
	/// <param name="serverCredentials">Server authentication credentials.</param>
	/// <param name="trace">Optional trace source for SSH protocol tracing.</param>
	public SecureStream(
		Stream transportStream,
		SshServerCredentials serverCredentials,
		TraceSource? trace = null)
	{
		this.transportStream = transportStream ??
			throw new ArgumentNullException(nameof(transportStream));
		this.session = new SshServerSession(
			SshSessionConfiguration.Default,
			trace ?? new TraceSource(nameof(SecureStream)));

		this.session.Authenticating += OnSessionAuthenticating;
		this.session.Closed += OnSessionClosed;

		this.serverCredentials = serverCredentials ??
			throw new ArgumentNullException(nameof(serverCredentials));
	}

	public event EventHandler<SshAuthenticatingEventArgs>? Authenticating;

	/// <summary>
	/// Gets a value indicating whether the session is closed.
	/// </summary>
	public bool IsClosed =>
		this.session.IsClosed;

	/// <summary>
	/// Event that is rised when underlying ssh session is closed.
	/// </summary>
	/// <remarks>
	/// The event is rised before the session stream is closed.
	/// The stream will be closed after the event handler.
	/// </remarks>
	public EventHandler<SshSessionClosedEventArgs>? Closed
	{
		get;
		set;
	}

	/// <summary>
	/// Limits the amount of time that ConnectAsync() may wait for the initial
	/// session handshake (version exchange).
	/// </summary>
	public TimeSpan? ConnectTimeout
	{
		get => this.session.ConnectTimeout;
		set => this.session.ConnectTimeout = value;
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
			if (this.serverCredentials != null)
			{
				var serverSession = (SshServerSession)this.session;
				serverSession.Credentials = this.serverCredentials;
			}

			await this.session.ConnectAsync(this.transportStream, cancellation).ConfigureAwait(false);

			SshChannel? channel = null;
			if (this.clientCredentials != null)
			{
				var clientSession = (SshClientSession)this.session;
				if (!(await clientSession.AuthenticateServerAsync(cancellation).ConfigureAwait(false)))
				{
					throw new SshConnectionException(
						"Server authentication failed.", SshDisconnectReason.HostKeyNotVerifiable);
				}

				if (!(await clientSession.AuthenticateClientAsync(
					this.clientCredentials, cancellation).ConfigureAwait(false)))
				{
					throw new SshConnectionException(
						"Client authentication failed.", SshDisconnectReason.NoMoreAuthMethodsAvailable);
				}

				channel = await this.session.OpenChannelAsync(cancellation).ConfigureAwait(false);
			}
			else
			{
				channel = await this.session.AcceptChannelAsync(cancellation).ConfigureAwait(false);
			}

			this.stream = CreateStream(channel);
			channel.Closed += (_, _) =>
			{
				this.Dispose();
			};
		}
		catch (Exception ex)
		{
			var disconnectReason = (ex as SshConnectionException)?.DisconnectReason ??
				SshDisconnectReason.ProtocolError;
			await this.session.CloseAsync(disconnectReason, ex).ConfigureAwait(false);
			this.connectCompletion.TrySetException(ex);
			throw;
		}

		this.connectCompletion.TrySetResult(true);
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
			this.stream?.Dispose();
			this.session.Dispose();

			// If the session has not connected yet, it doesn't know about the stream and won't dispose it.
			// So we dispose it explicitly here.
			this.transportStream.Dispose();
		}

		base.Dispose(disposing);
	}

	/// <summary>
	/// Close the SSH session with <see cref="SshDisconnectReason.None"/> reason and dispose the underlying transport stream.
	/// </summary>
	public async Task CloseAsync()
	{
		// Diposing the session closes the channel, which causes this SecureStream to be disposed.
		await this.session.CloseAsync(
			SshDisconnectReason.None, this.session.GetType().Name + " disposed").ConfigureAwait(false);
		this.session.Dispose();

#if !NETSTANDARD2_0 && !NET4
		await this.transportStream.DisposeAsync().ConfigureAwait(false);
#else
		this.transportStream.Dispose();
#endif
	}

	/// <summary>
	/// The SSH software name and version of the remote client,
	/// parsed when a connection is made to the server
	/// </summary>
	public SshVersionInfo? RemoteVersion => this.session.RemoteVersion;

	private void OnSessionAuthenticating(object? sender, SshAuthenticatingEventArgs e)
	{
		Authenticating?.Invoke(this, e);
	}

	private void OnSessionClosed(object? sender, SshSessionClosedEventArgs e)
	{
		this.session.Closed -= OnSessionClosed;
		Closed?.Invoke(this, e);
	}

	public override bool CanRead => true;

	public override bool CanWrite => true;

	public override void Flush()
	{
		this.stream?.Flush();
	}

	private SshStream ConnectedStream
		=> this.stream ?? throw new InvalidOperationException("Stream is not connected.");

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
		await this.connectCompletion.Task.ConfigureAwait(false);
		return await ConnectedStream.ReadAsync(buffer, offset, count, cancellation)
			.ConfigureAwait(false);
	}

	public override async Task WriteAsync(
		byte[] buffer, int offset, int count, CancellationToken cancellation)
	{
		await this.connectCompletion.Task.ConfigureAwait(false);
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
