// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Services;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Multiplexes multiple virtual streams (channels) over a single transport stream, using the
/// SSH protocol while providing a simplified interface without any encryption or authentication.
/// </summary>
/// <remarks>
/// This class is a complement to <see cref="SecureStream"/>, which provides only the
/// encryption and authentication functions of SSH.
///
/// To communicate over multiple channels, two sides first establish a transport stream
/// over a pipe, socket, or anything else. Then one side accepts a channel while the
/// other side opens a channel. Either side can both open and accept channels over the
/// same transport stream, as long as the other side does the complementary action.
/// </remarks>
/// <example>
///
///     // On side A, where `transportStreamA` is already connected to B
///     var muxA = new MultiChannelStream(transportStreamA);
///     Stream channelA1 = await muxA.AcceptChannelAsync();
///     Stream channelA2 = await muxA.OpenChannelAsync();
///
///     // On side B, where `transportStreamB` is already connected to A
///     var muxB = new MultiChannelStream(transportStreamB);
///     Stream channelB1 = await muxA.OpenChannelAsync();
///     Stream channelB2 = await muxA.AcceptChannelAsync();
///
/// </example>
public class MultiChannelStream : IDisposable
{
	/// <summary>
	/// Creates a new multi-channel stream over an underlying transport stream.
	/// </summary>
	/// <param name="transportStream">Stream that is used to multiplex all the channels.</param>
	/// <param name="trace">Optional trace source for SSH protocol tracing.</param>
	public MultiChannelStream(Stream transportStream, TraceSource? trace = null)
	{
		this.TransportStream = transportStream ?? throw new ArgumentNullException(nameof(transportStream));
		this.Session = new SshSession(
			SshSessionConfiguration.NoSecurity,
			trace ?? new TraceSource(nameof(MultiChannelStream)));

		this.Session.Closed += OnSessionClosed;
		this.Session.ChannelOpening += OnChannelOpening;
	}

	/// <summary>
	/// Gets the underlying transport stream for the multi-channel stream.
	/// </summary>
	protected Stream TransportStream { get; }

	/// <summary>
	/// Gets the SSH session that implements the multi-channel protocol.
	/// </summary>
	protected SshSession Session { get; }

	/// <summary>
	/// Gets a value indicating whether the session is closed.
	/// </summary>
	public bool IsClosed =>
		this.Session.IsClosed;

	/// <summary>
	/// Gets or sets the maximum window size for channels within the multi-channel stream.
	/// </summary>
	/// <seealso cref="SshChannel.MaxWindowSize" />
	public uint ChannelMaxWindowSize { get; set; } = SshChannel.DefaultMaxWindowSize;

	/// <summary>
	/// Event that is raised when a channel is requested.
	/// Check <see cref="SshChannelOpeningEventArgs.IsRemoteRequest"/> to determine if the channel open request was initiated by the other party.
	/// The handler may set <see cref="SshChannelOpeningEventArgs.FailureReason"/> to abort channel opening,
	/// or call <see cref="AcceptChannelAsync(string?, CancellationToken)"/> or <see cref="AcceptStreamAsync(string?, CancellationToken)"/> to accept the channel.
	/// </summary>
	/// <remarks>
	/// Adding an event handler will activate the connection service on the session.
	/// </remarks>
	/// <exception cref="ObjectDisposedException">If a handler is added when the underlying ssh session is closed.</exception>
	public event EventHandler<SshChannelOpeningEventArgs>? ChannelOpening;

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
	/// remote peer. Waits for the protocol version exchange and key exchange. Additional message
	/// processing is kicked off as a background task chain.
	/// </summary>
	/// <exception cref="SshConnectionException">The connection failed due to a protocol
	/// error.</exception>
	/// <exception cref="TimeoutException">The ConnectTimeout property is set and the initial
	/// version exchange could not be completed within the timeout.</exception>
	public virtual Task ConnectAsync(CancellationToken cancellation = default)
	{
		// Activate the connection service (support for opening channels) before connecting.
		// This ensures that a channel request immediately after connection can be handled.
		// In a normal session this would be activated after key-exchange and authentication.
		this.Session.ActivateService<ConnectionService>();

		return this.Session.ConnectAsync(this.TransportStream, cancellation);
	}

	/// <summary>
	/// Connects, waits until the session closes or <paramref name="cancellation"/> is cancelled, and then disposes the session and the transport stream.
	/// </summary>
	/// <param name="cancellation">Cancellation token.</param>
	/// <exception cref="ObjectDisposedException">If the session is already closed.</exception>
	/// <exception cref="OperationCanceledException">If <paramref name="cancellation"/> is cancelled before the session ended.</exception>
	/// <exception cref="SshConnectionException">If the connection failed due to a protocol error.</exception>
	/// <exception cref="TimeoutException">If the ConnectTimeout property is set and the initial
	/// version exchange could not be completed within the timeout.</exception>
	public async Task ConnectAndRunUntilClosedAsync(CancellationToken cancellation = default)
	{
		var tcs = new TaskCompletionSource<SshDisconnectReason>(
			TaskCreationOptions.RunContinuationsAsynchronously);
		void OnSessionClosed(object? sender, SshSessionClosedEventArgs e) => tcs.TrySetResult(e.Reason);

		this.Session.Closed += OnSessionClosed;

		try
		{
			await ConnectAsync(cancellation).ConfigureAwait(false);

			using var tokenRegistration = cancellation.CanBeCanceled ?
				cancellation.Register(() => tcs.TrySetCanceled(cancellation)) : default;

			var disconnectReason = await tcs.Task.ConfigureAwait(false);
			if (disconnectReason != SshDisconnectReason.ByApplication && disconnectReason != SshDisconnectReason.None)
			{
				throw new SshConnectionException("SSH connection failed", disconnectReason);
			}
		}
		catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
		{
			// Expected.
			throw;
		}
		catch (Exception exception)
		{
			var reason = exception is SshConnectionException connectionException ?
				connectionException.DisconnectReason : SshDisconnectReason.ConnectionLost;
			await this.Session.CloseAsync(reason, exception).ConfigureAwait(false);
			throw;
		}
		finally
		{
			this.Session.Closed -= OnSessionClosed;
			await CloseAsync().ConfigureAwait(false);
		}
	}

	/// <summary>
	/// Asynchronously waits for the other side to open a channel.
	/// </summary>
	/// <returns>The accepted channel.</returns>
	/// <exception cref="SshConnectionException">There was a protocol error while establishing
	/// the session.</exception>
	/// <exception cref="IOException">There was a problem reading from or writing to the
	/// transport stream.</exception>
	public Task<SshStream> AcceptStreamAsync(
		CancellationToken cancellation = default)
	{
		return AcceptStreamAsync(null, cancellation);
	}

	/// <summary>
	/// Asynchronously waits for the other side to open a channel.
	/// </summary>
	/// <param name="channelType">Optional channel type to accept. Only a channel with the given type
	/// will be accepted by this call.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The accepted channel.</returns>
	/// <exception cref="SshConnectionException">There was a protocol error while establishing
	/// the session.</exception>
	/// <exception cref="IOException">There was a problem reading from or writing to the
	/// transport stream.</exception>
	public async Task<SshStream> AcceptStreamAsync(
		string? channelType,
		CancellationToken cancellation = default)
	{
		return CreateStream(
			await AcceptChannelAsync(channelType, cancellation).ConfigureAwait(false));
	}

	/// <summary>
	/// Asynchronously waits for the other side to open a channel.
	/// </summary>
	/// <param name="channelType">Optional channel type to accept. Only a channel with the given type
	/// will be accepted by this call.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The ssh channel being opened.</returns>
	public async Task<SshChannel> AcceptChannelAsync(
		string? channelType,
		CancellationToken cancellation = default)
	{
		await ConnectAsync(cancellation).ConfigureAwait(false);
		var channel = await this.Session.AcceptChannelAsync(channelType, cancellation)
			.ConfigureAwait(false);
		return channel;
	}

	/// <summary>
	/// Opens a channel and asynchronously waits for the other side to accept it.
	/// </summary>
	/// <returns>The opened channel.</returns>
	/// <exception cref="SshChannelException">The other side blocked the channel
	/// from opening.</exception>
	/// <exception cref="SshConnectionException">There was a protocol error while establishing
	/// the session or opening the channel.</exception>
	/// <exception cref="IOException">There was a problem reading from or writing to the
	/// transport stream.</exception>
	public Task<SshStream> OpenStreamAsync(
		CancellationToken cancellation = default)
	{
		return OpenStreamAsync(null, cancellation);
	}

	/// <summary>
	/// Opens a channel and asynchronously waits for the other side to accept it.
	/// </summary>
	/// <param name="channelType">Optional channel type to open. The other side must accept a
	/// channel with the given type.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The opened channel.</returns>
	/// <exception cref="SshChannelException">The other side blocked the channel
	/// from opening.</exception>
	/// <exception cref="SshConnectionException">There was a protocol error while establishing
	/// the session or opening the channel.</exception>
	/// <exception cref="IOException">There was a problem reading from or writing to the
	/// transport stream.</exception>
	public async Task<SshStream> OpenStreamAsync(
		string? channelType,
		CancellationToken cancellation = default)
	{
		return CreateStream(
			await OpenChannelAsync(channelType, cancellation).ConfigureAwait(false));
	}

	/// <summary>
	/// Opens a channel and asynchronously waits for the other side to accept it.
	/// </summary>
	/// <param name="channelType">Optional channel type to open. The other side must accept a
	/// channel with the given type.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The opened channel.</returns>
	public virtual async Task<SshChannel> OpenChannelAsync(
		string? channelType,
		CancellationToken cancellation = default)
	{
		await this.Session.ConnectAsync(this.TransportStream, cancellation).ConfigureAwait(false);

		var openMessage = new ChannelOpenMessage
		{
			ChannelType = channelType,
			MaxWindowSize = ChannelMaxWindowSize,
		};
		var channel = await this.Session.OpenChannelAsync(openMessage, null, cancellation)
			.ConfigureAwait(false);
		return channel;
	}

	/// <summary>
	/// Creates a stream instance for a channel. May be overridden to create a
	/// <see cref="SshStream" /> subclass.
	/// </summary>
	protected virtual SshStream CreateStream(SshChannel channel)
	{
		return new SshStream(channel);
	}

	/// <summary>
	/// Disposes the SSH session and the underlying transport stream.
	/// </summary>
	public void Dispose()
	{
		this.Dispose(true);
		GC.SuppressFinalize(this);
	}

	protected virtual void Dispose(bool disposing)
	{
		if (disposing)
		{
			this.Session.Dispose();

			// If the session has not connected yet, it doesn't know about the stream and won't dispose it.
			// So we dispose it explicitly here.
			this.TransportStream.Dispose();
		}
	}

	/// <summary>
	/// Close the SSH session with <see cref="SshDisconnectReason.None"/> reason and dispose the underlying transport stream.
	/// </summary>
	public virtual async Task CloseAsync()
	{
		await this.Session.CloseAsync(
			SshDisconnectReason.None, this.Session.GetType().Name + " disposed.").ConfigureAwait(false);
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

	private void OnChannelOpening(object? sender, SshChannelOpeningEventArgs e)
	{
		if (e.IsRemoteRequest)
		{
			e.Channel.MaxWindowSize = ChannelMaxWindowSize;
		}

		ChannelOpening?.Invoke(this, e);
	}

	private void OnSessionClosed(object? sender, SshSessionClosedEventArgs e)
	{
		this.Session.Closed -= OnSessionClosed;
		this.Session.ChannelOpening -= OnChannelOpening;
		Closed?.Invoke(this, e);
	}
}
