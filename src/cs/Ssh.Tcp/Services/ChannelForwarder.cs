﻿// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;

namespace Microsoft.DevTunnels.Ssh.Tcp;

internal class ChannelForwarder : IDisposable
{
	private readonly PortForwardingService pfs;
	private bool disposed;
	private readonly SemaphoreSlim receiveSemaphore;
	private readonly ConcurrentQueue<Buffer> receiveQueue;
	private SshChannelClosedEventArgs? channelClosedEvent;
	private readonly NetworkStream stream;
	private readonly TraceSource trace;
	private readonly CancellationTokenSource disposeCancellationSource;

	public ChannelForwarder(PortForwardingService pfs, SshChannel channel, TcpClient client)
	{
		this.pfs = pfs ?? throw new ArgumentNullException(nameof(pfs));
		Channel = channel ?? throw new ArgumentNullException(nameof(channel));
		Client = client ?? throw new ArgumentNullException(nameof(client));
		this.stream = client.GetStream() ?? throw new ArgumentNullException(nameof(client));

		this.receiveSemaphore = new SemaphoreSlim(0);
		this.receiveQueue = new ConcurrentQueue<Buffer>();
		this.trace = channel.Session.Trace;
		this.disposeCancellationSource = new CancellationTokenSource();

		Channel.DataReceived += OnChannelDataReceived;
		Channel.Closed += OnChannelClosed;

		ForwardFromStreamToChannel(new Buffer(4096));
		ForwardFromChannelToStream();
	}

	public SshChannel Channel { get; }

	public TcpClient Client { get; set; }

	private void OnChannelDataReceived(object? sender, Buffer data)
	{
		if (this.disposed)
		{
			return;
		}

		// Enqueue a copy of the buffer because the current one may be re-used by the caller.
		var copy = new Buffer(data.Count);
		data.CopyTo(copy);

		this.receiveQueue.Enqueue(copy);

		try
		{
			this.receiveSemaphore.Release();
		}
		catch (ObjectDisposedException)
		{
			// The semaphore was disposed.
		}

		Channel.AdjustWindow((uint)data.Count);
	}

	private void OnChannelClosed(object? sender, SshChannelClosedEventArgs e)
	{
		if (this.disposed)
		{
			return;
		}

		this.channelClosedEvent = e;

		try
		{
			this.receiveSemaphore.Release();
		}
		catch (ObjectDisposedException)
		{
			// The semaphore was disposed.
		}
	}

	private async void ForwardFromChannelToStream()
	{
		try
		{
			bool forwarding;
			do
			{
				forwarding = await ForwardFromChannelToStreamAsync().ConfigureAwait(false);
			}
			while (forwarding);

			this.pfs.RemoveChannelForwarder(this);
			this.Dispose();
		}
		catch (Exception ex)
		{
			// Catch all exceptions in this async void method.
			this.trace.TraceEvent(
				TraceEventType.Error,
				SshTraceEventIds.UnknownError,
				$"{nameof(PortForwardingService)} unexpected error reading channel stream: {ex}");
		}
	}

	private async Task<bool> ForwardFromChannelToStreamAsync()
	{
		try
		{
			await this.receiveSemaphore.WaitAsync(this.disposeCancellationSource.Token)
				.ConfigureAwait(false);
		}
		catch (ObjectDisposedException)
		{
			// The semaphore was disposed.
			CloseStream(abort: true);
			return false;
		}
		catch (OperationCanceledException)
		when (this.disposeCancellationSource.IsCancellationRequested)
		{
			// The channel-forwarder was disposed.
			CloseStream(abort: true);
			return false;
		}

		if (this.receiveQueue.TryDequeue(out Buffer data))
		{
			try
			{
#if SSH_ENABLE_SPAN
				await this.stream.WriteAsync(
					data.Memory, this.disposeCancellationSource.Token).ConfigureAwait(false);
#else
				await this.stream.WriteAsync(
					data.Array,
					data.Offset,
					data.Count,
					this.disposeCancellationSource.Token).ConfigureAwait(false);
#endif
				return true;
			}
			catch (OperationCanceledException)
			when (this.disposeCancellationSource.IsCancellationRequested)
			{
				// The channel-forwarder was disposed.
				CloseStream(abort: true);
				return false;
			}
		}
		else
		{
			if (this.channelClosedEvent != null)
			{
				var errorMessage = this.channelClosedEvent.ErrorMessage
					?? this.channelClosedEvent.Exception?.Message;
				var message = string.IsNullOrEmpty(errorMessage) ?
					$"Forwarder channel {Channel.ChannelId} closed." :
					$"Forwarder channel {Channel.ChannelId} closed with error: " + errorMessage;
				this.trace.TraceEvent(
					TraceEventType.Information,
					SshTraceEventIds.PortForwardChannelClosed,
					message);

				CloseStream(abort: (errorMessage != null));
			}

			// Reached end of stream.
			return false;
		}
	}

	private void CloseStream(bool abort)
	{
		try
		{
			if (abort)
			{
				var socket = Client.Client;
				socket.Abort();
			}
			else
			{
				this.stream.Close();
			}
		}
		catch (Exception ex)
		{
			this.trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.UnknownError,
				$"{nameof(PortForwardingService)} unexpected error clising connection: {ex}");
			return;
		}

		this.trace.TraceEvent(
			TraceEventType.Information,
			SshTraceEventIds.PortForwardChannelClosed,
			$"Channel forwarder {(abort ? "aborted" : "closed")} connection.");
	}

	private async void ForwardFromStreamToChannel(Buffer buffer)
	{
		try
		{
			bool forwarding;
			do
			{
				forwarding = await ForwardFromStreamToChannelAsync(
					buffer, this.disposeCancellationSource.Token).ConfigureAwait(false);
			}
			while (forwarding);

			this.pfs.RemoveChannelForwarder(this);
			this.Dispose();
		}
		catch (Exception ex)
		{
			// Catch all exceptions in this async void method.
			this.trace.TraceEvent(
				TraceEventType.Error,
				SshTraceEventIds.UnknownError,
				$"{nameof(PortForwardingService)} unexpected error reading channel stream: {ex}");
		}
	}

	private async Task<bool> ForwardFromStreamToChannelAsync(
		Buffer buffer, CancellationToken cancellation)
	{
		int count;
		Exception? ex = null;
		try
		{
#if NETSTANDARD2_0 || NET4
			count = await this.stream.ReadAsync(
				buffer.Array, buffer.Offset, buffer.Count, cancellation).ConfigureAwait(false);
#else
			count = await this.stream.ReadAsync(buffer.Memory, cancellation).ConfigureAwait(false);
#endif
		}
		catch (IOException ioex)
		{
			ex = ioex;
			count = 0;
		}
		catch (SocketException sockex)
		{
			ex = sockex;
			count = 0;
		}
		catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
		{
			return false;
		}

		// Do not use the (dispose) cancellation token when writing to the channel, because
		// an interrupted write can cause the whole SSH session to disconnect.
		if (count > 0)
		{
			await Channel.SendAsync(buffer.Slice(0, count), CancellationToken.None)
				.ConfigureAwait(false);
			return true;
		}
		else if (ex == null)
		{
			string message = "Channel forwarder reached end of stream.";
			this.trace.TraceEvent(TraceEventType.Verbose, SshTraceEventIds.ChannelClosed, message);
			try
			{
				await Channel.SendAsync(Buffer.Empty, CancellationToken.None).ConfigureAwait(false);
				await Channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
			}
		}
		else
		{
			string message = $"Channel forwarder stream read error: {ex.Message}";
			this.trace.TraceEvent(TraceEventType.Verbose, SshTraceEventIds.ChannelClosed, message);
			try
			{
				await Channel.CloseAsync("SIGABRT", ex.Message, CancellationToken.None)
					.ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
			}
		}

		return false;
	}

	/// <summary>
	/// Diposes the service; called when the session is disposing.
	/// </summary>
	public void Dispose()
	{
		Dispose(true);
		GC.SuppressFinalize(this);
	}

	/// <summary>
	/// Subclasses may override this method to dispose any resources.
	/// </summary>
	/// <param name="disposing">True if managed objects are disposed.</param>
	protected virtual void Dispose(bool disposing)
	{
		if (disposing && !this.disposed)
		{
			this.disposed = true;
			try
			{
				this.disposeCancellationSource.Cancel();
			}
			catch (ObjectDisposedException) { }
			this.disposeCancellationSource.Dispose();

			this.receiveSemaphore.Dispose();
		}
	}
}
