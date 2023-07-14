// Copyright (c) Microsoft. All rights reserved.

using System;
#if SSH_ENABLE_SPAN
using System.Buffers;
#endif
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Tcp;

internal class StreamForwarder : IDisposable
{
	private const int BufferSize = 8192;

	private bool disposed;

	public StreamForwarder(
		Stream localStream,
		Stream remoteStream,
		TraceSource trace)
	{
		LocalStream = localStream ?? throw new ArgumentNullException(nameof(localStream));
		RemoteStream = remoteStream ?? throw new ArgumentNullException(nameof(remoteStream));
		Trace = trace ?? throw new ArgumentNullException(nameof(trace));

		ForwardStreamAsync();
	}

	public Stream LocalStream { get; }

	public Stream RemoteStream { get; }

	public TraceSource Trace { get; }

	public event EventHandler<EventArgs>? Closed;

	private async void ForwardStreamAsync()
	{
		try
		{
			bool endOfStream = await ForwardStreamAsync(LocalStream, RemoteStream)
				.ConfigureAwait(false);
			Close(abort: !endOfStream);
		}
		catch (Exception ex)
		{
			// Catch all exceptions in this async void method.
			try
			{
				Trace.TraceEvent(
					TraceEventType.Error,
					SshTraceEventIds.UnknownError,
					$"{nameof(PortForwardingService)} unexpected error forwarding stream: {ex}");
				Close(abort: true);
			}
			catch (Exception)
			{
			}
		}
	}

	/// <summary>
	/// Forwards data between local and remote streams until either the end of one of the streams
	/// is reached or an I/O error occurs.
	/// </summary>
	/// <returns>True if the end of stream was reached (graceful closure) else false</returns>
	protected virtual async Task<bool> ForwardStreamAsync(Stream localStream, Stream remoteStream)
	{
		if (localStream == null) throw new ArgumentNullException(nameof(localStream));
		if (remoteStream == null) throw new ArgumentNullException(nameof(remoteStream));

		using var cancellationSource = new CancellationTokenSource();

		var forwardTask = ForwardStreamAsync(localStream, remoteStream, cancellationSource.Token);
		var backwardTask = ForwardStreamAsync(remoteStream, localStream, cancellationSource.Token);

		var firstToComplete = await Task.WhenAny(forwardTask, backwardTask)
			.ConfigureAwait(false);
		cancellationSource.Cancel();

		await Task.WhenAll(forwardTask, backwardTask).ConfigureAwait(false);
		return await firstToComplete.ConfigureAwait(false);
	}

	/// <summary>
	/// Forwards from a source stream to a destination stream until either the end of the source
	/// stream is reached, an I/O error occurs, or the cancellation token is cancelled.
	/// </summary>
	/// <returns>True if the end of stream was reached (graceful closure) else false</returns>
	private async Task<bool> ForwardStreamAsync(
		Stream source,
		Stream destination,
		CancellationToken cancellation = default)
	{
#if SSH_ENABLE_SPAN
		using var memoryOwner = MemoryPool<byte>.Shared.Rent(BufferSize);
		var memory = memoryOwner.Memory;
#else
		byte[] buffer = new byte[BufferSize];
#endif
		while (!cancellation.IsCancellationRequested)
		{
			int count = 0;
			Exception? readException = null;
			try
			{
#if SSH_ENABLE_SPAN
				count = await source.ReadAsync(memory, cancellation)
#else
				count = await source.ReadAsync(buffer, 0, buffer.Length, cancellation)
#endif
					.ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
			{
				break;
			}
			catch (IOException) when (this.disposed)
			{
				return false;
			}
			catch (ObjectDisposedException) when (this.disposed)
			{
				return false;
			}
			catch (IOException ex)
			{
				readException = ex;
			}
			catch (SocketException ex)
			{
				readException = ex;
			}
			catch (ObjectDisposedException ex)
			{
				readException = ex;
			}
			catch (SshConnectionException ex)
			{
				readException = ex;
			}

			if (count > 0)
			{
				// Do not pass cancellation token to writer because writing may be non-atomic,
				// and cancelling it may corrupt the stream.
#if SSH_ENABLE_SPAN
				await destination.WriteAsync(memory.Slice(0, count), CancellationToken.None)
#else
				await destination.WriteAsync(buffer, 0, count, CancellationToken.None)
#endif
					.ConfigureAwait(false);
			}
			else if (readException == null)
			{
				string message = $"Stream forwarder reached end of stream.";
				Trace.TraceEvent(
					TraceEventType.Verbose, SshTraceEventIds.ChannelClosed, message);
				await destination.FlushAsync(CancellationToken.None).ConfigureAwait(false);
				break;
			}
			else
			{
				string message = $"Stream forwarder stream read error: {readException.Message}";
				Trace.TraceEvent(TraceEventType.Verbose, SshTraceEventIds.ChannelClosed, message);
				Trace.TraceEvent(TraceEventType.Verbose, SshTraceEventIds.ChannelClosed, readException.ToString());
				await destination.FlushAsync(CancellationToken.None).ConfigureAwait(false);
				destination.Close();
				return false;
			}
		}

		if (!this.disposed)
		{
			this.disposed = true;
			destination.Close();
			Closed?.Invoke(this, EventArgs.Empty);
		}

		return true;
	}

	private void Close(bool abort, string? errorMessage = null)
	{
		try
		{
			if (abort && LocalStream is NetworkStream networkStream)
			{
				networkStream.Abort();
			}
			else
			{
				LocalStream.Close();
			}

			if (abort && RemoteStream is SshStream sshStream && !sshStream.IsDisposed)
			{
				_ = sshStream.Channel.CloseAsync("SIGABRT", errorMessage);
			}
			else
			{
				RemoteStream.Close();
			}

			Trace.TraceEvent(
				TraceEventType.Verbose,
				SshTraceEventIds.PortForwardChannelClosed,
				$"Stream forwarder {(abort ? "aborted" : "closed")} connection.");
		}
		catch (Exception ex)
		{
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.UnknownError,
				$"{nameof(PortForwardingService)} unexpected error closing connection: {ex}");
		}

		Closed?.Invoke(this, EventArgs.Empty);
	}

	/// <summary>
	/// Disposes the service; called when the session is disposing.
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
			Close(abort: true);
		}
	}
}
