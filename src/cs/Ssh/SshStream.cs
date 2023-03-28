// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Wraps an SSH channel in a stream.
/// </summary>
/// <remarks>
/// This class is NOT fully thread-safe. While it supports current reading and writing,
/// it does not support more than one concurrent reader or more than one concurrent writer.
/// </remarks>
public class SshStream : Stream
{
#pragma warning disable CA2213 // Disposable fields should be disposed
	private readonly SemaphoreSlim readSemaphore;
#pragma warning restore CA2213 // Disposable fields should be disposed

	private readonly ConcurrentQueue<Buffer> readQueue;
	private Buffer readBuffer;
	private int readBufferOffset;
	private bool channelClosed;
	private Exception? channelClosedException;

	public SshStream(SshChannel channel)
	{
		if (channel == null) throw new ArgumentNullException(nameof(channel));

		this.readSemaphore = new SemaphoreSlim(0);
		this.readQueue = new ConcurrentQueue<Buffer>();

		Channel = channel;
		Channel.DataReceived += OnChannelDataReceived;
		Channel.Closed += OnChannelClosed;
	}

	public SshChannel Channel { get; }

	public bool IsDisposed { get; private set; }

	public override bool CanRead => !IsDisposed;

	public override bool CanWrite => !IsDisposed;

	#region Seek / position / length are not supported

	public override bool CanSeek => false;

	public override long Seek(long offset, SeekOrigin origin)
	{
		throw new NotSupportedException();
	}

#pragma warning disable CA1065 // Properties should not throw invalid exception types

	public override long Position
	{
		get => throw new NotSupportedException();
		set => throw new NotSupportedException();
	}

	public override long Length => throw new NotSupportedException();

#pragma warning restore CA1065

	public override void SetLength(long value)
	{
		throw new NotSupportedException();
	}

	#endregion

	public override void Flush()
	{
		CheckDisposed();

		// It could be possible to wait for the channel sending window to fully open.
		// That would indicate the other side has read all the sent bytes... but it
		// would be a very extreme interpretation of "flush".
	}

	public override int Read(byte[] buffer, int offset, int count)
	{
		if (buffer == null) throw new ArgumentNullException(nameof(buffer));

		CheckDisposed();

		if (this.readBuffer.Count == 0)
		{
			this.readSemaphore.Wait();
			DequeueBuffer();
		}

		return ReadFromBuffer(buffer, offset, count);
	}

	public override async Task<int> ReadAsync(
		byte[] buffer, int offset, int count, CancellationToken cancellation)
	{
		if (buffer == null) throw new ArgumentNullException(nameof(buffer));

		CheckDisposed();

		if (this.readBuffer.Count == 0)
		{
			await this.readSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
			DequeueBuffer();
		}

		return ReadFromBuffer(buffer, offset, count);
	}

	private void DequeueBuffer()
	{
		if (this.readQueue.TryDequeue(out this.readBuffer))
		{
			if (!this.channelClosed && this.readBuffer.Count > 0)
			{
				Channel.AdjustWindow((uint)this.readBuffer.Count);
			}
		}
		else
		{
			if (this.channelClosed && this.channelClosedException != null)
			{
				// If there is nothing read from the network, and the network stream threw IOException,
				// throw the network disruption exception here, to differentiate abnormal network activity with
				// normal closure.
				throw this.channelClosedException;
			}

			// Reached end of stream.
			this.readBuffer = Buffer.Empty;
			this.readSemaphore.TryRelease();
		}

		this.readBufferOffset = 0;
	}

	private int ReadFromBuffer(byte[] buffer, int offset, int count)
	{
		int available = this.readBuffer.Count - this.readBufferOffset;
		if (count >= available)
		{
			// Fully consume the read buffer.
			this.readBuffer.Slice(this.readBufferOffset, available).CopyTo(buffer, offset);
			this.readBuffer = Buffer.Empty;
			return available;
		}
		else
		{
			// Partially consume the read buffer.
			this.readBuffer.Slice(this.readBufferOffset, count).CopyTo(buffer, offset);
			this.readBufferOffset += count;
			return count;
		}
	}

	public override void Write(byte[] buffer, int offset, int count)
	{
		if (buffer == null) throw new ArgumentNullException(nameof(buffer));

		CheckDisposed();

		Task sendTask = Channel.SendAsync(
			Buffer.From(buffer, offset, count), CancellationToken.None);
		sendTask.Wait();
	}

	public override async Task WriteAsync(
		byte[] buffer, int offset, int count, CancellationToken cancellation)
	{
		if (buffer == null) throw new ArgumentNullException(nameof(buffer));

		CheckDisposed();

		await Channel.SendAsync(Buffer.From(buffer, offset, count), cancellation)
			.ConfigureAwait(false);
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			// Asynchronously close the channel, but don't wait for it.
			_ = Channel.CloseAsync();

			// SemaphoreSlim.Dispose() is not thread-safe and may cause WaitAsync(CancellationToken) not being cancelled
			// when SemaphoreSlim.Dispose is invoked immediately after CancellationTokenSource.Cancel.
			// See https://github.com/dotnet/runtime/issues/59639
			// SemaphoreSlim.Dispose() only disposes it's wait handle, which is not initialized unless its AvailableWaitHandle
			// property is read, which we don't use.

			// this.readSemaphore.Dispose();

			IsDisposed = true;
		}

		base.Dispose(disposing);
	}

	private void OnChannelDataReceived(object? sender, Buffer data)
	{
		if (IsDisposed)
		{
			return;
		}

		// Enqueue a copy of the buffer because the current one may be re-used by the caller.
		var copy = new Buffer(data.Count);
		data.CopyTo(copy);

		this.readQueue.Enqueue(copy);

		this.readSemaphore.TryRelease();
	}

	private void OnChannelClosed(object? sender, SshChannelClosedEventArgs e)
	{
		if (IsDisposed)
		{
			return;
		}

		this.channelClosed = true;
		this.channelClosedException = e.Exception;

		this.readSemaphore.TryRelease();
	}

	private void CheckDisposed()
	{
		if (IsDisposed)
		{
			throw new ObjectDisposedException(nameof(SshStream));
		}
	}

	public override string ToString()
	{
		return $"{GetType().Name}(Channel Type: {Channel.ChannelType}, " +
			$"Id: {Channel.ChannelId}, RemoteId: {Channel.RemoteChannelId})";
	}
}
