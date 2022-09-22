using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Test;

/// <summary>
/// Wraps a stream with mock disconnection behaviors for testing purposes.
/// </summary>
class MockNetworkStream : Stream
{
	private int? dropSendBytesCount;
	private Exception disconnectException;

	private readonly TaskCompletionSource<int> disposedCompletionSource =
		new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

	public MockNetworkStream(Stream underlyingStream)
	{
		UnderlyingStream = underlyingStream;
	}

	public Stream UnderlyingStream { get; }

	public bool DisposeUnderlyingStream { get; set; } = true;

	public bool IsClosed { get; private set; }

	public override bool CanRead => UnderlyingStream.CanRead;

	public override bool CanSeek => false;

	public override bool CanWrite => UnderlyingStream.CanWrite;

	public override long Length => throw new NotSupportedException();

	public override long Position
	{
		get => throw new NotSupportedException();
		set => throw new NotSupportedException();
	}

	public override void Flush()
		=> throw new NotImplementedException("Synchronous APIs are not implemented.");

	public override int Read(byte[] buffer, int offset, int count)
		=> throw new NotImplementedException("Synchronous APIs are not implemented.");

	public override long Seek(long offset, SeekOrigin origin)
		=> throw new NotImplementedException("Synchronous APIs are not implemented.");

	public override void SetLength(long value)
		=> throw new NotSupportedException();

	public override void Write(byte[] buffer, int offset, int count)
		=> throw new NotImplementedException("Synchronous APIs are not implemented.");

	public void MockDisconnect(
		Exception disconnectException,
		int? dropSendBytesCount = null)
	{
		if (dropSendBytesCount == null)
		{
			this.IsClosed = true;
			this.disposedCompletionSource.TrySetException(disconnectException);
		}
		else
		{
			this.disconnectException = disconnectException;
			this.dropSendBytesCount = dropSendBytesCount;
		}
	}

	public override async Task<int> ReadAsync(
		byte[] buffer, int offset, int count, CancellationToken cancellationToken)
	{
		var disposedTask = this.disposedCompletionSource.Task;
		if (IsClosed) await disposedTask;

		// Retry the read when getting a zero-length result.
		// This accounts for a bug in the pipe stream pair used for unit-testing.
		// These streams return a zero-lengh result when there is no available data,
		// whereas a network stream would not return a zero-length result until graefully closed.
		int result = 0;
		for (int i = 0; result == 0 && i < 2; i++)
		{
			var readTask = UnderlyingStream.ReadAsync(buffer, offset, count, cancellationToken);
			result = await await Task.WhenAny(readTask, disposedTask);
		}

		return result;
	}

	public override async Task WriteAsync(
		byte[] buffer, int offset, int count, CancellationToken cancellationToken)
	{
		var disposedTask = this.disposedCompletionSource.Task;
		if (IsClosed) await disposedTask;

		if (this.dropSendBytesCount != null)
		{
			if (count <= this.dropSendBytesCount)
			{
				this.dropSendBytesCount -= count;

				// Drop these bytes by returning without writing to the underlying stream.
				return;
			}
			else
			{
				this.disposedCompletionSource.TrySetException(this.disconnectException);
				this.Dispose();
				await disposedTask;
			}
		}

		var writeTask = UnderlyingStream.WriteAsync(buffer, offset, count, cancellationToken);
		await await Task.WhenAny(writeTask, disposedTask);
	}

	public override async Task FlushAsync(CancellationToken cancellationToken)
	{
		var disposedTask = this.disposedCompletionSource.Task;
		if (IsClosed) await disposedTask;

		if (this.dropSendBytesCount == 0)
		{
			this.disposedCompletionSource.TrySetException(this.disconnectException);
			this.Dispose();
			return;
		}

		var flushTask = UnderlyingStream.FlushAsync(cancellationToken);
		await await Task.WhenAny(flushTask, disposedTask);
	}

	protected override void Dispose(bool disposing)
	{
		IsClosed = true;

		if (disposing)
		{
			this.disposedCompletionSource.TrySetException(
				new ObjectDisposedException(nameof(MockNetworkStream)));

			if (DisposeUnderlyingStream)
			{
				UnderlyingStream.Dispose();
			}
		}

		base.Dispose(disposing);
	}
}
