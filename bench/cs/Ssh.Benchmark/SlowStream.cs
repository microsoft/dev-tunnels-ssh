using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Benchmark;

/// <summary>
/// Simulates additional network latency by inserting async delays in stream writes (not reads).
/// </summary>
class SlowStream : Stream
{
	private Queue<byte[]> writeQueue = new Queue<byte[]>();
	private int writeCount = 0;

	public SlowStream(Stream baseStream, TimeSpan addedLatency)
	{
		BaseStream = baseStream ?? throw new ArgumentNullException(nameof(baseStream));
		AddedLatency = addedLatency;
	}

	public Stream BaseStream { get; }

	public TimeSpan AddedLatency { get; }

	public override bool CanRead => BaseStream.CanRead;

	public override bool CanSeek => BaseStream.CanSeek;

	public override bool CanWrite => BaseStream.CanWrite;

	public override long Length => BaseStream.Length;

	public override long Position { get => BaseStream.Position; set => BaseStream.Position = value; }

	public override int Read(byte[] buffer, int offset, int count) =>
		throw new NotSupportedException("Synchronous stream methods are not supported.");

	public override long Seek(long offset, SeekOrigin origin) => BaseStream.Seek(offset, origin);

	public override void SetLength(long value) => BaseStream.SetLength(value);

	public override void Write(byte[] buffer, int offset, int count) =>
		throw new NotSupportedException("Synchronous stream methods are not supported.");
	public override void Flush() =>
		throw new NotSupportedException("Synchronous stream methods are not supported.");

	public override Task<int> ReadAsync(
		byte[] buffer, int offset, int count, CancellationToken cancellationToken)
	{
		return BaseStream.ReadAsync(buffer, offset, count, cancellationToken);
	}

	public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
	{
		var segment = new byte[count];
		Array.Copy(buffer, offset, segment, 0, count);
		lock (this.writeQueue)
		{
			this.writeQueue.Enqueue(segment);
			this.writeCount++;
		}
		return Task.CompletedTask;
	}

	public override Task FlushAsync(CancellationToken cancellationToken)
	{
		int count;
		lock (this.writeQueue)
		{
			// Only flush the number of writes since the last flush.
			// This ensures all writes get exactly the specified delay.
			count = this.writeCount;
			this.writeCount = 0;
		}

		if (count == 0)
		{
			return Task.CompletedTask;
		}

		var stopwatch = new System.Diagnostics.Stopwatch();
		stopwatch.Start();

		Task.Run(async () =>
		{
				// Spinning like this is horribly inefficient, but for benchmarking purposes it enables
				// a much more precise latency simulation compared to something like Task.Delay(ms).
				while (stopwatch.ElapsedMilliseconds < AddedLatency.TotalMilliseconds)
			{
				await Task.Yield();
			}

				// Lock while dequeuing+writing to ensure blocks are written to the base stream in order.
				lock (this.writeQueue)
			{
				while (count-- > 0 && this.writeQueue.TryDequeue(out var buffer))
				{
					BaseStream.Write(buffer, 0, buffer.Length);
				}
			}
		});

		return Task.CompletedTask;
	}
}
