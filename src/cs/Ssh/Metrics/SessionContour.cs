// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Metrics;

/// <summary>
/// Collects session metrics over time, producing an outline of the timing, speed,
/// and quantity of bytes sent/received during the session.
/// </summary>
/// <remarks>
/// Metrics are recorded across a number of equal time intervals. As the session time
/// increases, intervals are expanded to keep the number of intervals under the configured
/// maximum. Each expansion doubles the length of all intervals, while combining the metrics
/// within each pair of combined intervals. Therefore, a longer session has longer intervals
/// and less-granular metrics. In this way, the memory usage (and serialized size) of the
/// session contour remains roughly constant regardless of the length of the session.
///
/// Metrics exposed via the collection properties on this class may be momentarily
/// inconsistent (but will not throw exceptions) if continued session operation causes
/// intervals to be expanded while the data is being read concurrently. To avoid any
/// inconsistency, hold a lock on the <see cref="SessionContour" /> instance while reading
/// data. (Or wait until the session ends.)
///
/// A session contour can be exported in a compact form suitable for logging or telemetry.
/// Use the code in `SessionContour.kql` to chart a session contour in Azure Data Explorer.
/// </remarks>
public sealed class SessionContour : IDisposable
{
	private const long InitialInterval = 1_000; // 1 second (in milliseconds)

	/// <summary>Current size of the metrics interval, in milliseconds.</summary>
	private long interval = InitialInterval;

	// Each of these arrays holds one metric per interval.
	private readonly long[] bytesSent;
	private readonly long[] bytesReceived;
	private readonly float[] latencyMin;
	private readonly float[] latencyMax;
	private readonly double[] latencySum;
	private readonly long[] latencyCount;

	/// <summary>Queue of contour updates to be processed in a background task.</summary>
	private readonly ConcurrentQueue<ContourUpdate> updateQueue =
		new ConcurrentQueue<ContourUpdate>();

#pragma warning disable CA2213 // Disposable fields should be disposed
	/// <summary>Notifies when updates are available on the queue.</summary>
	private readonly SemaphoreSlim updateSemaphore = new SemaphoreSlim(0);
#pragma warning restore CA2213 // Disposable fields should be disposed

	private bool disposed;

	/// <summary>
	/// Creates a new instance of the <see cref="SessionContour" /> class.
	/// </summary>
	/// <param name="maxIntervals">Maximum number of metric intervals to record,
	/// defaults to 256. Must be a power of two.</param>
	public SessionContour(int maxIntervals = 256)
	{
		if (maxIntervals < 2 || (maxIntervals & (maxIntervals - 1)) != 0)
		{
			throw new ArgumentOutOfRangeException(
				nameof(maxIntervals), "Contour intervals must be a power of two.");
		}

		MaxIntervals = maxIntervals;
		this.bytesSent = new long[maxIntervals];
		this.bytesReceived = new long[maxIntervals];
		this.latencyMin = new float[maxIntervals];
		this.latencyMax = new float[maxIntervals];
		this.latencySum = new double[maxIntervals];
		this.latencyCount = new long[maxIntervals];

		BytesSent = new ContourList<long>(() => IntervalCount, (i) => this.bytesSent[i]);
		BytesReceived = new ContourList<long>(() => IntervalCount, (i) => this.bytesReceived[i]);
		LatencyMinMs = new ContourList<float>(() => IntervalCount, (i) => this.latencyMin[i]);
		LatencyMaxMs = new ContourList<float>(() => IntervalCount, (i) => this.latencyMax[i]);
		LatencyAverageMs = new ContourList<float>(() => IntervalCount, (i) =>
		{
			var count = this.latencyCount[i];
			return (float)(count == 0 ? 0 : this.latencySum[i] / count);
		});
	}

	/// <summary>
	/// Gets the maximum number of intervals that can be recorded in this contour. Intervals
	/// are expanded as necesary such that the entire duration of the session is always covered
	/// by fewer intervals than this limit.
	/// </summary>
	public int MaxIntervals { get; }

	/// <summary>
	/// Gets the current number of contour intervals with recorded metrics. This is always
	/// less than <see cref="MaxIntervals" />.
	/// </summary>
	public int IntervalCount { get; private set; }

	/// <summary>
	/// Gets the current time span of each contour interval. This interval time span is
	/// doubled as necesary such that the entire duration of the session is always covered
	/// by fewer intervals than the maximum.
	/// </summary>
	public TimeSpan Interval => TimeSpan.FromMilliseconds(this.interval);

	/// <summary>
	/// Gets the total number of bytes sent for each interval during the session,
	/// including all channels and non-channel protocol messages, and including message
	/// framing, padding, and MAC bytes. The number of values is equal to
	/// <see cref="IntervalCount" />.
	/// </summary>
	public IReadOnlyList<long> BytesSent { get; }

	/// <summary>
	/// Gets the total number of bytes received for each interval during the session,
	/// including all channels and non-channel protocol messages, and including message
	/// framing, padding, and MAC bytes. The number of values is equal to
	/// <see cref="IntervalCount" />.
	/// </summary>
	public IReadOnlyList<long> BytesReceived { get; }

	/// <summary>
	/// Gets the minimum recorded round-trip connection latency between client and server for
	/// each interval during the session. The number of values is equal to
	/// <see cref="IntervalCount" />.
	/// </summary>
	public IReadOnlyList<float> LatencyMinMs { get; }

	/// <summary>
	/// Gets the maximum recorded round-trip connection latency between client and server for
	/// each interval during the session. The number of values is equal to
	/// <see cref="IntervalCount" />.
	/// </summary>
	public IReadOnlyList<float> LatencyMaxMs { get; }

	/// <summary>
	/// Gets the average recorded round-trip connection latency between client and server for
	/// each interval during the session. The number of values is equal to
	/// <see cref="IntervalCount" />.
	/// </summary>
	public IReadOnlyList<float> LatencyAverageMs { get; }

	private void OnMessageSent(object? sender, (long Time, int Size) e)
	{
		this.updateQueue.Enqueue(new ContourUpdate
		{
			Time = e.Time,
			BytesSent = e.Size,
		});
		this.updateSemaphore.TryRelease();
	}

	private void OnMessageReceived(object? sender, (long Time, int Size) e)
	{
		this.updateQueue.Enqueue(new ContourUpdate
		{
			Time = e.Time,
			BytesReceived = e.Size,
		});
		this.updateSemaphore.TryRelease();
	}

	private void OnLatencyUpdated(object? sender, (long Time, float Latency) e)
	{
		this.updateQueue.Enqueue(new ContourUpdate
		{
			Time = e.Time,
			Latency = e.Latency,
		});
		this.updateSemaphore.TryRelease();
	}

	private void OnSessionClosed(object? sender, EventArgs e)
	{
		// Releasing the semaphore without enqueuing an update will cause the update loop to end.
		this.updateSemaphore.TryRelease();
	}

	/// <summary>
	/// Starts collecting session metrics, and processes the metrics in a backgroud loop until
	/// cancelled or until the session is closed or the <see cref="SessionContour" /> instance
	/// is disposed.
	/// </summary>
	public async Task CollectMetricsAsync(
		SessionMetrics sessionMetrics,
		CancellationToken cancellation = default)
	{
		if (sessionMetrics == null) throw new ArgumentNullException(nameof(sessionMetrics));
		if (this.disposed) throw new ObjectDisposedException(nameof(SessionContour));

		sessionMetrics.MessageSent += OnMessageSent;
		sessionMetrics.MessageReceived += OnMessageReceived;
		sessionMetrics.LatencyUpdated += OnLatencyUpdated;
		sessionMetrics.SessionClosed += OnSessionClosed;
		try
		{
			while (!cancellation.IsCancellationRequested)
			{
				await this.updateSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
				if (this.disposed)
				{
					break;
				}

				if (!this.updateQueue.TryDequeue(out var update))
				{
					// The semaphore was released without enqueueing an update item.
					break;
				}

				var intervalIndex = UpdateInterval(update.Time);

				this.bytesSent[intervalIndex] += update.BytesSent;
				this.bytesReceived[intervalIndex] += update.BytesReceived;

				var latency = update.Latency;
				if (latency != 0)
				{
					if (this.latencyMin[intervalIndex] == 0 ||
						latency < this.latencyMin[intervalIndex])
					{
						this.latencyMin[intervalIndex] = latency;
					}

					if (latency > this.latencyMax[intervalIndex])
					{
						this.latencyMax[intervalIndex] = latency;
					}

					this.latencySum[intervalIndex] += latency;
					this.latencyCount[intervalIndex]++;
				}
			}
		}
		finally
		{
			sessionMetrics.MessageSent -= OnMessageSent;
			sessionMetrics.MessageReceived -= OnMessageReceived;
			sessionMetrics.LatencyUpdated -= OnLatencyUpdated;
			sessionMetrics.SessionClosed -= OnSessionClosed;
		}
	}

	private int UpdateInterval(long time)
	{
		var intervalIndex = (int)(time / this.interval);
		if (intervalIndex >= IntervalCount)
		{
			// Expand as needed to accomodate the current time interval.
			while (intervalIndex >= MaxIntervals)
			{
				// Hold a lock on the instance while expanding intervals so that data consumers
				// can also lock if they need to get consistent data.
#pragma warning disable CA2002 // Do not lock on objects with weak identity
				lock (this)
#pragma warning restore CA2002 // Do not lock on objects with weak identity
				{
					ExpandIntervals();
				}

				intervalIndex = (int)(time / this.interval);
			}

			IntervalCount = intervalIndex + 1;
		}

		return intervalIndex;
	}

	private void ExpandIntervals()
	{
		Func<float, float, Func<float, float, float>, float> combineLatency = (a, b, f) =>
			a == 0 ? b : b == 0 ? a : f(a, b);

		int halfMaxIntervals = MaxIntervals / 2;
		for (int i = 0; i < halfMaxIntervals; i++)
		{
			int iA = 2 * i;
			int iB = (2 * i) + 1;
			this.latencyMin[i] = combineLatency(this.latencyMin[iA], this.latencyMin[iB], Math.Min);
			this.latencyMax[i] = combineLatency(this.latencyMax[iA], this.latencyMax[iB], Math.Max);
			this.latencySum[i] = this.latencySum[iA] + this.latencySum[iB];
			this.latencyCount[i] = this.latencyCount[iA] + this.latencyCount[iB];
			this.bytesSent[i] = this.bytesSent[iA] + this.bytesSent[iB];
			this.bytesReceived[i] = this.bytesReceived[iA] + this.bytesReceived[iB];
		}

		Array.Clear(this.latencyMin, halfMaxIntervals, halfMaxIntervals);
		Array.Clear(this.latencyMax, halfMaxIntervals, halfMaxIntervals);
		Array.Clear(this.latencySum, halfMaxIntervals, halfMaxIntervals);
		Array.Clear(this.latencyCount, halfMaxIntervals, halfMaxIntervals);
		Array.Clear(this.bytesSent, halfMaxIntervals, halfMaxIntervals);
		Array.Clear(this.bytesReceived, halfMaxIntervals, halfMaxIntervals);

		this.interval *= 2;
	}

	public void Dispose()
	{
		this.disposed = true;

		// SemaphoreSlim.Dispose() is not thread-safe and may cause WaitAsync(CancellationToken) not being cancelled
		// when SemaphoreSlim.Dispose is invoked immediately after CancellationTokenSource.Cancel.
		// See https://github.com/dotnet/runtime/issues/59639
		// SemaphoreSlim.Dispose() only disposes it's wait handle, which is not initialized unless its AvailableWaitHandle
		// property is read, which we don't use.

		this.updateSemaphore.TryRelease();
	}

	/// <summary>
	/// Serializes the session contour into a compact form suitable for recording in
	/// logs or telemetry.
	/// </summary>
	/// <remarks>
	/// This compact serialization format uses one byte per metric per interval, so there is
	/// some loss of precision, but generally not so much that it affects a visualization. A
	/// scale factor for each metric is automatically determined and included in the serialized
	/// header. The size of the serialized encoded data will be a little under 7 bytes per
	/// interval. With the default interval maximum (256), that comes out to less than 1.75 KB.
	///
	/// Use the code in `SessionContour.kql` to decode and chart this output in
	/// Azure Data Explorer.
	/// </remarks>
	public string Export()
	{
		// Time and value scales are in log2 form, determined based on the maximum
		// value in each series. This allows for a reasonable range of precision for each
		// value (with byte values ranging from 0-255). For example a max latency in the
		// 500ms range will get a scale factor of 1 (because ceil(log2(500/255)) = 1), so
		// each serialized value (0-255) is half the actual value (0-510).
		Func<double, byte> getScale = (max) =>
			(byte)Math.Max(0, Math.Ceiling(Math.Log(max / byte.MaxValue, 2)));
		Func<double, byte, byte> applyReverseScale = (value, scale) =>
			(byte)Math.Round(value / Math.Pow(2, scale));

#pragma warning disable CA2002 // Do not lock on objects with weak identity
		lock (this)
#pragma warning restore CA2002 // Do not lock on objects with weak identity
		{
			var bytes = new byte[3 + ((2 + IntervalCount) * 5)];

			const byte version = 1;
			byte timeScale = (byte)Math.Log(this.interval / InitialInterval, 2);

			bytes[0] = version;
			bytes[1] = 5; // Number of metrics per interval
			bytes[2] = timeScale;

			bytes[3] = getScale(LatencyMinMs.Max());
			bytes[4] = getScale(LatencyMaxMs.Max());
			bytes[5] = getScale(LatencyAverageMs.Max());
			bytes[6] = getScale(BytesSent.Max());
			bytes[7] = getScale(BytesReceived.Max());

			bytes[8] = (byte)SessionMetric.LatencyMin;
			bytes[9] = (byte)SessionMetric.LatencyMax;
			bytes[10] = (byte)SessionMetric.LatencyAverage;
			bytes[11] = (byte)SessionMetric.BytesSent;
			bytes[12] = (byte)SessionMetric.BytesReceived;

			for (int i = 0; i < IntervalCount; i++)
			{
				var offset = 13 + (5 * i);
				bytes[offset + 0] = applyReverseScale(LatencyMinMs[i], bytes[3]);
				bytes[offset + 1] = applyReverseScale(LatencyMaxMs[i], bytes[4]);
				bytes[offset + 2] = applyReverseScale(LatencyAverageMs[i], bytes[5]);
				bytes[offset + 3] = applyReverseScale(BytesSent[i], bytes[6]);
				bytes[offset + 4] = applyReverseScale(BytesReceived[i], bytes[7]);
			}

			return Convert.ToBase64String(bytes);
		}
	}

	/// <summary>
	/// Deserializes a session contour that was previously exported.
	/// </summary>
	/// <remarks>
	/// Due to loss in precision, some values in the deserialized contour will not exactly match
	/// the original, but they will be close.
	/// </remarks>
	public static SessionContour Import(string contourBase64)
	{
		var bytes = Convert.FromBase64String(contourBase64);
		if (bytes.Length < 3)
		{
			throw new FormatException("Invalid session contour string.");
		}

		byte version = bytes[0];
		byte metricsPerInterval = bytes[1];
		byte timeScale = bytes[2];

		if (version != 1)
		{
			throw new FormatException($"Unsupported session contour version: {version}");
		}

		int intervalCount = ((bytes.Length - 3) / metricsPerInterval) - 2;
		if (intervalCount < 1 || bytes.Length != (3 + (metricsPerInterval * (intervalCount + 2))))
		{
			throw new FormatException($"Incomplete session contour string.");
		}

		int maxIntervals = (int)Math.Pow(2, Math.Ceiling(Math.Log(intervalCount, 2)));
		var sessionContour = new SessionContour(maxIntervals);
		sessionContour.interval = (long)Math.Pow(2, timeScale) * InitialInterval;
		sessionContour.IntervalCount = intervalCount;

		var scales = new int[metricsPerInterval];
		for (int m = 0; m < metricsPerInterval; m++)
		{
			scales[m] = (int)Math.Pow(2, bytes[3 + m]);
		}

		var ids = new SessionMetric[metricsPerInterval];
		for (int m = 0; m < metricsPerInterval; m++)
		{
			ids[m] = (SessionMetric)bytes[3 + metricsPerInterval + m];
		}

		for (int i = 0; i < intervalCount; i++)
		{
			int offset = 3 + ((2 + i) * metricsPerInterval);
			for (int m = 0; m < metricsPerInterval; m++)
			{
				switch (ids[m])
				{
					case SessionMetric.LatencyMin:
						sessionContour.latencyMin[i] = bytes[offset + m] * scales[m];
						break;
					case SessionMetric.LatencyMax:
						sessionContour.latencyMax[i] = bytes[offset + m] * scales[m];
						break;
					case SessionMetric.LatencyAverage:
						sessionContour.latencySum[i] = bytes[offset + m] * scales[m];
						sessionContour.latencyCount[i] = bytes[offset + m] == 0 ? 0 : 1;
						break;
					case SessionMetric.BytesSent:
						sessionContour.bytesSent[i] = bytes[offset + m] * (long)scales[m];
						break;
					case SessionMetric.BytesReceived:
						sessionContour.bytesReceived[i] = bytes[offset + m] * (long)scales[m];
						break;
					default:
						// Ignore any unknown metrics
						break;
				}
			}
		}

		return sessionContour;
	}

	/// <summary>
	/// Identifies a series of values in the exported format, and enables adding new
	/// series without breaking existing deserialization code.
	/// </summary>
	private enum SessionMetric : byte
	{
		None = 0,

		LatencyMin = 1,
		LatencyMax = 2,
		LatencyAverage = 3,

		BytesSent = 11,
		BytesReceived = 12,
	}

	private struct ContourUpdate
	{
		public long Time { get; set; }
		public int BytesSent { get; set; }
		public int BytesReceived { get; set; }
		public float Latency { get; set; }
	}

	private class ContourList<T> : IReadOnlyList<T>
	{
		private readonly Func<int> getCount;
		private readonly Func<int, T> getValue;

		public ContourList(Func<int> getCount, Func<int, T> getValue)
		{
			this.getCount = getCount;
			this.getValue = getValue;
		}

		public T this[int index] => this.getValue(index);

		public int Count => this.getCount();

		public IEnumerator<T> GetEnumerator()
		{
			int count = this.getCount();
			for (int i = 0; i < count; i++)
			{
				yield return this.getValue(i);
			}
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			int count = this.getCount();
			for (int i = 0; i < count; i++)
			{
				yield return this.getValue(i);
			}
		}
	}
}
