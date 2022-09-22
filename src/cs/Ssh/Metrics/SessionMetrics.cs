// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Globalization;
using System.Threading;

namespace Microsoft.DevTunnels.Ssh.Metrics;

/// <summary>
/// Collects current and cumulative measurements about a session.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
public sealed class SessionMetrics
{
	// Latency is measured in microseconds, but reported in milliseconds.
	private const float MicrosecondsPerMillisecond = 1000.0f;

	private long messagesSent;
	private long messagesReceived;
	private long bytesSent;
	private long bytesReceived;
	private int reconnections;

	private int latencyCurrent;
	private int latencyMin;
	private int latencyMax;
	private long latencySum;
	private long latencyCount;

	private readonly Stopwatch stopwatch;

	internal SessionMetrics()
	{
		this.stopwatch = new Stopwatch();
		this.stopwatch.Start();
	}

	/// <summary>
	/// Gets the total cumulative number of messages sent for the duration of the session,
	/// including all channels and non-channel protocol messages.
	/// </summary>
	public long MessagesSent => this.messagesSent;

	/// <summary>
	/// Gets the total cumulative number of messages received for the duration of the session,
	/// including all channels and non-channel protocol messages.
	/// </summary>
	public long MessagesReceived => this.messagesReceived;

	/// <summary>
	/// Gets the total cumulative number of bytes sent for the duration of the session,
	/// including all channels and non-channel protocol messages, and including message
	/// framing, padding, and MAC bytes.
	/// </summary>
	public long BytesSent => this.bytesSent;

	/// <summary>
	/// Gets the total cumulative number of bytes received for the duration of the session,
	/// including all channels and non-channel protocol messages, and including message
	/// framing, padding, and MAC bytes.
	/// </summary>
	public long BytesReceived => this.bytesReceived;

	/// <summary>
	/// Gets the number of times the session has reconnected.
	/// </summary>
	/// <remarks>
	/// Reconnection requires both sides to support the
	/// <see cref="SshProtocolExtensionNames.SessionReconnect" /> protocol extension.
	/// </remarks>
	public int Reconnections => this.reconnections;

	/// <summary>
	/// Gets the average measured round-trip connection latency between client and server
	/// over the duration of the session, in milliseconds.
	/// </summary>
	/// <remarks>
	/// Latency measurement requires both sides to support the
	/// <see cref="SshProtocolExtensionNames.SessionLatency" /> protocol extension.
	/// If not supported, this value will be 0.
	/// </remarks>
	public float LatencyAverageMs => this.latencyCount == 0 ? 0 :
		this.latencySum / this.latencyCount / MicrosecondsPerMillisecond;

	/// <summary>
	/// Gets the minimum measured round-trip connection latency between client and server
	/// over the duration of the session, in milliseconds.
	/// </summary>
	/// <remarks>
	/// Latency measurement requires both sides to support the
	/// <see cref="SshProtocolExtensionNames.SessionLatency" /> protocol extension.
	/// If not supported, this value will be 0.
	/// </remarks>
	public float LatencyMinMs => this.latencyMin / MicrosecondsPerMillisecond;

	/// <summary>
	/// Gets the maximum measured round-trip connection latency between client and server
	/// over the duration of the session, in milliseconds.
	/// </summary>
	/// <remarks>
	/// Latency measurement requires both sides to support the
	/// <see cref="SshProtocolExtensionNames.SessionLatency" /> protocol extension.
	/// If not supported, this value will be 0.
	/// </remarks>
	public float LatencyMaxMs => this.latencyMax / MicrosecondsPerMillisecond;

	/// <summary>
	/// Gets the most recent measurement of round-trip connection latency between client and
	/// server, in milliseconds.
	/// </summary>
	/// <remarks>
	/// Latency measurement requires both sides to support the
	/// <see cref="SshProtocolExtensionNames.SessionLatency" /> protocol extension.
	/// If not supported or the session is not currently connected, this value will be 0.
	/// </remarks>
	public float LatencyCurrentMs => this.latencyCurrent / MicrosecondsPerMillisecond;

	/// <summary>
	/// Event raised when a message is sent. The tuple is the session time in milliseconds
	/// and the size of the message in bytes.
	/// </summary>
	public event EventHandler<(long, int)>? MessageSent;

	/// <summary>
	/// Event raised when a message is sent. The tuple is the session time in milliseconds
	/// and the size of the message in bytes.
	/// </summary>
	public event EventHandler<(long, int)>? MessageReceived;

	/// <summary>
	/// Event raised when latency is measured. The tuple is the session time in milliseconds
	/// and the round-trip latency in milliseconds.
	/// </summary>
	public event EventHandler<(long, float)>? LatencyUpdated;

	/// <summary>
	/// Event raised when the session is closed, after which no further metrics will be reported.
	/// </summary>
	public event EventHandler? SessionClosed;

	/// <summary>
	/// Gets the elapsed session time in microseconds, used for measuring latency and
	/// recording metrics over time.
	/// </summary>
	internal long Time => this.stopwatch.ElapsedTicks * 1_000_000 / Stopwatch.Frequency;

	internal void AddMessageSent(int size)
	{
		Interlocked.Increment(ref this.messagesSent);
		Interlocked.Add(ref this.bytesSent, size);

		MessageSent?.Invoke(this, (this.stopwatch.ElapsedTicks / 10_000, size));
	}

	internal void AddMessageReceived(int size)
	{
		Interlocked.Increment(ref this.messagesReceived);
		Interlocked.Add(ref this.bytesReceived, size);

		MessageReceived?.Invoke(this, (this.stopwatch.ElapsedTicks / 10_000, size));
	}

	internal void AddReconnection()
	{
		Interlocked.Increment(ref this.reconnections);
	}

	internal void UpdateLatency(int latencyMicroseconds)
	{
		if (latencyMicroseconds < 0)
		{
			throw new ArgumentOutOfRangeException(
				nameof(latencyMicroseconds), "Measured latency cannot be negative.");
		}

		this.latencyCurrent = latencyMicroseconds;

		if (latencyMicroseconds == 0)
		{
			// Disconnected.
			return;
		}

		var currentMin = this.latencyMin;
		while (currentMin == 0 || latencyMicroseconds < currentMin)
		{
			Interlocked.CompareExchange(ref this.latencyMin, latencyMicroseconds, currentMin);
			currentMin = this.latencyMin;
		}

		var currentMax = this.latencyMax;
		while (latencyMicroseconds > currentMax)
		{
			Interlocked.CompareExchange(ref this.latencyMax, latencyMicroseconds, currentMax);
			currentMax = this.latencyMax;
		}

		// Enable computing the average.
		Interlocked.Add(ref this.latencySum, latencyMicroseconds);
		Interlocked.Increment(ref this.latencyCount);

		var latencyMilliseconds = latencyMicroseconds / MicrosecondsPerMillisecond;
		LatencyUpdated?.Invoke(this, (this.stopwatch.ElapsedTicks / 10_000, latencyMilliseconds));
	}

	internal void Close()
	{
		this.latencyCurrent = 0;
		SessionClosed?.Invoke(this, EventArgs.Empty);
	}

	public override string ToString()
	{
		var s =
			$"Messages S/R: {MessagesSent} / {MessagesReceived}; " +
			$"Bytes S/R: {BytesSent} / {BytesReceived}; " +
			$"Reconnections: {Reconnections}; ";

		// Show extra precision for a low-latency connection.
		var format = (this.latencyMin >= 10000 ? "F0" : this.latencyMin >= 1000 ? "F1" : "F2");

		if (this.latencyMax > 0)
		{
			s += string.Format(
				CultureInfo.InvariantCulture,
				$"Latency Min-Avg-Max: {{0:{format}}} - {{1:{format}}} - {{1:{format}}} ms; ",
				this.latencyMin / MicrosecondsPerMillisecond,
				(this.latencySum / this.latencyCount) / MicrosecondsPerMillisecond,
				this.latencyMax / MicrosecondsPerMillisecond);
		}

		if (this.latencyCurrent > 0)
		{
			s += string.Format(
				CultureInfo.InvariantCulture,
				$"Current Latency: {{0:{format}}} ms; ",
				this.latencyCurrent / MicrosecondsPerMillisecond);
		}

		return s;
	}
}
