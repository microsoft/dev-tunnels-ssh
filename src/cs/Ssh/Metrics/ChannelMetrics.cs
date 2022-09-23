// Copyright (c) Microsoft. All rights reserved.

using System.Diagnostics;
using System.Threading;

namespace Microsoft.DevTunnels.Ssh.Metrics;

/// <summary>
/// Collects cumulative measurements about a channel.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
public sealed class ChannelMetrics
{
	private long bytesSent;
	private long bytesReceived;

	internal ChannelMetrics()
	{
	}

	/// <summary>
	/// Gets the total cumulative number of bytes sent for the duration of the channel,
	/// not including message framing, padding, and MAC bytes.
	/// </summary>
	public long BytesSent => this.bytesSent;

	/// <summary>
	/// Gets the total cumulative number of bytes received for the duration of the channel,
	/// not including message framing, padding, and MAC bytes.
	/// </summary>
	public long BytesReceived => this.bytesReceived;

	internal void AddBytesSent(long count)
	{
		Interlocked.Add(ref this.bytesSent, count);
	}

	internal void AddBytesReceived(long count)
	{
		Interlocked.Add(ref this.bytesReceived, count);
	}

	public override string ToString()
	{
		return $"Bytes S/R: {BytesSent} / {BytesReceived}; ";
	}
}
