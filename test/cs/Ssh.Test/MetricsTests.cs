using Microsoft.DevTunnels.Ssh.Metrics;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class MetricsTests : IDisposable
{
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

	private static readonly BindingFlags PrivateInstanceBinding =
		BindingFlags.NonPublic | BindingFlags.Instance;
	private static readonly MethodInfo SessionContourOnMessageSentMethod =
		typeof(SessionContour).GetMethod("OnMessageSent", PrivateInstanceBinding);
	private static readonly MethodInfo SessionContourOnMessageReceivedMethod =
		typeof(SessionContour).GetMethod("OnMessageReceived", PrivateInstanceBinding);
	private static readonly MethodInfo SessionContourOnLatencyUpdatedMethod =
		typeof(SessionContour).GetMethod("OnLatencyUpdated", PrivateInstanceBinding);
	private static readonly MethodInfo SessionContourSessionClosedMethod =
		typeof(SessionContour).GetMethod("OnSessionClosed", PrivateInstanceBinding);

	private SessionPair sessionPair;
	private SshServerSession serverSession;
	private SshClientSession clientSession;
	private SessionContour sessionContour;

	public MetricsTests()
	{
		InitializeSessionPair();
	}

	private void InitializeSessionPair()
	{
		var serverConfig = SshSessionConfiguration.DefaultWithReconnect;
		var clientConfig = SshSessionConfiguration.DefaultWithReconnect;

		var reconnectableSessions = new List<SshServerSession>();
		this.sessionPair = new SessionPair(serverConfig, clientConfig, reconnectableSessions);
		this.serverSession = this.sessionPair.ServerSession;
		this.clientSession = this.sessionPair.ClientSession;
		this.sessionContour = new SessionContour(4);
	}

	public void Dispose()
	{
		this.sessionPair.Dispose();
	}

	[Fact]
	public async Task MeasureChannelBytes()
	{
		var channels = await OpenClientChannelAsync();

		byte[][] data = new[] { new byte[] { 1 }, new byte[] { 1, 2, 3 } };
		await SendDataBetweenChannelsAsync(data, channels.Client, channels.Server);

		Assert.Equal(4, channels.Client.Metrics.BytesSent);
		Assert.Equal(0, channels.Client.Metrics.BytesReceived);
		Assert.Equal(0, channels.Server.Metrics.BytesSent);
		Assert.Equal(4, channels.Server.Metrics.BytesReceived);
	}

	[Fact]
	public async Task MeasureSessionBytes()
	{
		var channels = await OpenClientChannelAsync();

		var initialClientBytesSent = this.clientSession.Metrics.BytesSent;
		var initialClientBytesReceived = this.clientSession.Metrics.BytesReceived;
		var initialServerBytesSent = this.serverSession.Metrics.BytesSent;
		var initialServerBytesReceived = this.serverSession.Metrics.BytesReceived;
		Assert.NotEqual(0, initialClientBytesSent);
		Assert.NotEqual(0, initialClientBytesReceived);
		Assert.NotEqual(0, initialServerBytesSent);
		Assert.NotEqual(0, initialServerBytesReceived);

		byte[][] data = new[] { new byte[] { 1 }, new byte[] { 1, 2, 3 } };
		await SendDataBetweenChannelsAsync(data, channels.Client, channels.Server);

		Assert.True(this.clientSession.Metrics.BytesSent > initialClientBytesSent);
		Assert.Equal(initialClientBytesReceived, this.clientSession.Metrics.BytesReceived);
		Assert.Equal(initialServerBytesSent, this.serverSession.Metrics.BytesSent);
		Assert.True(this.serverSession.Metrics.BytesReceived > initialServerBytesReceived);
	}

	[Fact]
	public async Task MeasureSessionMessages()
	{
		var channels = await OpenClientChannelAsync();

		var initialClientMessagesSent = this.clientSession.Metrics.MessagesSent;
		var initialClientMessagesReceived = this.clientSession.Metrics.MessagesReceived;
		var initialServerMessagesSent = this.serverSession.Metrics.MessagesSent;
		var initialServerMessagesReceived = this.serverSession.Metrics.MessagesReceived;
		Assert.NotEqual(0, initialClientMessagesSent);
		Assert.NotEqual(0, initialClientMessagesReceived);
		Assert.NotEqual(0, initialServerMessagesSent);
		Assert.NotEqual(0, initialServerMessagesReceived);

		byte[][] data = new[] { new byte[] { 1 }, new byte[] { 1, 2, 3 } };
		await SendDataBetweenChannelsAsync(data, channels.Client, channels.Server);

		Assert.True(this.clientSession.Metrics.MessagesSent > initialClientMessagesSent);
		Assert.Equal(initialClientMessagesReceived, this.clientSession.Metrics.MessagesReceived);
		Assert.Equal(initialServerMessagesSent, this.serverSession.Metrics.MessagesSent);
		Assert.True(this.serverSession.Metrics.MessagesReceived > initialServerMessagesReceived);
	}

	[Fact]
	public async Task MeasureSessionLatency()
	{
		var channels = await OpenClientChannelAsync();
		byte[][] data = new[] { new byte[] { 1 } };
		await SendDataBetweenChannelsAsync(data, channels.Client, channels.Server);
		await SendDataBetweenChannelsAsync(data, channels.Server, channels.Client);

		void ValidateLatency(SessionMetrics metrics)
		{
			Assert.NotEqual(0, metrics.LatencyMaxMs);
			Assert.NotEqual(0, metrics.LatencyAverageMs);
			Assert.NotEqual(0, metrics.LatencyMinMs);
			Assert.NotEqual(0, metrics.LatencyCurrentMs);
			Assert.True(metrics.LatencyMinMs <= metrics.LatencyAverageMs);
			Assert.True(metrics.LatencyAverageMs <= metrics.LatencyMaxMs);
		}

		ValidateLatency(this.clientSession.Metrics);
		ValidateLatency(this.serverSession.Metrics);
	}

	[Fact]
	public async Task ClosedSessionHasNoLatency()
	{
		await OpenClientChannelAsync();

		await this.clientSession.CloseAsync(SshDisconnectReason.ByApplication);
		await this.serverSession.CloseAsync(SshDisconnectReason.ByApplication);

		await TaskExtensions.WaitUntil(() =>
			this.clientSession.Metrics.LatencyCurrentMs == 0 &&
			this.serverSession.Metrics.LatencyCurrentMs == 0).WithTimeout(Timeout);
	}

	[Fact]
	public async Task RecordSessionContour()
	{
		var clientContour = new SessionContour(256);
		var serverContour = new SessionContour(256);

		var clientContourTask = clientContour.CollectMetricsAsync(this.clientSession.Metrics);
		var serverContourTask = serverContour.CollectMetricsAsync(this.serverSession.Metrics);

		void ValidateContour(SessionContour contour)
		{
			// Normally the interval should be 1 second, but tests tests need to work
			// on very slow build machines where the interval could grow larger.
			Assert.Contains(
				contour.Interval,
				new[] { TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4) });

			Assert.NotEqual(0, contour.IntervalCount);
			Assert.NotEqual(0, contour.LatencyMinMs.Sum());
			Assert.NotEqual(0, contour.LatencyMaxMs.Sum());
			Assert.NotEqual(0, contour.LatencyAverageMs.Sum());
			Assert.NotEqual(0, contour.BytesSent.Sum());
			Assert.NotEqual(0, contour.BytesReceived.Sum());

			for (int i = 0; i < contour.IntervalCount; i++)
			{
				Assert.True(contour.LatencyMinMs[i] <= contour.LatencyAverageMs[i]);
				Assert.True(contour.LatencyAverageMs[i] <= contour.LatencyMaxMs[i]);
			}
		}

		var channels = await OpenClientChannelAsync();

		await Task.Delay(TimeSpan.FromSeconds(1));
		byte[][] data = new[] { new byte[] { 1 } };
		await SendDataBetweenChannelsAsync(data, channels.Client, channels.Server);
		await SendDataBetweenChannelsAsync(data, channels.Server, channels.Client);
		await Task.Delay(TimeSpan.FromSeconds(1));
		await SendDataBetweenChannelsAsync(data, channels.Client, channels.Server);
		await SendDataBetweenChannelsAsync(data, channels.Server, channels.Client);
		await Task.Delay(TimeSpan.FromSeconds(1));
		await SendDataBetweenChannelsAsync(data, channels.Client, channels.Server);
		await SendDataBetweenChannelsAsync(data, channels.Server, channels.Client);

		await WaitForContourUpdateAsync(clientContour, clientContourTask);
		await WaitForContourUpdateAsync(serverContour, serverContourTask);

		ValidateContour(clientContour);
		ValidateContour(serverContour);
	}

	[Fact]
	public async Task ExpandContourIntervals()
	{
		var session = new SshClientSession(
			SshSessionConfiguration.Default, new TraceSource(nameof(MetricsTests)));
		var metrics = session.Metrics;

		var updateTask = this.sessionContour.CollectMetricsAsync(metrics);
		Assert.Equal(TimeSpan.FromSeconds(1), this.sessionContour.Interval);
		AddMessageReceived(2_000, 2);
		UpdateLatency(3_000, 16);
		UpdateLatency(3_500, 32);
		AddMessageSent(3_800, 1);
		AddMessageReceived(3_900, 3);
		await WaitForContourUpdateAsync(this.sessionContour, updateTask);
		Assert.Equal(TimeSpan.FromSeconds(1), this.sessionContour.Interval);
		Assert.Equal(new float[] { 0, 0, 0, 16 }, this.sessionContour.LatencyMinMs);
		Assert.Equal(new float[] { 0, 0, 0, 32 }, this.sessionContour.LatencyMaxMs);
		Assert.Equal(new float[] { 0, 0, 0, 24 }, this.sessionContour.LatencyAverageMs);
		Assert.Equal(new long[] { 0, 0, 0, 1 }, this.sessionContour.BytesSent);
		Assert.Equal(new long[] { 0, 0, 2, 3 }, this.sessionContour.BytesReceived);
		updateTask = this.sessionContour.CollectMetricsAsync(metrics);
		AddMessageSent(4_000, 1);
		UpdateLatency(4_500, 32);
		UpdateLatency(4_600, 16);
		await WaitForContourUpdateAsync(this.sessionContour, updateTask);
		Assert.Equal(TimeSpan.FromSeconds(2), this.sessionContour.Interval);
		Assert.Equal(new float[] { 0, 16, 16 }, this.sessionContour.LatencyMinMs);
		Assert.Equal(new float[] { 0, 32, 32 }, this.sessionContour.LatencyMaxMs);
		Assert.Equal(new float[] { 0, 24, 24 }, this.sessionContour.LatencyAverageMs);
		Assert.Equal(new long[] { 0, 1, 1 }, this.sessionContour.BytesSent);
		Assert.Equal(new long[] { 0, 5, 0 }, this.sessionContour.BytesReceived);
		updateTask = this.sessionContour.CollectMetricsAsync(metrics);
		AddMessageSent(8_000, 1);
		UpdateLatency(8_100, 32);
		AddMessageSent(12_000, 2);
		UpdateLatency(12_500, 64);
		await WaitForContourUpdateAsync(this.sessionContour, updateTask);
		Assert.Equal(TimeSpan.FromSeconds(4), this.sessionContour.Interval);
		Assert.Equal(new float[] { 16, 16, 32, 64 }, this.sessionContour.LatencyMinMs);
		Assert.Equal(new float[] { 32, 32, 32, 64 }, this.sessionContour.LatencyMaxMs);
		Assert.Equal(new float[] { 24, 24, 32, 64 }, this.sessionContour.LatencyAverageMs);
		Assert.Equal(new long[] { 1, 1, 1, 2 }, this.sessionContour.BytesSent);
		Assert.Equal(new long[] { 5, 0, 0, 0 }, this.sessionContour.BytesReceived);
		updateTask = this.sessionContour.CollectMetricsAsync(metrics);
		AddMessageSent(16_000, 10);
		await WaitForContourUpdateAsync(this.sessionContour, updateTask);
		Assert.Equal(TimeSpan.FromSeconds(8), this.sessionContour.Interval);
		Assert.Equal(new float[] { 16, 32, 0 }, this.sessionContour.LatencyMinMs);
		Assert.Equal(new float[] { 32, 64, 0 }, this.sessionContour.LatencyMaxMs);
		Assert.Equal(new float[] { 24, 48, 0 }, this.sessionContour.LatencyAverageMs);
		Assert.Equal(new long[] { 2, 3, 10 }, this.sessionContour.BytesSent);
		Assert.Equal(new long[] { 5, 0, 0 }, this.sessionContour.BytesReceived);
	}

	[Fact]
	public async Task ExportImportContour()
	{
		var session = new SshClientSession(
			SshSessionConfiguration.Default, new TraceSource(nameof(MetricsTests)));
		var metrics = session.Metrics;

		var updateTask = this.sessionContour.CollectMetricsAsync(metrics);
		AddMessageReceived(0, 2000);
		UpdateLatency(2_000, 16);
		UpdateLatency(3_000, 32);
		AddMessageSent(3_600, 1000);
		AddMessageReceived(3_800, 3000);
		AddMessageSent(4_000, 1);
		UpdateLatency(5_000, 32);
		UpdateLatency(5_200, 16);
		await WaitForContourUpdateAsync(this.sessionContour, updateTask);
		Assert.Equal(TimeSpan.FromSeconds(2), this.sessionContour.Interval);

		var result = this.sessionContour.Export();
		var resultBytes = Convert.FromBase64String(result);

		Assert.Equal(string.Join(" ", new byte[]
		{
				1,  // version
				5,  // metric count
				1,  // timeScale
				0,  // \
				0,  //  \
				0,  //   } value scales
				2,  //  /
				4,  // /
				1,  // \
				2,  //  \
				3,  //   } metric IDs
				11, //  /
				12, // /
				0,  // \
				0,  //  \
				0,  //   } interval 0
				0,  //  /
				125,// /
				16, // \
				32, //  \
				24, //   } interval 1
				250,//  /
				188,// /
				16, // \
				32, //  \
				24, //   } interval 2
				0,  //  /
				0,  // /
		}), string.Join(" ", resultBytes));

		var sessionContour2 = SessionContour.Import(result);
		Assert.Equal(3, sessionContour2.IntervalCount);
		Assert.Equal(TimeSpan.FromSeconds(2), sessionContour2.Interval);

		var result2 = sessionContour2.Export();
		var result2Bytes = Convert.FromBase64String(result2);
		Assert.Equal(string.Join(" ", resultBytes), string.Join(" ", result2Bytes));
	}

	private void AddMessageSent(long time, int size)
	{
		SessionContourOnMessageSentMethod.Invoke(
			this.sessionContour, new object[] { null, (time, size) });
	}

	private void AddMessageReceived(long time, int size)
	{
		SessionContourOnMessageReceivedMethod.Invoke(
			this.sessionContour, new object[] { null, (time, size) });
	}

	private void UpdateLatency(long time, float latency)
	{
		SessionContourOnLatencyUpdatedMethod.Invoke(
			this.sessionContour, new object[] { null, (time, latency) });
	}

	private async Task WaitForContourUpdateAsync(SessionContour sessionContour, Task t)
	{
		SessionContourSessionClosedMethod.Invoke(
			sessionContour, new object[] { null, EventArgs.Empty });
		await t.WithTimeout(Timeout);
	}

	private async Task<Channels> OpenClientChannelAsync()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var serverChannelTask = this.serverSession.AcceptChannelAsync();
		var clientChannel = await this.clientSession.OpenChannelAsync().WithTimeout(Timeout);
		var serverChannel = await serverChannelTask.WithTimeout(Timeout);

		return new Channels
		{
			Client = clientChannel,
			Server = serverChannel,
		};
	}

	private static async Task SendDataBetweenChannelsAsync(
		byte[][] data,
		SshChannel channelA,
		SshChannel channelB)
	{
		MemoryStream receivingStream = null;
		TaskCompletionSource<byte[]> receivedCompletion = null;
		int expectedDataLength = 0;

		EventHandler<Buffer> dataReceivedHandler = (sender, bytes) =>
		{
			receivingStream.Write(bytes.Array, bytes.Offset, bytes.Count);
			if (receivingStream.Length >= expectedDataLength)
			{
				receivedCompletion.SetResult(receivingStream.ToArray());
			}

			channelB.AdjustWindow((uint)bytes.Count);
		};
		channelB.DataReceived += dataReceivedHandler;

		for (int i = 0; i < data.Length; i++)
		{
			receivingStream = new MemoryStream();
			receivedCompletion = new TaskCompletionSource<byte[]>();
			expectedDataLength = data[i].Length;

			await channelA.SendAsync(data[i], CancellationToken.None);

			var receivedData = await receivedCompletion.Task.WithTimeout(
				TimeSpan.FromMilliseconds(4 * Timeout.TotalMilliseconds));
			Assert.Equal(data[i], receivedData);
		}

		channelB.DataReceived -= dataReceivedHandler;
	}

	[DebuggerStepThrough]
	private class Channels
	{
		public SshChannel Client { get; set; }
		public SshChannel Server { get; set; }
	}
}
