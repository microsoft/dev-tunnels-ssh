using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.IO;
using Microsoft.DevTunnels.Ssh.Messages;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test
{
	public class PipeTests
	{
		private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

		private readonly SessionPair sessionPair1;
		private readonly SshClientSession clientSession1;
		private readonly SshServerSession serverSession1;
		private readonly SessionPair sessionPair2;
		private readonly SshClientSession clientSession2;
		private readonly SshServerSession serverSession2;

		public PipeTests()
		{
			var config = new SshSessionConfiguration();

			this.sessionPair1 = new SessionPair(config);
			this.clientSession1 = sessionPair1.ClientSession;
			this.serverSession1 = sessionPair1.ServerSession;
			this.sessionPair2 = new SessionPair(config);
			this.clientSession2 = sessionPair2.ClientSession;
			this.serverSession2 = sessionPair2.ServerSession;
		}

		private async Task ConnectSessions()
		{
			await Task.WhenAll(
				this.sessionPair1.ConnectAsync(true),
				this.sessionPair2.ConnectAsync(true));
		}

		[Theory]
		[InlineData(false)]
		[InlineData(true)]
		public async Task PipeChannelClose(bool closeTarget)
		{
			await this.ConnectSessions();
			var (clientChannel1, serverChannel1) = await this.sessionPair1.OpenChannelAsync();
			var (clientChannel2, serverChannel2) = await this.sessionPair2.OpenChannelAsync();
			var pipeTask = serverChannel1.PipeAsync(serverChannel2);

			var closedCompletion = new TaskCompletionSource<SshChannelClosedEventArgs>();
			(closeTarget ? clientChannel1 : clientChannel2).Closed +=
				(sender, e) => closedCompletion.TrySetResult(e);
			await (closeTarget ? clientChannel2 : clientChannel1).CloseAsync();
			await closedCompletion.Task.WithTimeout(Timeout);
			await pipeTask.WithTimeout(Timeout);
		}

		[Theory]
		[InlineData(false)]
		[InlineData(true)]
		public async Task PipeChannelSend(bool fromTarget)
		{
			await this.ConnectSessions();
			var (clientChannel1, serverChannel1) = await this.sessionPair1.OpenChannelAsync();
			var (clientChannel2, serverChannel2) = await this.sessionPair2.OpenChannelAsync();
			_ = serverChannel1.PipeAsync(serverChannel2);

			var testData = Buffer.From(Encoding.UTF8.GetBytes("test"));
			var dataCompletion = new TaskCompletionSource<Buffer>();
			(fromTarget ? clientChannel1 : clientChannel2).DataReceived +=
				(sender, data) => dataCompletion.TrySetResult(data.Copy());
			await (fromTarget ? clientChannel2 : clientChannel1).SendAsync(
				testData, CancellationToken.None);
			var receivedData = await dataCompletion.Task.WithTimeout(Timeout);
			Assert.True(receivedData.Equals(testData));
		}

		[Theory]
		[InlineData(false)]
		[InlineData(true)]
		public async Task PipeChannelSendSequence(bool fromTarget)
		{
			await this.ConnectSessions();
			var (clientChannel1, serverChannel1) = await this.sessionPair1.OpenChannelAsync();
			var (clientChannel2, serverChannel2) = await this.sessionPair2.OpenChannelAsync();
			_ = serverChannel1.PipeAsync(serverChannel2);

			int count = 1000;
			var receivedCompletion = new TaskCompletionSource<int>();
			int receivedCount = 0;
			(fromTarget ? clientChannel1 : clientChannel2).DataReceived += (sender, data) =>
			{
				var expectedData = Buffer.From(Encoding.UTF8.GetBytes("test:" + receivedCount));
				Assert.True(data.Equals(expectedData));
				if (++receivedCount == count)
				{
					receivedCompletion.SetResult(count);
				}
				((SshChannel)sender).AdjustWindow((uint)data.Count);
			};

			for (int i = 0; i < count; i++)
			{
				var testData = Buffer.From(Encoding.UTF8.GetBytes("test:" + i));
				_ = (fromTarget ? clientChannel2 : clientChannel1).SendAsync(
					testData, CancellationToken.None);
			}

			await receivedCompletion.Task.WithTimeout(Timeout);
		}

		[Theory]
		[InlineData(false)]
		[InlineData(true)]
		public async Task PipeChannelSendLargeData(bool fromTarget)
		{
			await this.ConnectSessions();
			var (clientChannel1, serverChannel1) = await this.sessionPair1.OpenChannelAsync();
			var (clientChannel2, serverChannel2) = await this.sessionPair2.OpenChannelAsync();
			_ = serverChannel1.PipeAsync(serverChannel2);

			// Test data that is larger than the channel flow-control window size (1MB).
			const int largeDataSize = 1024 * 1024 * 7 / 2;
			byte[] largeData = new byte[largeDataSize];
			for (int i = 0; i < largeData.Length; i++) largeData[i] = (byte)(i & 0xFF);

			var receivingStream = new MemoryStream();
			var receivedCompletion = new TaskCompletionSource<byte[]>();

			(fromTarget ? clientChannel1 : clientChannel2).DataReceived += (sender, data) =>
			{
				receivingStream.Write(data.Array, data.Offset, data.Count);
				if (receivingStream.Length >= largeDataSize)
				{
					receivedCompletion.SetResult(receivingStream.ToArray());
				}

				((SshChannel)sender).AdjustWindow((uint)data.Count);
			};

			await (fromTarget ? clientChannel2 : clientChannel1).SendAsync(
				largeData, CancellationToken.None).WithTimeout(Timeout);
			var receivedData = await receivedCompletion.Task.WithTimeout(Timeout);
			Assert.True(Buffer.From(receivedData).Equals(largeData));
		}

		[Fact]
		public async Task PipeChannelPendingRequest()
		{
			await this.ConnectSessions();
			var (clientChannel1, serverChannel1) = await this.sessionPair1.OpenChannelAsync();
			var (clientChannel2, serverChannel2) = await this.sessionPair2.OpenChannelAsync();
			_ = serverChannel1.PipeAsync(clientChannel2);

			var firstRequest = new ChannelRequestMessage { RequestType = "first", WantReply = true };
			var secondRequest = new ChannelRequestMessage { RequestType = "second", WantReply = true };
			TaskCompletionSource<bool> secondMessageCompletion = new TaskCompletionSource<bool>();
			TaskCompletionSource<bool> firstMessageCompletion = new TaskCompletionSource<bool>();
			var responseTask = async (SshRequestEventArgs<ChannelRequestMessage> e) =>
			{
				if (e.Request.RequestType == "second")
				{
					secondMessageCompletion.SetResult(true);
				}
				else
				{
					firstMessageCompletion.SetResult(true);
					await secondMessageCompletion.Task;
				}
				return new ChannelSuccessMessage() as SshMessage;
			};
			serverChannel2.Request += (sender, e) =>
			{
				e.ResponseTask = responseTask(e);
			};
			var firstTask = clientChannel1.RequestAsync(
				firstRequest, CancellationToken.None);
			await clientChannel1.RequestAsync(
				secondRequest, CancellationToken.None);
			await firstTask;
			Assert.True(await secondMessageCompletion.Task);
			Assert.True(await firstMessageCompletion.Task);
		}

		[Theory]
		[InlineData(false)]
		[InlineData(true)]
		public async Task PipeSessionClose(bool closeTarget)
		{
			await this.ConnectSessions();
			var pipeTask = this.sessionPair1.ServerSession.PipeAsync(this.sessionPair2.ServerSession);

			var closedCompletion = new TaskCompletionSource<SshSessionClosedEventArgs>();
			(closeTarget ? this.sessionPair1.ClientSession : this.sessionPair2.ClientSession).Closed +=
				(sender, e) => closedCompletion.TrySetResult(e);
			await (closeTarget ? this.sessionPair2.ClientSession : this.sessionPair1.ClientSession)
				.CloseAsync(SshDisconnectReason.ByApplication);

			var closedEvent = await closedCompletion.Task.WithTimeout(Timeout);
			Assert.Equal(SshDisconnectReason.ByApplication, closedEvent.Reason);
			await pipeTask.WithTimeout(Timeout);
		}

		[Theory]
		[InlineData(false)]
		[InlineData(true)]
		public async Task PipeSessionChannelOpen(bool fromTarget)
		{
			await this.ConnectSessions();
			_ = this.sessionPair1.ServerSession.PipeAsync(this.sessionPair2.ServerSession);

			var channelTask =
				(fromTarget ? this.sessionPair1.ClientSession : this.sessionPair2.ClientSession)
				.AcceptChannelAsync("test");
			_ = await (fromTarget ? this.sessionPair2.ClientSession : this.sessionPair1.ClientSession)
				.OpenChannelAsync("test").WithTimeout(Timeout);
			var channel = await channelTask.WithTimeout(Timeout);
			Assert.Equal("test", channel.ChannelType);
		}

		[Theory]
		[InlineData(false)]
		[InlineData(true)]
		public async Task PipeSessionChannelOpenAndClose(bool fromTarget)
		{
			await this.ConnectSessions();
			_ = this.sessionPair1.ServerSession.PipeAsync(this.sessionPair2.ServerSession);

			var channelTask =
				(fromTarget ? this.sessionPair1.ClientSession : this.sessionPair2.ClientSession)
				.AcceptChannelAsync();
			var channelA = await
				(fromTarget ? this.sessionPair2.ClientSession : this.sessionPair1.ClientSession)
				.OpenChannelAsync().WithTimeout(Timeout);
			var channelB = await channelTask.WithTimeout(Timeout);

			var closedCompletion = new TaskCompletionSource<SshChannelClosedEventArgs>();
			(fromTarget ? channelA : channelB).Closed +=
				(sender, e) => closedCompletion.TrySetResult(e);
			await (fromTarget ? channelB : channelA).CloseAsync();
			await closedCompletion.Task.WithTimeout(Timeout);
		}

		[Theory]
		[InlineData(false)]
		[InlineData(true)]
		public async Task PipeSessionChannelSend(bool fromTarget)
		{
			await this.ConnectSessions();
			_ = this.sessionPair1.ServerSession.PipeAsync(this.sessionPair2.ServerSession);

			var channelTask =
				(fromTarget ? this.sessionPair1.ClientSession : this.sessionPair2.ClientSession)
				.AcceptChannelAsync();
			var channelA = await
				(fromTarget ? this.sessionPair2.ClientSession : this.sessionPair1.ClientSession)
				.OpenChannelAsync().WithTimeout(Timeout);
			var channelB = await channelTask.WithTimeout(Timeout);

			var testData = Buffer.From(Encoding.UTF8.GetBytes("test"));
			var dataCompletion = new TaskCompletionSource<Buffer>();
			channelB.DataReceived += (sender, data) =>
			{
				dataCompletion.TrySetResult(data.Copy());
			};
			await channelA.SendAsync(testData, CancellationToken.None);
			var receivedData = await dataCompletion.Task.WithTimeout(Timeout);
			Assert.True(receivedData.Equals(testData));
		}

		[Fact]
		public async Task PipeExtensibleSessionRequest()
		{
			await this.ConnectSessions();
			_ = this.sessionPair1.ServerSession.PipeAsync(this.sessionPair2.ServerSession);

			var client1 = this.sessionPair1.ClientSession;
			var client2 = this.sessionPair2.ClientSession;

			var requestCompletion = new TaskCompletionSource<SessionRequestMessage>();
			client2.Request += (sender, e) =>
			{
				requestCompletion.TrySetResult(e.Request);
				e.ResponseTask = Task.FromResult<SshMessage>(new TestSessionRequestSuccessMessage());
			};

			var requestTask = client1.RequestAsync<TestSessionRequestSuccessMessage>(
				new TestSessionRequestMessage { RequestType = "test" }, CancellationToken.None);

			var testRequest = await requestCompletion.Task.WithTimeout(Timeout);
			Assert.Equal("test", testRequest.RequestType);
			testRequest.ConvertTo<TestSessionRequestMessage>();

			var testResponse = await requestTask;
			Assert.NotNull(testResponse);
		}

		[Fact]
		public async Task PipeSessionPendingRequest()
		{
			await this.ConnectSessions();
			_ = this.sessionPair1.ServerSession.PipeAsync(this.sessionPair2.ClientSession);

			var firstRequest = new SessionRequestMessage { RequestType = "first", WantReply = true };
			var secondRequest = new SessionRequestMessage { RequestType = "second", WantReply = true };
			TaskCompletionSource<bool> secondMessageCompletion = new TaskCompletionSource<bool>();
			TaskCompletionSource<bool> firstMessageCompletion = new TaskCompletionSource<bool>();
			var responseTask = async (SshRequestEventArgs<SessionRequestMessage> e) =>
			{
				if (e.Request.RequestType == "second")
				{
					secondMessageCompletion.SetResult(true);
				}
				else
				{
					firstMessageCompletion.SetResult(true);
					await secondMessageCompletion.Task;
				}
				return new SessionRequestSuccessMessage() as SshMessage;
			};
			this.sessionPair2.ServerSession.Request += (sender, e) =>
			{
				e.ResponseTask = responseTask(e);
			};
			var firstTask = this.sessionPair1.ClientSession.RequestAsync(
				firstRequest, CancellationToken.None);
			await this.sessionPair1.ClientSession.RequestAsync(
				secondRequest, CancellationToken.None);
			await firstTask;
			Assert.True(await secondMessageCompletion.Task);
			Assert.True(await firstMessageCompletion.Task);
		}

		[Fact]
		public async Task PipeExtensibleChannelOpen()
		{
			await this.ConnectSessions();
			_ = this.sessionPair1.ServerSession.PipeAsync(this.sessionPair2.ServerSession);

			var requestCompletion = new TaskCompletionSource<ChannelOpenMessage>();
			var channelCompletion = new TaskCompletionSource<SshChannel>();
			this.sessionPair2.ClientSession.ChannelOpening += (sender, e) =>
			{
				requestCompletion.TrySetResult(e.Request);
				channelCompletion.TrySetResult(e.Channel);
			};

			var openTask = this.sessionPair1.ClientSession.OpenChannelAsync(
				new TestChannelOpenMessage { ChannelType = "test" }, null).WithTimeout(Timeout);

			var testRequest = await requestCompletion.Task.WithTimeout(Timeout);
			testRequest.ConvertTo<TestChannelOpenMessage>();

			var channel1 = await openTask.WithTimeout(Timeout);
			Assert.Equal("test", channel1.ChannelType);

			var channel2 = await channelCompletion.Task;
			Assert.Equal("test", channel2.ChannelType);
		}

		[Theory]
		[InlineData(false)]
		[InlineData(true)]
		public async Task PipeExtensibleChannelRequest(bool withChannelIdMapping)
		{
			await this.ConnectSessions();

			if (withChannelIdMapping)
			{
				// Open a channel BEFORE piping, so that the channel IDs will not be in sync.
				// Channel piping should support re-mapping channel IDs.
				_ = await this.sessionPair1.ClientSession.OpenChannelAsync();
			}

			_ = this.sessionPair1.ServerSession.PipeAsync(this.sessionPair2.ServerSession);

			var acceptTask = this.sessionPair2.ClientSession.AcceptChannelAsync("test");
			var channel1 = await this.sessionPair1.ClientSession.OpenChannelAsync("test")
				.WithTimeout(Timeout);
			var channel2 = await acceptTask.WithTimeout(Timeout);

			var requestCompletion = new TaskCompletionSource<ChannelRequestMessage>();
			channel2.Request += (sender, e) =>
			{
				requestCompletion.TrySetResult(e.Request);
				e.IsAuthorized = true;
			};

			var requestTask = channel1.RequestAsync(
				new TestChannelRequestMessage { RequestType = "test" });

			var request = await requestCompletion.Task.WithTimeout(Timeout);
			Assert.Equal("test", request.RequestType);
			request.ConvertTo<TestChannelRequestMessage>();

			var result = await requestTask.WithTimeout(Timeout);
			Assert.True(result);
		}

		private class TestSessionRequestMessage : SessionRequestMessage
		{
			protected override void OnWrite(ref SshDataWriter writer)
			{
				base.OnWrite(ref writer);
				writer.Write((uint)1);
			}

			protected override void OnRead(ref SshDataReader reader)
			{
				base.OnRead(ref reader);
				Assert.Equal((uint)1, reader.ReadUInt32());
			}
		}

		private class TestSessionRequestSuccessMessage : SessionRequestSuccessMessage
		{
			protected override void OnWrite(ref SshDataWriter writer)
			{
				base.OnWrite(ref writer);
				writer.Write((uint)1);
			}

			protected override void OnRead(ref SshDataReader reader)
			{
				base.OnRead(ref reader);
				Assert.Equal((uint)1, reader.ReadUInt32());
			}
		}

		private class TestChannelOpenMessage : ChannelOpenMessage
		{
			protected override void OnWrite(ref SshDataWriter writer)
			{
				base.OnWrite(ref writer);
				writer.Write((uint)1);
			}

			protected override void OnRead(ref SshDataReader reader)
			{
				base.OnRead(ref reader);
				Assert.Equal((uint)1, reader.ReadUInt32());
			}
		}

		private class TestChannelRequestMessage : ChannelRequestMessage
		{
			protected override void OnWrite(ref SshDataWriter writer)
			{
				base.OnWrite(ref writer);
				writer.Write((uint)1);
			}

			protected override void OnRead(ref SshDataReader reader)
			{
				base.OnRead(ref reader);
				Assert.Equal((uint)1, reader.ReadUInt32());
			}
		}
	}
}
