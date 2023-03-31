using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class ChannelTests : IDisposable
{
	private const int WindowSize = 1024 * 1024;
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
	private static readonly TimeSpan LongTimeout = TimeSpan.FromSeconds(100);
	private readonly CancellationToken timeoutToken = Debugger.IsAttached ? CancellationToken.None : new CancellationTokenSource(Timeout).Token;

	private SshSessionConfiguration serverConfig;
	private SshSessionConfiguration clientConfig;
	private SessionPair sessionPair;
	private SshServerSession serverSession;
	private SshClientSession clientSession;

	public ChannelTests()
	{
		InitializeSessionPair(true, true);
	}

	private void InitializeSessionPair(
		bool useServerExtensions, bool useClientExtensions)
	{
		this.serverConfig = new SshSessionConfiguration();
		if (!useServerExtensions)
		{
			this.serverConfig.ProtocolExtensions.Remove(SshProtocolExtensionNames.OpenChannelRequest);
		}

		this.clientConfig = new SshSessionConfiguration();
		if (!useClientExtensions)
		{
			this.clientConfig.ProtocolExtensions.Remove(SshProtocolExtensionNames.OpenChannelRequest);
		}

		this.sessionPair = new SessionPair(serverConfig, clientConfig);
		this.serverSession = this.sessionPair.ServerSession;
		this.clientSession = this.sessionPair.ClientSession;
	}

	public void Dispose()
	{
		this.sessionPair.Dispose();
	}

	[Theory]
	[InlineData(null)]
	[InlineData("test")]
	public async Task OpenAndCloseChannelFromClient(string channelType)
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var serverChannelTask = this.serverSession.AcceptChannelAsync(channelType).WithTimeout(Timeout);

		Assert.Equal(0, this.serverSession.Channels.Count);
		Assert.Equal(0, this.clientSession.Channels.Count);

		var clientChannel = await this.clientSession.OpenChannelAsync(channelType).WithTimeout(Timeout);

		Assert.NotNull(clientChannel);
		Assert.Equal(channelType ?? SshChannel.SessionChannelType, clientChannel.ChannelType);

		var serverChannel = await serverChannelTask.WithTimeout(Timeout);
		Assert.Equal(channelType ?? SshChannel.SessionChannelType, serverChannel?.ChannelType);

		var serverChannelClosedCompletion = new TaskCompletionSource<bool>();
		serverChannel.Closed += (sender, e) => serverChannelClosedCompletion.SetResult(true);

		Assert.Equal(1, this.serverSession.Channels.Count);
		Assert.Same(serverChannel, this.serverSession.Channels.Single());
		Assert.Equal(1, this.clientSession.Channels.Count);
		Assert.Same(clientChannel, this.clientSession.Channels.Single());

		await clientChannel.CloseAsync(CancellationToken.None);

		await serverChannelClosedCompletion.Task.WithTimeout(Timeout);

		// The channel is removed from the channels collection AFTER the Closed event. So
		// depending on timing of the async continuation, it might not be removed yet at this point.
		Assert.True(await WaitForCondition(() => this.serverSession.Channels.Count == 0));
		Assert.True(await WaitForCondition(() => this.clientSession.Channels.Count == 0));
	}

	private async Task<bool> WaitForCondition(Func<bool> check)
	{
		for (int i = 0; i < 10; i++)
		{
			if (check())
			{
				return true;
			}

			await Task.Delay(10);
		}

		return false;
	}

	[Theory]
	[InlineData(null)]
	[InlineData("test")]
	public async Task OpenAndCloseChannelFromServer(string channelType)
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var clientChannelTask = this.clientSession.AcceptChannelAsync(channelType);

		var serverChannel = await this.serverSession.OpenChannelAsync(channelType).WithTimeout(Timeout);

		Assert.NotNull(serverChannel);
		Assert.Equal(channelType ?? SshChannel.SessionChannelType, serverChannel.ChannelType);

		var clientChannel = await clientChannelTask.WithTimeout(Timeout);
		Assert.Equal(channelType ?? SshChannel.SessionChannelType, clientChannel?.ChannelType);

		var clientChannelClosedCompletion = new TaskCompletionSource<bool>();
		clientChannel.Closed += (sender, e) => clientChannelClosedCompletion.SetResult(true);

		await serverChannel.CloseAsync(CancellationToken.None);

		await clientChannelClosedCompletion.Task.WithTimeout(Timeout);
	}

	[Fact]
	public async Task OpenChannelCancelByOpener()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var cancellationSource = new CancellationTokenSource();
		cancellationSource.Cancel();
		await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
		{
			await this.clientSession.OpenChannelAsync(cancellationSource.Token);
		});
	}

	[Fact]
	public async Task OpenChannelCancelByAcceptor()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		this.serverSession.ChannelOpening += (sender, e) =>
		{
			e.FailureReason = SshChannelOpenFailureReason.ConnectFailed;
			e.FailureDescription = nameof(OpenChannelCancelByAcceptor);
		};

		try
		{
			await this.clientSession.OpenChannelAsync();
			Assert.True(false, "Open channel should have thrown an exception.");
		}
		catch (Exception ex)
		{
			Assert.IsType<SshChannelException>(ex);
			Assert.Equal(
				SshChannelOpenFailureReason.ConnectFailed,
				((SshChannelException)ex).OpenFailureReason);
			Assert.Equal(
				$"{nameof(OpenChannelCancelByAcceptor)}\nReason: " +
					SshChannelOpenFailureReason.ConnectFailed,
				((SshChannelException)ex).Message);
		}
	}

	[Theory]
	[InlineData(false, false)]
	[InlineData(false, true)]
	[InlineData(true, false)]
	[InlineData(true, true)]
	public async Task OpenChannelWithRequest(bool serverExtension, bool clientExtension)
	{
		InitializeSessionPair(serverExtension, clientExtension);
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		ChannelRequestMessage serverRequest = null;
		this.serverSession.ChannelOpening += (sender, e) =>
		{
			e.Channel.Request += (sender, e) =>
			{
				serverRequest = e.Request;
				e.IsAuthorized = true;
			};
		};

		var serverChannelTask = this.serverSession.AcceptChannelAsync();

		const string testRequestType = "test";
		var clientRequest = new ChannelRequestMessage { RequestType = testRequestType, WantReply = true };
		var clientChannel = await this.clientSession.OpenChannelAsync(
			new ChannelOpenMessage(), clientRequest).WithTimeout(Timeout);
		var serverChannel = await serverChannelTask.WithTimeout(Timeout);

		Assert.NotNull(clientChannel);
		Assert.NotNull(serverRequest);
		Assert.Equal(testRequestType, serverRequest.RequestType);
	}

	[Theory]
	[InlineData(false, false)]
	[InlineData(false, true)]
	[InlineData(true, false)]
	[InlineData(true, true)]
	public async Task OpenChannelWithRequestFail(bool serverExtension, bool clientExtension)
	{
		InitializeSessionPair(serverExtension, clientExtension);
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		ChannelRequestMessage serverRequest = null;
		this.serverSession.ChannelOpening += (sender, e) =>
		{
			e.Channel.Request += (sender, e) =>
			{
				serverRequest = e.Request;
				e.IsAuthorized = false;
			};
		};

		var serverChannelTask = this.serverSession.AcceptChannelAsync();

		const string testRequestType = "test";
		var clientRequest = new ChannelRequestMessage { RequestType = testRequestType, WantReply = true };

		await Assert.ThrowsAsync<SshChannelException>(async () =>
		{
			await this.clientSession.OpenChannelAsync(
				new ChannelOpenMessage(), clientRequest).WithTimeout(Timeout);
		});

		var serverChannel = await serverChannelTask.WithTimeout(Timeout);

		Assert.NotNull(serverRequest);
		Assert.Equal(testRequestType, serverRequest.RequestType);
	}

	[Theory]
	[InlineData(false, false)]
	[InlineData(false, true)]
	[InlineData(true, false)]
	[InlineData(true, true)]
	public async Task OpenChannelWithRequestNoReply(bool serverExtension, bool clientExtension)
	{
		InitializeSessionPair(serverExtension, clientExtension);
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var serverOpeningCompletion = new TaskCompletionSource<ChannelRequestMessage>();
		this.serverSession.ChannelOpening += (sender, e) =>
		{
			e.Channel.Request += (sender, e) =>
			{
				serverOpeningCompletion.SetResult(e.Request);
				e.IsAuthorized = false; // Will be ignored.
				};
		};

		var serverChannelTask = this.serverSession.AcceptChannelAsync();

		const string testRequestType = "test";
		var clientRequest = new ChannelRequestMessage { RequestType = testRequestType, WantReply = false };
		var clientChannel = await this.clientSession.OpenChannelAsync(
			new ChannelOpenMessage(), clientRequest).WithTimeout(Timeout);
		var serverChannel = await serverChannelTask.WithTimeout(Timeout);

		Assert.NotNull(clientChannel);

		var serverRequest = await serverOpeningCompletion.Task.WithTimeout(Timeout);
		Assert.NotNull(serverRequest);
		Assert.Equal(testRequestType, serverRequest.RequestType);
	}

	[Fact]
	public async Task OpenChannelWithRequestUnauthenticated()
	{
		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		SshChannelOpeningEventArgs requestArgs = null;
		this.serverSession.ChannelOpening += (sender, e) =>
		{
			requestArgs = e;
		};

		var ex = await Assert.ThrowsAsync<SshChannelException>(async () =>
		{
			await this.clientSession.OpenChannelAsync();
		});

		Assert.Equal(SshChannelOpenFailureReason.AdministrativelyProhibited, ex.OpenFailureReason);
		Assert.Null(requestArgs);
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task ChannelRequest(bool success)
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var (clientChannel, serverChannel) = await OpenClientChannelAsync();

		ChannelRequestMessage serverRequest = null;
		serverChannel.Request += (sender, e) =>
		{
			serverRequest = e.Request;
			e.IsAuthorized = success;
		};

		const string testRequestType = "test";
		var clientRequest = new ChannelRequestMessage { RequestType = testRequestType, WantReply = true };
		bool result = await clientChannel.RequestAsync(clientRequest, CancellationToken.None)
			.WithTimeout(Timeout);

		Assert.Equal(success, result);
		Assert.NotNull(serverRequest);
		Assert.Equal(testRequestType, serverRequest.RequestType);
	}

	[Fact]
	public async Task ChannelRequestEarlyCancellation()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var cancellationSource = new CancellationTokenSource();
		this.serverSession.ChannelOpening += (sender, ce) =>
		{
			ce.Channel.Request += (_, e) => e.IsAuthorized = true;
		};

		var serverChannelTask = this.serverSession.AcceptChannelAsync(null);
		var clientChannel = await this.clientSession.OpenChannelAsync(null, this.timeoutToken).WithTimeout(Timeout);
		var clientRequest = new ChannelRequestMessage { RequestType = "test" };

		// Cancel the request before it is sent.
		cancellationSource.Cancel();
		await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
			clientChannel.RequestAsync(clientRequest, cancellationSource.Token));

		// Open another channel
		clientChannel = await this.clientSession.OpenChannelAsync(null, this.timeoutToken);
		Assert.True(await clientChannel.RequestAsync(clientRequest, this.timeoutToken));
		Assert.False(this.clientSession.IsClosed);
		Assert.False(this.serverSession.IsClosed);
	}

	[Fact]
	public async Task ChannelRequestLateCancellation()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var cancellationSource = new CancellationTokenSource();
		this.serverSession.ChannelOpening += (sender, ce) =>
		{
			ce.Channel.Request += (_, e) =>
			{
				// Cancel the request once it reaches the server.
				cancellationSource.Cancel();
				e.IsAuthorized = true;
			};
		};

		var serverChannelTask = this.serverSession.AcceptChannelAsync(null);
		var clientChannel = await this.clientSession.OpenChannelAsync(null, this.timeoutToken).WithTimeout(Timeout);
		var clientRequest = new ChannelRequestMessage { RequestType = "test", WantReply = true };

		await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
			clientChannel.RequestAsync(clientRequest, cancellationSource.Token));

		// Open another channel
		clientChannel = await this.clientSession.OpenChannelAsync(null, this.timeoutToken);
		Assert.True(await clientChannel.RequestAsync(clientRequest, this.timeoutToken));
		Assert.False(this.clientSession.IsClosed);
		Assert.False(this.serverSession.IsClosed);
	}

	[Fact]
	public async Task ChannelRequestHandlerClosesChannel()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		this.serverSession.ChannelOpening += (sender, ce) =>
		{
			ce.Channel.Request += (_, e) =>
			{
				e.IsAuthorized = true;

				if (e.RequestType == "close")
				{
					// Close the channel while handling the request.
					e.ResponseTask = Task.Run<SshMessage>(async () =>
					{
						await ce.Channel.CloseAsync();
						return new ChannelSuccessMessage();
					});
				}
			};
		};

		var clientChannel = await this.clientSession.OpenChannelAsync(null, this.timeoutToken).WithTimeout(Timeout);

		// The request should not throw an exception if the channel was closed by the request handler.
		var closeRequest = new ChannelRequestMessage { RequestType = "close", WantReply = true };
		var closeResponse = await clientChannel.RequestAsync(closeRequest);
		Assert.False(closeResponse);

		// The channel should be closed after receiving the response from the request.
		Assert.True(clientChannel.IsClosed);

		// Open another channel and send a request on that channel.
		clientChannel = await this.clientSession.OpenChannelAsync(null, this.timeoutToken);
		var testRequest = new ChannelRequestMessage { RequestType = "test", WantReply = true };
		Assert.True(await clientChannel.RequestAsync(testRequest, this.timeoutToken));
		Assert.False(this.clientSession.IsClosed);
		Assert.False(this.serverSession.IsClosed);
	}

	[Fact]
	public async Task ChannelRequestHandlerException()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		this.serverSession.ChannelOpening += (sender, ce) =>
		{
			ce.Channel.Request += (_, e) =>
			{
				e.IsAuthorized = true;

				if (e.RequestType == "test")
				{
					throw new Exception("test exception");
				}
			};
		};

		var clientChannel = await this.clientSession.OpenChannelAsync(null, this.timeoutToken).WithTimeout(Timeout);

		var testRequest = new ChannelRequestMessage { RequestType = "test", WantReply = true };
		var response = await clientChannel.RequestAsync(testRequest);

		Assert.False(response);
	}

	public static IEnumerable<object[]> GetTestChannelData()
	{
		// Each yielded object[] contains one byte[][] array;
		// each of those is an array of byte[] arrays to send.
		yield return new object[] { new[] { new byte[0] } };
		yield return new object[] { new[] { new byte[] { 0 }, new byte[0] } };
		yield return new object[] { new[] { Encoding.ASCII.GetBytes("test"), new byte[0] } };

		// A data size of 2032 causes only the padding to exceed the initial packet
		// size of 2048 bytes. There was previously a bug in this boundary condition.
		yield return new object[] { new[] { Encoding.ASCII.GetBytes(new string('A', 2032)) } };
	}

	[Theory]
	[MemberData(nameof(GetTestChannelData))]
	public async Task SendChannelData(byte[][] data)
	{
		var channels = await OpenClientChannelAsync();
		await SendDataFromClientToServerChannelAsync(data, channels.Client, channels.Server);
	}

	[Theory]
	[InlineData(SshChannel.DefaultMaxWindowSize, SshChannel.DefaultMaxWindowSize)]
	[InlineData(SshChannel.DefaultMaxWindowSize, 5 * SshChannel.DefaultMaxWindowSize)]
	[InlineData(5 * SshChannel.DefaultMaxWindowSize, SshChannel.DefaultMaxWindowSize)]
	public async Task SendLargeChannelData(uint clientMaxWindowSize, uint serverMaxWindowSize)
	{
		// (Xunit data-driven test case discovery doesn't handle large data very well.)
		// Test data that is larger than the channel flow-control window size (1MB).
		const int largeDataSize = 1024 * 1024 * 7 / 2;
		byte[] largeData = new byte[largeDataSize];
		for (int i = 0; i < largeData.Length; i++) largeData[i] = (byte)(i & 0xFF);

		var data = new[] { largeData, new byte[0] };
		var channels = await OpenClientChannelAsync(clientMaxWindowSize, serverMaxWindowSize);
		await SendDataFromClientToServerChannelAsync(data, channels.Client, channels.Server);
	}

	[Fact]
	public async Task SendIncreasingChannelData()
	{
		// This test is designed to catch bugs related to expanding send/receive buffers.
		const int maxDataSize = 4096;
		var data = new Buffer(maxDataSize);
		for (int i = 0; i < data.Count; i++) data[i] = (byte)(i & 0xFF);

		var channels = await OpenClientChannelAsync();

		for (int size = 32; size <= maxDataSize; size += 32)
		{
			await SendDataFromClientToServerChannelAsync(
				new[] { data.Slice(0, size).ToArray() },
				channels.Client,
				channels.Server,
				closeChannels: false);
		}

		await channels.Client.CloseAsync();
		await channels.Server.CloseAsync();
	}

	[Fact]
	public async Task SendChannelDataWithOffset()
	{
		var channels = await OpenClientChannelAsync();

		var data = Encoding.ASCII.GetBytes("offset test");
		var offset = 7;
		var count = data.Length - offset;

		MemoryStream receivingStream = null;
		TaskCompletionSource<byte[]> receivedCompletion = null;

		channels.Server.DataReceived += (sender, bytes) =>
		{
			receivingStream.Write(bytes.Array, bytes.Offset, bytes.Count);
			if (receivingStream.Length >= count)
			{
				receivedCompletion.SetResult(receivingStream.ToArray());
			}
		};

		receivingStream = new MemoryStream();
		receivedCompletion = new TaskCompletionSource<byte[]>();

		var bufferWithOffset = Buffer.From(data, offset, count);
		await channels.Client.SendAsync(bufferWithOffset, CancellationToken.None).WithTimeout(Timeout);

		var receivedData = await receivedCompletion.Task.WithTimeout(LongTimeout);
		Assert.True(bufferWithOffset.Equals(receivedData));

		await channels.Client.CloseAsync().WithTimeout(Timeout);
		await channels.Server.CloseAsync().WithTimeout(Timeout);
	}

	[Theory]
	[MemberData(nameof(GetTestChannelData))]
	public async Task SendServerChannelData(byte[][] data)
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var (clientChannel, serverChannel) = await OpenClientChannelAsync();

		TaskCompletionSource<byte[]> receivedCompletion = null;
		clientChannel.DataReceived += (sender, bytes) =>
		{
			receivedCompletion.SetResult(bytes.ToArray());
			clientChannel.AdjustWindow((uint)bytes.Count);
		};

		for (int i = 0; i < data.Length; i++)
		{
			receivedCompletion = new TaskCompletionSource<byte[]>();
			await serverChannel.SendAsync(data[i], CancellationToken.None);
			var receivedData = await receivedCompletion.Task.WithTimeout(Timeout);
			Assert.Equal(data[i], receivedData);
		}
	}

	[Fact]
	public async Task ChannelReceiveWaitsForListener()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var serverChannelTask = this.serverSession.AcceptChannelAsync();
		var clientChannel = await this.clientSession.OpenChannelAsync(
			channelType: null,
			cancellation: this.timeoutToken).WithTimeout(Timeout);
		var serverChannel = await serverChannelTask.WithTimeout(Timeout);

		var sendTask = clientChannel.SendAsync(new byte[2 * WindowSize], this.timeoutToken);
		await Task.Delay(TimeSpan.FromMilliseconds(10));

		var receiveCompletion = new TaskCompletionSource<byte[]>();
		serverChannel.DataReceived += (sender, data) =>
		{
			receiveCompletion.TrySetResult(data.ToArray());
		};

		var receiveCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(1));
		receiveCancellation.Token.Register(() => receiveCompletion.TrySetCanceled(receiveCancellation.Token));
		await receiveCompletion.Task;
	}

	[Fact]
	public async Task SendBlocksOnClosedWindow()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var serverChannelTask = this.serverSession.AcceptChannelAsync();

		var clientChannel = await this.clientSession.OpenChannelAsync(
			channelType: null, cancellation: this.timeoutToken).WithTimeout(Timeout);
		var serverChannel = await serverChannelTask.WithTimeout(Timeout);

		var expectedDataCollected = CreateTcs();
		int dataRecieved = 0;
		int expectedData = 0;
		clientChannel.DataReceived += (sender, data) =>
		{
			dataRecieved += data.Count;
			if (dataRecieved == expectedData)
			{
				expectedDataCollected.TrySetResult(null);
			}
			else if (dataRecieved > expectedData)
			{
				expectedDataCollected.TrySetException(new InvalidOperationException("Recieved more data than expected"));
			}
		};

		expectedData = WindowSize;
		var sendTask = serverChannel.SendAsync(new byte[WindowSize * 2], this.timeoutToken);

		await expectedDataCollected.Task;
		Assert.False(sendTask.IsCompleted);

		expectedDataCollected = CreateTcs();
		expectedData += WindowSize;

		clientChannel.AdjustWindow(WindowSize);
		await expectedDataCollected.Task;
		await sendTask;

		await serverChannel.CloseAsync();
	}

	private TaskCompletionSource<object> CreateTcs() =>
		CreateTcs<object>();

	private TaskCompletionSource<T> CreateTcs<T>()
	{
		var result = new TaskCompletionSource<T>();
		if (this.timeoutToken.CanBeCanceled)
		{
			this.timeoutToken.Register(() => result.TrySetCanceled(this.timeoutToken));
		}

		return result;
	}

	[Theory]
	[MemberData(nameof(GetTestChannelData))]
	public async Task SendChannelDataOverMultipleChannels(byte[][] data)
	{
		const int ParallelTasks = 200;

		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var serverChannels = Enumerable.Range(0, ParallelTasks).Select(i => new TaskCompletionSource<SshChannel>()).ToArray();
		this.serverSession.ChannelOpening += (sender, ce) =>
		{
			ce.Channel.Request += (s, requestMessage) =>
			{
				int index = int.Parse(requestMessage.RequestType, CultureInfo.InvariantCulture);
				serverChannels[index].SetResult(ce.Channel);
				requestMessage.IsAuthorized = true;
			};
		};

		var tasks = Enumerable.Range(0, ParallelTasks).Select(i => Task.Run(async () =>
		{
			SshChannel clientChannel = await this.clientSession.OpenChannelAsync();
			bool accepted = await clientChannel.RequestAsync(new ChannelRequestMessage { RequestType = i.ToString(CultureInfo.InvariantCulture) }, CancellationToken.None);
			Assert.True(accepted);

			SshChannel serverChannel = await serverChannels[i].Task;
			await SendDataFromClientToServerChannelAsync(data, clientChannel, serverChannel);
		}));

		await Task.WhenAll(tasks);
	}

	[Fact]
	public Task UnknownChannelDataIsIgnored() =>
		UnknownChannelIsIgnored(channel => channel.SendAsync(new Buffer(16), this.timeoutToken));

	[Fact]
	public Task UnknownChannelEofIsIgnored() =>
		UnknownChannelIsIgnored(channel => channel.SendAsync(new Buffer(0), this.timeoutToken));

	[Fact]
	public Task UnknownChannelAdjustWindowIsIgnored() =>
		UnknownChannelIsIgnored(channel => { channel.AdjustWindow(1); return Task.CompletedTask; });

	private async Task UnknownChannelIsIgnored(Func<SshChannel, Task> channelActionAsync)
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var (clientChannel, serverChannel) = await OpenClientChannelAsync();
		serverChannel.Request += (sender, e) => e.IsAuthorized = true;

		Assert.True(await clientChannel.RequestAsync(new ChannelRequestMessage { RequestType = "test" }, this.timeoutToken));

		// Use reflection to set the RemoteChannelId, causing incorrect messages to be sent.
		var remoteChannelIdProperty = typeof(SshChannel).GetProperty(
			nameof(SshChannel.RemoteChannelId));
		remoteChannelIdProperty.SetValue(serverChannel, (uint)99);
		remoteChannelIdProperty.SetValue(clientChannel, (uint)99);

		await channelActionAsync(serverChannel);
		await channelActionAsync(clientChannel);

		Assert.False(this.serverSession.IsClosed);
		Assert.False(this.clientSession.IsClosed);
	}

	private async Task<Channels> OpenClientChannelAsync(
		uint? clientMaxWindowSize = null,
		uint? serverMaxWindowSize = null)
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		SshChannel clientChannel, serverChannel;

		EventHandler<SshChannelOpeningEventArgs> openingHandler = (sender, e) =>
		{
			e.Channel.MaxWindowSize = serverMaxWindowSize ?? SshChannel.DefaultMaxWindowSize;
		};
		this.serverSession.ChannelOpening += openingHandler;

		var openMessage = new ChannelOpenMessage
		{
			MaxWindowSize = clientMaxWindowSize ?? SshChannel.DefaultMaxWindowSize,
		};

		var serverChannelTask = this.serverSession.AcceptChannelAsync();
		clientChannel = await this.clientSession.OpenChannelAsync(openMessage, null)
			.WithTimeout(Timeout);
		serverChannel = await serverChannelTask.WithTimeout(Timeout);

		this.serverSession.ChannelOpening -= openingHandler;

		Assert.True(clientMaxWindowSize == null ||
			clientChannel.MaxWindowSize == clientMaxWindowSize.Value);
		Assert.True(serverMaxWindowSize == null ||
			serverChannel.MaxWindowSize == serverMaxWindowSize.Value);

		return new Channels
		{
			Client = clientChannel,
			Server = serverChannel,
		};
	}

	private static async Task SendDataFromClientToServerChannelAsync(
		byte[][] data,
		SshChannel clientChannel,
		SshChannel serverChannel,
		bool closeChannels = true)
	{
		MemoryStream receivingStream = null;
		TaskCompletionSource<byte[]> receivedCompletion = null;
		int expectedDataLength = 0;

		EventHandler<Buffer> dataReceivedHandler = (sender, bytes) =>
		{
				// Insert some delay on the receiving end to make channel flow-control kick in.
				////Thread.Sleep(5);
				receivingStream.Write(bytes.Array, bytes.Offset, bytes.Count);
			if (receivingStream.Length >= expectedDataLength)
			{
				receivedCompletion.SetResult(receivingStream.ToArray());
			}

			serverChannel.AdjustWindow((uint)bytes.Count);
		};
		serverChannel.DataReceived += dataReceivedHandler;

		for (int i = 0; i < data.Length; i++)
		{
			receivingStream = new MemoryStream();
			receivedCompletion = new TaskCompletionSource<byte[]>();
			expectedDataLength = data[i].Length;

			await clientChannel.SendAsync(data[i], CancellationToken.None);

			var receivedData = await receivedCompletion.Task.WithTimeout(
				TimeSpan.FromMilliseconds(4 * Timeout.TotalMilliseconds));
			Assert.Equal(data[i], receivedData);
		}

		serverChannel.DataReceived -= dataReceivedHandler;
		if (closeChannels)
		{
			await clientChannel.CloseAsync();
			await serverChannel.CloseAsync();
		}
	}

	[Fact]
	public async Task SendLargeDataWithoutAwait()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var (clientChannel, serverChannel) = await OpenClientChannelAsync();

		var receivedCompletion = new TaskCompletionSource<bool>();
		int chunkIndex = -1;
		int messageIndex = 0;
		serverChannel.DataReceived += (sender, data) =>
		{
			if (++chunkIndex == 4)
			{
				chunkIndex = 0;
				++messageIndex;
			}

			if (data[0] != messageIndex)
			{
				receivedCompletion.SetResult(false);
			}

			if (messageIndex == 255)
			{
				receivedCompletion.SetResult(true);
			}

			serverChannel.AdjustWindow((uint)data.Count);
		};

		const int dataSize = (int)SshChannel.DefaultMaxPacketSize * 4;
		var data = new Buffer(dataSize);
		for (int i = 0; i < 256 && !receivedCompletion.Task.IsCompleted; i++)
		{
			for (int j = 0; j < data.Count; j++)
			{
				data.Array[data.Offset + j] = (byte)i;
			}

			// Don't await!
			_ = clientChannel.SendAsync(data, CancellationToken.None);
		}

		Assert.True(await receivedCompletion.Task.WithTimeout(LongTimeout));
	}

	[Fact]
	public async Task CloseSessionClosesChannel()
	{
		SshChannelClosedEventArgs closedEvent = null;
		var channels = await OpenClientChannelAsync();
		channels.Client.Closed += (sender, e) => closedEvent = e;
		await this.clientSession.CloseAsync(SshDisconnectReason.ByApplication);
		Assert.NotNull(closedEvent);
		Assert.IsType<SshConnectionException>(closedEvent.Exception);
		Assert.Equal(
			SshDisconnectReason.ByApplication,
			((SshConnectionException)closedEvent.Exception).DisconnectReason);
	}

	[Fact]
	public async Task CloseSessionClosesChannelWithException()
	{
		var testException = new Exception();
		SshChannelClosedEventArgs closedEvent = null;
		var channels = await OpenClientChannelAsync();
		channels.Client.Closed += (sender, e) => closedEvent = e;
		await this.clientSession.CloseAsync(SshDisconnectReason.ProtocolError, testException);
		Assert.NotNull(closedEvent);
		Assert.Same(testException, closedEvent.Exception);
	}

	[Fact]
	public async Task CloseServerChannel()
	{
		var closedCompletion = new TaskCompletionSource<SshChannelClosedEventArgs>();
		var channels = await OpenClientChannelAsync();
		channels.Client.Closed += (sender, e) => closedCompletion.SetResult(e);
		await channels.Server.CloseAsync();
		var closedEvent = await closedCompletion.Task.WithTimeout(Timeout);
		Assert.NotNull(closedEvent);
		Assert.Null(closedEvent.ExitStatus);
		Assert.Null(closedEvent.ExitSignal);
		Assert.Null(closedEvent.Exception);
	}

	[Fact]
	public async Task CloseClientChannel()
	{
		var closedCompletion = new TaskCompletionSource<SshChannelClosedEventArgs>();
		var channels = await OpenClientChannelAsync();
		channels.Server.Closed += (sender, e) => closedCompletion.SetResult(e);
		await channels.Client.CloseAsync();
		var closedEvent = await closedCompletion.Task.WithTimeout(Timeout);
		Assert.NotNull(closedEvent);
		Assert.Null(closedEvent.ExitStatus);
		Assert.Null(closedEvent.ExitSignal);
		Assert.Null(closedEvent.Exception);
	}

	[Fact]
	public async Task CloseChannelWithStatus()
	{
		var closedCompletion = new TaskCompletionSource<SshChannelClosedEventArgs>();
		var channels = await OpenClientChannelAsync();
		channels.Client.Closed += (sender, e) => closedCompletion.SetResult(e);
		await channels.Server.CloseAsync(11);
		var closedEvent = await closedCompletion.Task.WithTimeout(Timeout);
		Assert.NotNull(closedEvent);
		Assert.Equal((uint?)11, closedEvent.ExitStatus);
	}

	[Fact]
	public async Task CloseChannelWithSignal()
	{
		var closedCompletion = new TaskCompletionSource<SshChannelClosedEventArgs>();
		var channels = await OpenClientChannelAsync();
		channels.Client.Closed += (sender, e) => closedCompletion.SetResult(e);
		await channels.Server.CloseAsync("test", "message");
		var closedEvent = await closedCompletion.Task.WithTimeout(Timeout);
		Assert.NotNull(closedEvent);
		Assert.Equal("test", closedEvent.ExitSignal);
		Assert.Equal("message", closedEvent.ErrorMessage);
	}

	[Fact]
	public async Task DisposeChannelCloses()
	{
		var serverClosedCompletion = new TaskCompletionSource<SshChannelClosedEventArgs>();
		var clientClosedCompletion = new TaskCompletionSource<SshChannelClosedEventArgs>();
		var channels = await OpenClientChannelAsync();
		channels.Server.Closed += (sender, e) => serverClosedCompletion.SetResult(e);
		channels.Client.Closed += (sender, e) => clientClosedCompletion.SetResult(e);
		channels.Server.Dispose();
		await serverClosedCompletion.Task.WithTimeout(Timeout);
		await clientClosedCompletion.Task.WithTimeout(Timeout);
	}

	[Fact]
	public async Task TraceChannelData()
	{
		var channels = await OpenClientChannelAsync();

		var traceListener = new TestTraceListener();
		traceListener.EventIds.Add(SshTraceEventIds.SendingChannelData);
		traceListener.EventIds.Add(SshTraceEventIds.ReceivingChannelData);
		this.sessionPair.ClientTrace.Listeners.Add(traceListener);
		this.sessionPair.ServerTrace.Listeners.Add(traceListener);

		var testData = new[] { new byte[] { 1, 2, 3 } };
		await SendDataFromClientToServerChannelAsync(testData, channels.Client, channels.Server, closeChannels: false);
		Assert.Empty(traceListener.Events);

		this.clientConfig.TraceChannelData = true;
		await SendDataFromClientToServerChannelAsync(testData, channels.Client, channels.Server, closeChannels: false);
		Assert.Collection(traceListener.Events, (item) =>
		{
			Assert.Equal(SshTraceEventIds.SendingChannelData, item.Key);
			Assert.StartsWith("Sending #8 ChannelDataMessage[3] (55BC801D)\n0000: 01 02 03 ", item.Value);
		});
		traceListener.Events.Clear();

		this.clientConfig.TraceChannelData = false;
		this.serverConfig.TraceChannelData = true;
		await SendDataFromClientToServerChannelAsync(testData, channels.Client, channels.Server, closeChannels: false);
		Assert.Collection(traceListener.Events, (item) =>
		{
			Assert.Equal(SshTraceEventIds.ReceivingChannelData, item.Key);
			Assert.StartsWith("Receiving #9 ChannelDataMessage[3] (55BC801D)\n0000: 01 02 03 ", item.Value);
		});
	}

	[Fact]
	public async Task SendWhileOpening()
	{
		var testData = new byte[] { 1, 2, 3 };
		this.sessionPair.ServerSession.ChannelOpening += (_, e) =>
		{
			_ = e.Channel.SendAsync(testData, CancellationToken.None);
		};

		var channels = await OpenClientChannelAsync();

		var dataReceivedCompletion = new TaskCompletionSource<Buffer>();
		channels.Client.DataReceived += (_, data) =>
		{
			dataReceivedCompletion.TrySetResult(data);
		};
		await dataReceivedCompletion.Task.WithTimeout(Timeout);
	}

	[Fact]
	public async Task OpenChannelWithMultipleRequests()
	{
		InitializeSessionPair(true, true);
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		TaskCompletionSource<bool> secondMessageCompletion = new TaskCompletionSource<bool>();
		TaskCompletionSource<bool> firstMessageCompletion = new TaskCompletionSource<bool>();

		var serverChannelTask = this.serverSession.AcceptChannelAsync();

		var firstRequest = new ChannelRequestMessage { RequestType = "first", WantReply = true };
		var secondRequest = new ChannelRequestMessage { RequestType = "second", WantReply = true };
		var clientChannel = await this.clientSession.OpenChannelAsync(
			new ChannelOpenMessage(), null).WithTimeout(Timeout);
		var serverChannel = await serverChannelTask.WithTimeout(Timeout);

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
		serverChannel.Request += (sender, e) =>
		{
			e.ResponseTask = responseTask(e);
		};

		var firstTask = clientChannel.RequestAsync(firstRequest);
		await clientChannel.RequestAsync(secondRequest);
		await firstTask;
		Assert.True(await secondMessageCompletion.Task);
		Assert.True(await firstMessageCompletion.Task);

		await this.clientSession.CloseAsync(SshDisconnectReason.None);
		Assert.NotNull(clientChannel);
	}

	[DebuggerStepThrough]
	private class Channels
	{
		public SshChannel Client { get; set; }
		public SshChannel Server { get; set; }

		public void Deconstruct(out SshChannel clientChannel, out SshChannel serverChannel)
		{
			clientChannel = Client;
			serverChannel = Server;
		}
	}

	private class TestTraceListener : TraceListener
	{
		public ISet<int> EventIds { get; } = new HashSet<int>();

		public List<KeyValuePair<int, string>> Events { get; } = new List<KeyValuePair<int, string>>();

		public override void TraceEvent(TraceEventCache eventCache, string source, TraceEventType eventType, int id, string message)
		{
			if (EventIds.Contains(id))
			{
				message = message.Replace(Environment.NewLine, "\n");
				Events.Add(new KeyValuePair<int, string>(id, message));
			}
		}

		public override void Write(string message) => throw new NotSupportedException();
		public override void WriteLine(string message) => throw new NotSupportedException();
	}
}
