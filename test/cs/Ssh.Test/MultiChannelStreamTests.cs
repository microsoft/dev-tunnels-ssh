using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Nerdbank.Streams;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class MultiChannelStreamTests
{
	private static readonly TimeSpan Timeout = Debugger.IsAttached ? TimeSpan.FromDays(1) : TimeSpan.FromSeconds(20);
	private readonly CancellationToken TimeoutToken = new CancellationTokenSource(Timeout).Token;

	private readonly Stream clientStream;
	private readonly Stream serverStream;

	public MultiChannelStreamTests()
	{
		(this.serverStream, this.clientStream) = FullDuplexStream.CreatePair();
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task Dispose_DisposesTransportStream(bool disposeAsync)
	{
		var stream = new MemoryStream();

		var server = new MultiChannelStream(stream);
		Assert.False(server.IsClosed);
		var isClosedEventFired = false;
		server.Closed += (_, _) => isClosedEventFired = true;

		await DisposeServerAsync(server, disposeAsync);
		Assert.True(server.IsClosed);
		Assert.True(isClosedEventFired);

		// The stream is disposed even if the server has not connected yet.
		Assert.Throws<ObjectDisposedException>(() => stream.WriteByte(0));
	}

	private async ValueTask DisposeServerAsync(MultiChannelStream stream, bool disposeAsync)
	{
		if (disposeAsync)
		{
			await stream.CloseAsync();
		}
		else
		{
			stream.Dispose();
		}
	}

	[Theory]
	[InlineData(true, true)]
	[InlineData(true, false)]
	[InlineData(false, true)]
	[InlineData(false, false)]
	public async Task Dispose_FiresCloseEvent(bool isConnected, bool disposeAsync)
	{
		var server = new MultiChannelStream(this.serverStream);
		using var client = new MultiChannelStream(this.clientStream);

		var closedEventFired = false;
		server.Closed += Server_Closed;

		if (isConnected)
		{
			await Task.WhenAll(
				client.ConnectAsync(TimeoutToken),
				server.ConnectAsync(TimeoutToken));
		}

		await DisposeServerAsync(server, disposeAsync);

		Assert.True(server.IsClosed);
		Assert.True(closedEventFired);

		void Server_Closed(object sender, SshSessionClosedEventArgs e)
		{
			Assert.Equal(server, sender);
			Assert.Equal(SshDisconnectReason.None, e.Reason);
			Assert.Equal(typeof(SshSession).Name + " disposed", e.Message);
			Assert.IsType<SshConnectionException>(e.Exception);
			Assert.Equal(
				SshDisconnectReason.None,
				((SshConnectionException)e.Exception).DisconnectReason);
			closedEventFired = true;
		}
	}

	[Fact]
	public async Task ConnectAndRunUntilClosedAsync_Cancelled()
	{
		var server = new MultiChannelStream(this.serverStream);
		var client = new MultiChannelStream(this.clientStream);

		var cts = CancellationTokenSource.CreateLinkedTokenSource(TimeoutToken);

		var serverTask = server.ConnectAndRunUntilClosedAsync(cts.Token);
		var clientTask = client.ConnectAndRunUntilClosedAsync(TimeoutToken);

		await ExchangeDataAsync(server, client);

		cts.Cancel();

		await Assert.ThrowsAnyAsync<OperationCanceledException>(() => serverTask.WithTimeout(Timeout));
		await clientTask.WithTimeout(Timeout);

		Assert.True(server.IsClosed);
		Assert.True(client.IsClosed);
	}

	[Fact]
	public async Task SingleChannelConnect()
	{
		var server = new MultiChannelStream(this.serverStream);
		var client = new MultiChannelStream(this.clientStream);

		var serverChannelTask = server.AcceptStreamAsync();
		var clientChannel = await client.OpenStreamAsync().WithTimeout(Timeout);
		var serverChannel = await serverChannelTask.WithTimeout(Timeout);

		Assert.NotNull(serverChannel);
		Assert.NotNull(clientChannel);

		clientChannel.Close();
		serverChannel.Close();
	}

	[Fact]
	public async Task OpenChannelEvent_FiresWhenChannelOpened()
	{
		const string ChannelType = "MyChannelType";

		var server = new MultiChannelStream(this.serverStream);
		var client = new MultiChannelStream(this.clientStream);

		Task<SshStream> serverChannelTask = null;

		var serverChannelOpeningEventFired = false;
		var clientChannelOpeningEventFired = false;

		server.ChannelOpening += Server_ChannelOpening;
		client.ChannelOpening += Client_ChannelOpening;

		var clientTask = client.ConnectAndRunUntilClosedAsync(TimeoutToken);
		var serverTask = server.ConnectAndRunUntilClosedAsync(TimeoutToken);

		var clientChannel = await client.OpenStreamAsync(ChannelType, TimeoutToken);

		Assert.NotNull(clientChannel);
		Assert.NotNull(serverChannelTask);
		Assert.True(serverChannelOpeningEventFired);
		Assert.True(clientChannelOpeningEventFired);

		var serverChannel = await serverChannelTask.WithTimeout(Timeout);
		Assert.NotNull(serverChannel);

#if !NETSTANDARD2_0
		await clientChannel.DisposeAsync();
		await serverStream.DisposeAsync();

#else
		clientChannel.Close();
		serverChannel.Close();
#endif

		await client.CloseAsync();
		await server.CloseAsync();
		try
		{
			await clientTask.WithTimeout(Timeout);
		}
		catch (SshConnectionException)
		{
			// This may happen due to a race: when then the client session sends DisconnectMessage and then closes the client stream,
			// which immediately closes the server stream, and that might happen sooner than the server gets the disconnect message.
			// For the server it would look like connection ended prematurely.
			// This is specific to duplex streams used in testing.
			// Other streams may behave differently.
		}

		try
		{
			await serverTask.WithTimeout(Timeout);
		}
		catch (SshConnectionException)
		{
			// See above.
		}

		void Server_ChannelOpening(object sender, SshChannelOpeningEventArgs e)
		{
			serverChannelOpeningEventFired = true;
			Assert.Equal(server, sender);
			Assert.True(e.IsRemoteRequest);
			Assert.Equal(ChannelType, e.Channel?.ChannelType);
			serverChannelTask = server.AcceptStreamAsync(ChannelType);
		}

		void Client_ChannelOpening(object sender, SshChannelOpeningEventArgs e)
		{
			clientChannelOpeningEventFired = true;
			Assert.Equal(client, sender);
			Assert.False(e.IsRemoteRequest);
			Assert.Equal(ChannelType, e.Channel?.ChannelType);
		}
	}

	[Fact]
	public async Task SingleChannelReadWrite()
	{
		var server = new MultiChannelStream(this.serverStream);
		var client = new MultiChannelStream(this.clientStream);

		await ExchangeDataAsync(server, client);
	}

	private static async Task ExchangeDataAsync(MultiChannelStream server, MultiChannelStream client)
	{
		var serverChannelTask = server.AcceptStreamAsync();
		var clientChannel = await client.OpenStreamAsync().WithTimeout(Timeout);
		var serverChannel = await serverChannelTask.WithTimeout(Timeout);

		Assert.NotNull(serverChannel);
		Assert.NotNull(clientChannel);

		const string payloadString = "Hello!";
		byte[] payload = Encoding.UTF8.GetBytes(payloadString);
		byte[] result = new byte[100];

		// Write from client, read from server
		await clientChannel.WriteAsync(payload, 0, payload.Length);
		int resultCount = await serverChannel.ReadAsync(result, 0, result.Length);
		Assert.Equal(payload.Length, resultCount);
		Assert.Equal(payloadString, Encoding.UTF8.GetString(result, 0, resultCount));

		// Write from server, read from client
		await serverChannel.WriteAsync(payload, 0, payload.Length);
		resultCount = await clientChannel.ReadAsync(result, 0, result.Length);
		Assert.Equal(payload.Length, resultCount);
		Assert.Equal(payloadString, Encoding.UTF8.GetString(result, 0, resultCount));

		clientChannel.Close();
		serverChannel.Close();
	}

	[Fact]
	public async Task SequentialChannelOpenAccept()
	{
		var server = new MultiChannelStream(this.serverStream);
		var client = new MultiChannelStream(this.clientStream);

		var clientChannelTask = client.OpenStreamAsync();
		var serverChannel = await server.AcceptStreamAsync().WithTimeout(Timeout);
		var clientChannel = await clientChannelTask.WithTimeout(Timeout);

		Assert.NotNull(serverChannel);
		Assert.NotNull(clientChannel);
		clientChannel.Close();
		serverChannel.Close();

		clientChannelTask = client.OpenStreamAsync();

		// Allow time for the open message to reach the server before accepting.
		await Task.Delay(10);

		serverChannel = await server.AcceptStreamAsync().WithTimeout(Timeout);
		clientChannel = await clientChannelTask.WithTimeout(Timeout);

		Assert.NotNull(serverChannel);
		Assert.NotNull(clientChannel);
		clientChannel.Close();
		serverChannel.Close();
	}

	[Fact]
	public async Task MultiChannelConnect()
	{
		const int ParallelTasks = 20;

		var server = new MultiChannelStream(this.serverStream);
		var client = new MultiChannelStream(this.clientStream);

		var serverChannelTasks = Enumerable.Range(0, ParallelTasks).Select((i) => server.AcceptStreamAsync()).ToArray();
		var clientChannelTasks = Enumerable.Range(0, ParallelTasks).Select((i) => client.OpenStreamAsync()).ToArray();

		await Task.WhenAll(serverChannelTasks.Concat(clientChannelTasks)).WithTimeout(Timeout);

		foreach (var t in serverChannelTasks) t.Result.Close();
		foreach (var t in clientChannelTasks) t.Result.Close();
	}

	[Fact]
	public async Task MultiChannelReadWrite()
	{
		const int ParallelTasks = 20;

		var server = new MultiChannelStream(this.serverStream);
		var client = new MultiChannelStream(this.clientStream);

		const string payloadString = "Hello!";
		byte[] payload = Encoding.UTF8.GetBytes(payloadString);

		var tasks = Enumerable.Range(0, ParallelTasks).Select(i => Task.Run(async () =>
		{
			Stream channel;

			byte[] result = new byte[100];
			if (i % 2 == 0)
			{
				channel = await server.AcceptStreamAsync();

					// Write then read from client
					for (int j = 0; j < 10; j++)
				{
					await channel.WriteAsync(payload, 0, payload.Length);

					int resultCount = await channel.ReadAsync(result, 0, result.Length);
					Assert.Equal(payload.Length, resultCount);
					Assert.Equal(payloadString, Encoding.UTF8.GetString(result, 0, resultCount));
				}
			}
			else
			{
				channel = await client.OpenStreamAsync();

					// Read then write from server
					for (int j = 0; j < 10; j++)
				{
					int resultCount = await channel.ReadAsync(result, 0, result.Length);
					Assert.Equal(payload.Length, resultCount);
					Assert.Equal(payloadString, Encoding.UTF8.GetString(result, 0, resultCount));

					await channel.WriteAsync(payload, 0, payload.Length);
				}
			}

			return channel;
		})).ToArray();

		await Task.WhenAll(tasks).WithTimeout(Timeout);

		foreach (var t in tasks) t.Result.Close();
	}
}
