using System;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class StreamTests : IDisposable
{
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

	private readonly SessionPair sessionPair;
	private SshChannel serverChannel;
	private SshChannel clientChannel;

	public StreamTests()
	{
		this.sessionPair = new SessionPair();
	}

	public void Dispose()
	{
		this.sessionPair.Dispose();
	}

	private async Task OpenChannelAsync()
	{
		await this.sessionPair.ConnectAsync();
		var serverChannelTask = this.sessionPair.ServerSession.AcceptChannelAsync();
		this.clientChannel = await this.sessionPair.ClientSession.OpenChannelAsync();
		this.serverChannel = await serverChannelTask;
	}

	[Fact]
	public async Task CloseStreamClosesChannel()
	{
		await OpenChannelAsync();

		var clientStream = new SshStream(this.clientChannel);

		var closeCompletion = new TaskCompletionSource<bool>();
		this.serverChannel.Closed += (sender, e) =>
		{
			closeCompletion.SetResult(true);
		};

		clientStream.Close();
		await closeCompletion.Task.WithTimeout(Timeout);
	}

	[Fact]
	public async Task ClosedStreamCannotReadOrWrite()
	{
		await OpenChannelAsync();

		var clientStream = new SshStream(this.clientChannel);
		Assert.True(clientStream.CanRead);
		Assert.True(clientStream.CanWrite);

		clientStream.Close();

		Assert.False(clientStream.CanRead);
		Assert.False(clientStream.CanWrite);
	}

	[Theory]
	[MemberData(nameof(ChannelTests.GetTestChannelData), MemberType = typeof(ChannelTests))]
	public async Task StreamData(byte[][] data)
	{
		await OpenChannelAsync();

		var clientStream = new SshStream(this.clientChannel);
		var serverStream = new SshStream(this.serverChannel);

		for (int i = 0; i < data.Length; i++)
		{
			await clientStream.WriteAsync(data[i], 0, data[i].Length);

			var buffer = new byte[data[i].Length];
			await serverStream.ReadAsync(buffer, 0, buffer.Length);

			Assert.Equal(data[i], buffer);
		}
	}
}
