using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Messages;
using Nerdbank.Streams;
using Xunit;
using Xunit.Abstractions;

namespace Microsoft.DevTunnels.Ssh.Test;

public class ReconnectTests : IDisposable
{
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
	private static readonly TimeSpan LongTimeout = TimeSpan.FromSeconds(100);
	private static readonly SessionRequestMessage TestRequestMessage =
		new SessionRequestMessage { RequestType = "test", WantReply = true };

	private readonly CancellationToken cancellation;
	private SessionPair sessionPair;
	private SshServerSession serverSession;
	private SshClientSession clientSession;
	private ICollection<SshServerSession> reconnectableSessions;
	private TaskCompletionSource<EventArgs> clientDisconnectedCompletion =
		new TaskCompletionSource<EventArgs>();
	private TaskCompletionSource<EventArgs> serverDisconnectedCompletion =
		new TaskCompletionSource<EventArgs>();
	private TaskCompletionSource<EventArgs> serverReconnectedCompletion =
		new TaskCompletionSource<EventArgs>();
	private TaskCompletionSource<byte[]> serverReceivedCompletion;
	private TaskCompletionSource<byte[]> clientReceivedCompletion;

	public ReconnectTests(ITestOutputHelper testOutput)
	{
		InitializeSessionPair(testOutput);
		this.cancellation = new CancellationTokenSource(LongTimeout).Token;
	}

	public void Dispose()
	{
		this.sessionPair.Dispose();
	}

	private static void SetKeyRotationThreshold(SshSession session, int value)
	{
		var keyRotationThresholdProperty = typeof(SshSessionConfiguration).GetProperty(
			"KeyRotationThreshold", BindingFlags.NonPublic | BindingFlags.Instance);
		keyRotationThresholdProperty.SetValue(session.Config, value);
	}

	private void InitializeSessionPair(ITestOutputHelper testOutput)
	{
		var serverConfig = SshSessionConfiguration.DefaultWithReconnect;
		var clientConfig = SshSessionConfiguration.DefaultWithReconnect;

		this.reconnectableSessions = new List<SshServerSession>();
		this.sessionPair = new SessionPair(
			testOutput, serverConfig, clientConfig, this.reconnectableSessions);
		this.serverSession = this.sessionPair.ServerSession;
		this.clientSession = this.sessionPair.ClientSession;

		this.clientSession.Disconnected += (sender, e) =>
			this.clientDisconnectedCompletion.TrySetResult(e);
		this.serverSession.Disconnected += (sender, e) =>
			this.serverDisconnectedCompletion.TrySetResult(e);
		this.serverSession.Reconnected += (sender, e) =>
			this.serverReconnectedCompletion.TrySetResult(e);

		this.clientSession.Closed += (sender, e) =>
			this.clientDisconnectedCompletion.TrySetException(
			e.Exception ?? new Exception("Session closed."));
		this.serverSession.Closed += (sender, e) =>
			this.serverDisconnectedCompletion.TrySetException(
			e.Exception ?? new Exception("Session closed."));
	}

	private async Task<(SshChannel, SshChannel)> InitializeChannelPairAsync(
		bool withCompletions = true)
	{
		var serverChannelTask = this.serverSession.AcceptChannelAsync().WithTimeout(Timeout);
		var clientChannel = await this.clientSession.OpenChannelAsync().WithTimeout(Timeout);
		var serverChannel = await serverChannelTask;

		if (withCompletions)
		{
			this.serverReceivedCompletion = new TaskCompletionSource<byte[]>();
			this.clientReceivedCompletion = new TaskCompletionSource<byte[]>();
		}

		serverChannel.DataReceived += (sender, data) =>
		{
			serverChannel.AdjustWindow((uint)data.Count);

			if (withCompletions)
			{
				this.serverReceivedCompletion.SetResult(data.Copy().Array);
			}
		};
		clientChannel.DataReceived += (sender, data) =>
		{
			clientChannel.AdjustWindow((uint)data.Count);

			if (withCompletions)
			{
				this.clientReceivedCompletion.SetResult(data.Copy().Array);
			}
		};

		return (serverChannel, clientChannel);
	}

	private async Task ReconnectAsync(bool waitUntilDisconnected = true)
	{
		if (waitUntilDisconnected)
		{
			// Avoid test timing problems by waiting until the sessions are fully disconnected.
			await TaskExtensions.WaitUntil(() =>
				!this.clientSession.IsConnected &&
				!this.serverSession.IsConnected).WithTimeout(Timeout);
		}

		Assert.False(
			this.serverSession.IsClosed,
			"Server session should not be closed before reconnecting.");

		Assert.Collection(this.reconnectableSessions, (s) => Assert.Equal(this.serverSession, s));

		this.serverReconnectedCompletion = new TaskCompletionSource<EventArgs>();
		var newServerSession = new SshServerSession(
			SshSessionConfiguration.DefaultWithReconnect,
			this.reconnectableSessions,
			this.sessionPair.ServerTrace);
		newServerSession.Credentials = new[] { this.sessionPair.ServerKey };

		bool serverDisconnected = false;
		bool serverRequest = false;
		newServerSession.Disconnected += (sender, e) => serverDisconnected = true;
		newServerSession.Request += (sender, e) => serverRequest = true;

		// Reconnect the session using a new pair of streams (and a temporary server session).
		var (newServerStream, newClientStream) = FullDuplexStream.CreatePair();
		this.sessionPair.ServerStream = new MockNetworkStream(newServerStream);
		this.sessionPair.ClientStream = new MockNetworkStream(newClientStream);
		var serverConnectTask = newServerSession.ConnectAsync(this.sessionPair.ServerStream);
		var reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);
		await reconnectTask.WithTimeout(Timeout);
		await serverConnectTask.WithTimeout(Timeout);
		await this.serverReconnectedCompletion.Task.WithTimeout(Timeout);

		Assert.True(newServerSession.IsClosed, "New server session should be closed.");
		Assert.False(this.clientSession.IsClosed, "Client session should not be closed.");
		Assert.False(this.serverSession.IsClosed, "Server session should not be closed.");
		Assert.False(serverDisconnected, "New server session shouldn't raise disconnected event.");
		Assert.False(serverRequest, "New server session should intercept the reconnect request.");

		// The session should still be in the reconnectable collection.
		Assert.Collection(this.reconnectableSessions, (s) => Assert.Equal(this.serverSession, s));
	}

	private async Task WaitUntilReconnectEnabled()
	{
		Assert.True(this.serverSession.IsConnected);
		Assert.True(this.clientSession.IsConnected);

		// Reconnect is not enabled until a few messages are exchanged.
		await TaskExtensions.WaitUntil(() =>
			this.serverSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true &&
			this.clientSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true);

		await TaskExtensions.WaitUntil(() =>
		{
			lock (this.reconnectableSessions)
			{
				return this.reconnectableSessions.Contains(this.serverSession);
			}
		});
	}

	[Fact]
	public async Task DisconnectViaStreamClose()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		this.sessionPair.Disconnect();

		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		Assert.False(this.clientSession.IsConnected);
		Assert.False(this.clientSession.IsClosed);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);
		Assert.False(this.serverSession.IsConnected);
		Assert.False(this.serverSession.IsClosed);
	}

	[Fact]
	public async Task DisconnectViaStreamException()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		this.sessionPair.Disconnect(new Exception("Mock exception."));

		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		Assert.False(this.clientSession.IsConnected);
		Assert.False(this.clientSession.IsClosed);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);
		Assert.False(this.serverSession.IsConnected);
		Assert.False(this.serverSession.IsClosed);
	}

	[Fact]
	public async Task DisconnectViaClientSessionClose()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		await this.sessionPair.ClientSession.CloseAsync(SshDisconnectReason.ConnectionLost);

		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		Assert.False(this.clientSession.IsConnected);
		Assert.False(this.clientSession.IsClosed);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);
		Assert.False(this.serverSession.IsConnected);
		Assert.False(this.serverSession.IsClosed);
	}

	[Fact]
	public async Task DisconnectViaServerSessionClose()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		await this.sessionPair.ServerSession.CloseAsync(SshDisconnectReason.ConnectionLost);

		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		Assert.False(this.clientSession.IsConnected);
		Assert.False(this.clientSession.IsClosed);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);
		Assert.False(this.serverSession.IsConnected);
		Assert.False(this.serverSession.IsClosed);
	}

	[Fact]
	public async Task Reconnect()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);

		this.sessionPair.Disconnect();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

		await ReconnectAsync();

		// Verify messages can be sent and received after reconnecting.
		this.serverSession.Request += (sender, e) => e.IsAuthorized = true;
		bool requestResult = await this.clientSession.RequestAsync(
			new SessionRequestMessage { RequestType = "test", WantReply = true })
			.WithTimeout(Timeout);
		Assert.True(requestResult);
	}

	[Fact]
	public async Task ReconnectBeforeServerDisconnected()
	{
		// The server may not immediately detect the network disconnection, especially
		// if it is not trying to send any messages. Meanwhile the client may already try
		// to reconnect. That should work so the reconnection is not unnecessarily delayed.

		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);

		this.sessionPair.ClientStream.DisposeUnderlyingStream = false;
		this.sessionPair.ClientStream.Dispose();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		Assert.False(this.serverDisconnectedCompletion.Task.IsCompleted);

		await ReconnectAsync(waitUntilDisconnected: false);
	}

	[Fact]
	public async Task ReconnectChannel()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		var (serverChannel, clientChannel) = await InitializeChannelPairAsync();

		var testData = new byte[] { 1, 2, 3 };
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
		await this.clientReceivedCompletion.Task.WithTimeout(Timeout);

		this.sessionPair.Disconnect();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

		await ReconnectAsync();

		// Send more channel messages and verify they are received.
		this.serverReceivedCompletion = new TaskCompletionSource<byte[]>();
		this.clientReceivedCompletion = new TaskCompletionSource<byte[]>();
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
		await this.clientReceivedCompletion.Task.WithTimeout(Timeout);
	}

	[Fact]
	public async Task ReconnectWithRetransmittedClientData()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		var (serverChannel, clientChannel) = await InitializeChannelPairAsync();

		var testData = new byte[] { 1, 2, 3 };
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
		await this.clientReceivedCompletion.Task.WithTimeout(Timeout);

		this.serverReceivedCompletion = new TaskCompletionSource<byte[]>();
		this.sessionPair.ServerStream.Dispose();
		this.sessionPair.ClientStream.MockDisconnect(new Exception("Mock disconnect."), 36);
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		Assert.True(this.sessionPair.ClientStream.IsClosed);

		// The last sent message should have been dropped by the disconnection.
		await Task.Delay(5);
		Assert.False(this.serverReceivedCompletion.Task.IsCompleted);

		await ReconnectAsync();

		// The dropped message should be retransmitted after reconnection.
		await this.serverReceivedCompletion.Task.WithTimeout(Timeout);

		// Send more channel messages and verify they are received.
		this.serverReceivedCompletion = new TaskCompletionSource<byte[]>();
		this.clientReceivedCompletion = new TaskCompletionSource<byte[]>();
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
		await this.clientReceivedCompletion.Task.WithTimeout(Timeout);
	}

	[Fact]
	public async Task ReconnectWithRetransmittedServerData()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		var (serverChannel, clientChannel) = await InitializeChannelPairAsync();

		var testData = new byte[] { 1, 2, 3 };
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
		await this.clientReceivedCompletion.Task.WithTimeout(Timeout);

		this.clientReceivedCompletion = new TaskCompletionSource<byte[]>();
		this.sessionPair.ServerStream.MockDisconnect(new Exception("Mock disconnect."), 36);
		this.sessionPair.ClientStream.Dispose();
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		Assert.True(this.sessionPair.ServerStream.IsClosed);

		// The last sent message should have been dropped by the disconnection.
		await Task.Delay(5);
		Assert.False(this.clientReceivedCompletion.Task.IsCompleted);

		await ReconnectAsync();

		// The dropped message should be retransmitted after reconnection.
		await this.clientReceivedCompletion.Task.WithTimeout(Timeout);

		// Send more channel messages and verify they are received.
		this.serverReceivedCompletion = new TaskCompletionSource<byte[]>();
		this.clientReceivedCompletion = new TaskCompletionSource<byte[]>();
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
		await this.clientReceivedCompletion.Task.WithTimeout(Timeout);
	}

	[Fact]
	public async Task SendWhileDisconnected()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		var (serverChannel, clientChannel) = await InitializeChannelPairAsync();

		var testData = new byte[] { 1, 2, 3 };
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverReceivedCompletion.Task.WithTimeout(Timeout);
		await clientReceivedCompletion.Task.WithTimeout(Timeout);

		this.sessionPair.Disconnect();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

		// Sending on a disconnected session should still be possible. (Messages are buffered.)
		this.clientReceivedCompletion = new TaskCompletionSource<byte[]>();
		this.serverReceivedCompletion = new TaskCompletionSource<byte[]>();
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);

		await ReconnectAsync();

		// The messages sent during disconnection should be received after reconnect.
		await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
		await this.clientReceivedCompletion.Task.WithTimeout(Timeout);

		this.clientReceivedCompletion = new TaskCompletionSource<byte[]>();
		this.serverReceivedCompletion = new TaskCompletionSource<byte[]>();
		await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
		await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
		await this.clientReceivedCompletion.Task.WithTimeout(Timeout);
	}

	[Fact]
	public async Task MultiReconnect()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		var (serverChannel, clientChannel) = await InitializeChannelPairAsync();

		var testData = new byte[] { 1, 2, 3 };

		for (int i = 0; i < 3; i++)
		{
			// Send some messages while the session is connected.
			this.clientReceivedCompletion = new TaskCompletionSource<byte[]>();
			this.serverReceivedCompletion = new TaskCompletionSource<byte[]>();
			await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
			await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
			await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
			await this.clientReceivedCompletion.Task.WithTimeout(Timeout);

			// Disconnect while no messages are being sent.
			this.sessionPair.Disconnect();

			// Send some messages while the session is disconnected.
			this.clientReceivedCompletion = new TaskCompletionSource<byte[]>();
			this.serverReceivedCompletion = new TaskCompletionSource<byte[]>();
			await clientChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);
			await serverChannel.SendAsync(testData, cancellation).WithTimeout(Timeout);

			await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
			await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

			await ReconnectAsync();

			// The messages sent during disconnection should be received after reconnect.
			await this.serverReceivedCompletion.Task.WithTimeout(Timeout);
			await this.clientReceivedCompletion.Task.WithTimeout(Timeout);
		}
	}

	[Fact]
	public async Task ReconnectThenKeyExchange()
	{
		const int testKeyRotationThreshold = 10 * 1024 * 1024; // 10 MB
		SetKeyRotationThreshold(this.sessionPair.ServerSession, testKeyRotationThreshold);
		SetKeyRotationThreshold(this.sessionPair.ClientSession, testKeyRotationThreshold);

		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		var (serverChannel, clientChannel) = await InitializeChannelPairAsync(
			withCompletions: false);

		this.sessionPair.Disconnect();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

		await ReconnectAsync();

		// After reconnecting, send enough data to trigger a key rotation.
		const int largeMessageSize = 1024 * 1024 * 3 / 2;
		byte[] largeData = new byte[largeMessageSize];
		for (int i = 0; i < largeData.Length; i++) largeData[i] = (byte)(i & 0xFF);

		const int messageCount = testKeyRotationThreshold / largeMessageSize + 5;
		for (int i = 0; i < messageCount; i++)
		{
			await clientChannel.SendAsync(largeData, cancellation)
				.WithTimeout(TimeSpan.FromSeconds(Timeout.TotalSeconds * 2));
		}
	}

	[Fact]
	public async Task ReconnectSessionNotFound()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);

		this.sessionPair.Disconnect();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

		this.reconnectableSessions.Clear();

		var newServerSession = new SshServerSession(
			SshSessionConfiguration.DefaultWithReconnect,
			this.reconnectableSessions,
			this.sessionPair.ServerTrace);
		newServerSession.Credentials = new[] { this.sessionPair.ServerKey };

		bool serverDisconnected = false;
		newServerSession.Disconnected += (sender, e) => serverDisconnected = true;
		bool clientDisconnected = false;
		this.clientSession.Disconnected += (sender, e) => clientDisconnected = true;

		var (newServerStream, newClientStream) = FullDuplexStream.CreatePair();
		this.sessionPair.ServerStream = new MockNetworkStream(newServerStream);
		this.sessionPair.ClientStream = new MockNetworkStream(newClientStream);
		var serverConnectTask = newServerSession.ConnectAsync(this.sessionPair.ServerStream);
		var reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);

		await serverConnectTask.WithTimeout(Timeout);
		var reconnectException = await Assert.ThrowsAsync<SshReconnectException>(
			() => reconnectTask.WithTimeout(Timeout));
		Assert.Equal(
			SshReconnectFailureReason.SessionNotFound,
			reconnectException.FailureReason);
		Assert.False(serverDisconnected);
		Assert.False(clientDisconnected);
	}

	[Fact]
	public async Task AcceptChannelOnServerReconnect()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);

		this.sessionPair.Disconnect();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

		var newServerSession = new SshServerSession(
			SshSessionConfiguration.DefaultWithReconnect,
			this.reconnectableSessions,
			this.sessionPair.ServerTrace);
		newServerSession.Credentials = new[] { this.sessionPair.ServerKey };

		var (newServerStream, newClientStream) = FullDuplexStream.CreatePair();
		this.sessionPair.ServerStream = new MockNetworkStream(newServerStream);
		this.sessionPair.ClientStream = new MockNetworkStream(newClientStream);
		var reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);
		var acceptChannelTask = Assert.ThrowsAsync<ObjectDisposedException>(async () =>
		{
			await newServerSession.ConnectAsync(this.sessionPair.ServerStream);
			await newServerSession.AcceptChannelAsync();
		});
		await Task.WhenAll(reconnectTask, acceptChannelTask).WithTimeout(Timeout);
		await reconnectTask;
		await acceptChannelTask;
	}

	[Fact]
	public async Task ReconnectAfterInterruptedReconnect()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		var (serverChannel, clientChannel) = await InitializeChannelPairAsync();

		this.sessionPair.Disconnect();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

		this.serverReconnectedCompletion = new TaskCompletionSource<EventArgs>();
		var newServerSession = new SshServerSession(
			SshSessionConfiguration.DefaultWithReconnect,
			this.reconnectableSessions,
			this.sessionPair.ServerTrace);
		newServerSession.Credentials = new[] { this.sessionPair.ServerKey };

		var (newServerStream, newClientStream) = FullDuplexStream.CreatePair();
		this.sessionPair.ServerStream = new MockNetworkStream(newServerStream);
		this.sessionPair.ClientStream = new MockNetworkStream(newClientStream);

		// Cause the first reconnect attempt to be interrupted by another disconnection.
		this.sessionPair.ClientStream.MockDisconnect(new Exception("Test disconnection"), 50);

		var serverConnectTask = newServerSession.ConnectAsync(this.sessionPair.ServerStream);
		var reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);
		var ex = await Assert.ThrowsAnyAsync<Exception>(() => reconnectTask.WithTimeout(Timeout));
		Assert.True(ex is SshConnectionException || ex is ObjectDisposedException);
		var ex2 = await Assert.ThrowsAnyAsync<Exception>(() => serverConnectTask.WithTimeout(Timeout));
		Assert.True(ex2 is SshConnectionException || ex2 is ObjectDisposedException);

		Assert.False(this.clientSession.IsConnected);
		Assert.False(this.serverSession.IsConnected);
		Assert.Collection(this.reconnectableSessions, (s) => Assert.Equal(this.serverSession, s));

		// Try again, this time with no interruption.
		newServerSession = new SshServerSession(
			SshSessionConfiguration.DefaultWithReconnect,
			this.reconnectableSessions,
			this.sessionPair.ServerTrace);
		newServerSession.Credentials = new[] { this.sessionPair.ServerKey };

		var (newServerStream2, newClientStream2) = FullDuplexStream.CreatePair();
		this.sessionPair.ServerStream = new MockNetworkStream(newServerStream2);
		this.sessionPair.ClientStream = new MockNetworkStream(newClientStream2);

		serverConnectTask = newServerSession.ConnectAsync(this.sessionPair.ServerStream);
		reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);
		await reconnectTask.WithTimeout(Timeout);
		await serverConnectTask.WithTimeout(Timeout);
		await this.serverReconnectedCompletion.Task.WithTimeout(Timeout);
	}

	[Fact]
	public async Task ReconnectWrongSessionId()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);

		this.sessionPair.Disconnect();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

		// Avoid test timing problems by waiting until the sessions are fully disconnected.
		await TaskExtensions.WaitUntil(() =>
			!this.clientSession.IsConnected &&
			!this.serverSession.IsConnected).WithTimeout(Timeout);

		var newServerSession = new SshServerSession(
			SshSessionConfiguration.DefaultWithReconnect,
			this.reconnectableSessions,
			this.sessionPair.ServerTrace);
		newServerSession.Credentials = new[] { this.sessionPair.ServerKey };

		// Change the ID of the reconnectable server session to invalidate the reconnect attempt.
		Array.Clear(this.reconnectableSessions.Single().SessionId, 0, 10);

		// Reconnect the session using a new pair of streams (and a temporary server session).
		var (newServerStream, newClientStream) = FullDuplexStream.CreatePair();
		this.sessionPair.ServerStream = new MockNetworkStream(newServerStream);
		this.sessionPair.ClientStream = new MockNetworkStream(newClientStream);
		var serverConnectTask = newServerSession.ConnectAsync(this.sessionPair.ServerStream);
		var reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);

		// Reconnection should fail.
		var reconnectException = await Assert.ThrowsAsync<SshReconnectException>(
			() => reconnectTask.WithTimeout(Timeout));
		Assert.Equal(
			SshReconnectFailureReason.SessionNotFound,
			reconnectException.FailureReason);
		await serverConnectTask.WithTimeout(Timeout);
	}


	[Fact]
	public async Task ReconnectWrongHostKey()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);

		this.sessionPair.Disconnect();
		await this.clientDisconnectedCompletion.Task.WithTimeout(Timeout);
		await this.serverDisconnectedCompletion.Task.WithTimeout(Timeout);

		// Avoid test timing problems by waiting until the sessions are fully disconnected.
		await TaskExtensions.WaitUntil(() =>
			!this.clientSession.IsConnected &&
			!this.serverSession.IsConnected).WithTimeout(Timeout);

		var newServerSession = new SshServerSession(
			SshSessionConfiguration.DefaultWithReconnect,
			this.reconnectableSessions,
			this.sessionPair.ServerTrace);

		// Change the host key of the server session to invalidate the reconnect attempt.
		newServerSession.Credentials = new[]
		{
				SshAlgorithms.PublicKey.ECDsaSha2Nistp384.GenerateKeyPair(),
			};

		// Reconnect the session using a new pair of streams (and a temporary server session).
		var (newServerStream, newClientStream) = FullDuplexStream.CreatePair();
		this.sessionPair.ServerStream = new MockNetworkStream(newServerStream);
		this.sessionPair.ClientStream = new MockNetworkStream(newClientStream);
		var serverConnectTask = newServerSession.ConnectAsync(this.sessionPair.ServerStream);
		var reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);

		// Reconnection should fail.
		var reconnectException = await Assert.ThrowsAsync<SshReconnectException>(
			() => reconnectTask.WithTimeout(Timeout));
		Assert.Equal(
			SshReconnectFailureReason.DifferentServerHostKey,
			reconnectException.FailureReason);
		await serverConnectTask.WithTimeout(Timeout);
	}

	[Fact]
	public async Task ReconnectWhileStreaming()
	{
		this.sessionPair.ClientSession.Config.TraceChannelData = true;

		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		await WaitUntilReconnectEnabled().WithTimeout(Timeout);
		var (serverChannel, clientChannel) = await InitializeChannelPairAsync(withCompletions: false);

		// Start continuously sending/receiving data with both client and server sessions.
		Func<SshChannel, CancellationToken, Task<int>> sendAndReceiveUntilEnd =
			async (channel, cancellation) =>
		{
			var stream = new SshStream(channel);
			int receiveCount = 0;
			var receiveBuffer = new byte[4];
			string name = channel.Session is SshClientSession ? "Client" : "Server";
			while (true)
			{
				bool sent = false;
				var message = BitConverter.GetBytes(receiveCount);
				try
				{
					channel.Session.Trace.TraceInformation($"{name} sending *{receiveCount:x2}");
					await stream.WriteAsync(message, 0, message.Length, cancellation)
						.WithTimeout(Timeout);
					sent = true;
					channel.Session.Trace.TraceInformation($"{name} receiving *{receiveCount:x2}");
					await stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length, cancellation)
						.WithTimeout(Timeout);
					Assert.Equal(receiveCount, BitConverter.ToInt32(receiveBuffer, 0));
					channel.Session.Trace.TraceInformation($"{name} verified *{receiveCount:x2}");
				}
				catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
				{
					break;
				}
				catch (Exception)
				{
					channel.Session.Trace.TraceInformation(
						$"{name} failed to {(sent ? "receive" : "send")} *{receiveCount:x2}");

					stream.Close();
					throw;
				}

				receiveCount++;
			}

			return receiveCount;
		};

		var streamCancellationSource = new CancellationTokenSource();
		var clientStreamTask = Task.Run(async () => await sendAndReceiveUntilEnd(
			clientChannel, streamCancellationSource.Token));
		var serverStreamTask = Task.Run(async () => await sendAndReceiveUntilEnd(
			serverChannel, streamCancellationSource.Token));

		// Wait for a few messages to be exchanged.
		await Task.Delay(100);

		// Disconnect and reconnect.
		this.sessionPair.ServerStream.Dispose();
		this.sessionPair.ClientStream.MockDisconnect(new Exception("Mock disconnect."), 36);

		await TaskExtensions.WaitUntil(() =>
			!this.clientSession.IsConnected &&
			!this.serverSession.IsConnected).WithTimeout(Timeout);

		long serverBytesReceivedBeforeReconnect = serverChannel.Metrics.BytesReceived;
		long clientBytesReceivedBeforeReconnect = clientChannel.Metrics.BytesReceived;

		await ReconnectAsync();

		// Wait for a few more messages to be exchanged.
		await Task.Delay(100);

		// Verify some messages were received after reconnection.
		Assert.True(serverChannel.Metrics.BytesReceived > serverBytesReceivedBeforeReconnect);
		Assert.True(clientChannel.Metrics.BytesReceived > clientBytesReceivedBeforeReconnect);

		streamCancellationSource.Cancel();
		int clientPacketsReceived = await clientStreamTask;
		int serverPacketsReceived = await serverStreamTask;
		Assert.NotEqual(0, clientPacketsReceived);
		Assert.NotEqual(0, serverPacketsReceived);
	}
}
