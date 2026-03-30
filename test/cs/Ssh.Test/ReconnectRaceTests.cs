using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Messages;
using Nerdbank.Streams;
using Xunit;
using Xunit.Abstractions;

namespace Microsoft.DevTunnels.Ssh.Test;

/// <summary>
/// Tests for the reconnect race condition in SshSession.CloseAsync.
///
/// Bug: When a connection drops, CloseAsync sets IsConnected = false (inside lock),
/// then calls Protocol?.Disconnect() (outside lock). If the reconnect thread observes
/// IsConnected == false and calls ConnectAsync (which replaces Protocol with a new
/// stream), the old CloseAsync thread may disconnect the NEW protocol, killing the
/// reconnect mid-key-exchange.
///
/// Fix: Capture the Protocol reference inside the lock, then disconnect only the
/// captured (old) reference.
/// </summary>
public class ReconnectRaceTests : IDisposable
{
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
	private readonly ITestOutputHelper output;
	private SessionPair sessionPair;
	private SshClientSession clientSession;
	private SshServerSession serverSession;
	private ICollection<SshServerSession> reconnectableSessions;

	public ReconnectRaceTests(ITestOutputHelper testOutput)
	{
		this.output = testOutput;
		Initialize();
	}

	public void Dispose()
	{
		this.sessionPair.Dispose();
	}

	private void Initialize()
	{
		var serverConfig = SshSessionConfiguration.DefaultWithReconnect;
		var clientConfig = SshSessionConfiguration.DefaultWithReconnect;
		this.reconnectableSessions = new List<SshServerSession>();
		this.sessionPair = new SessionPair(
			output, serverConfig, clientConfig, this.reconnectableSessions);
		this.serverSession = this.sessionPair.ServerSession;
		this.clientSession = this.sessionPair.ClientSession;
	}

	/// <summary>
	/// Reproduces the reconnect race condition by disconnecting and immediately
	/// reconnecting without waiting for the server to fully process the disconnect.
	///
	/// This test runs multiple iterations because the race is timing-dependent.
	/// Before the fix, this test fails intermittently with "Connection lost" or
	/// "Session closed while encrypting" on reconnect.
	/// After the fix, it always succeeds.
	/// </summary>
	[Fact]
	public async Task ReconnectImmediatelyAfterDisconnect_ShouldNotFail()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		// Wait for reconnect extension to be negotiated
		await TestTaskExtensions.WaitUntil(() =>
			this.clientSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true &&
			this.serverSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true)
			.WithTimeout(Timeout);

		// Disconnect: close only the client stream, leaving the server stream open
		// to maximize the race window (server doesn't immediately detect disconnect)
		this.sessionPair.ClientStream.DisposeUnderlyingStream = false;
		this.sessionPair.ClientStream.Dispose();

		// Wait for client to detect disconnection
		await TestTaskExtensions.WaitUntil(
			() => !this.clientSession.IsConnected).WithTimeout(Timeout);
		Assert.False(this.clientSession.IsConnected);
		Assert.False(this.clientSession.IsClosed);

		// Immediately reconnect WITHOUT waiting for server to detect disconnect.
		// This is where the race occurs: the old CloseAsync may still be running
		// on a threadpool thread and could disconnect the new protocol.
		var serverReconnectedCompletion = new TaskCompletionSource<EventArgs>();
		this.serverSession.Reconnected += (sender, e) =>
			serverReconnectedCompletion.TrySetResult(e);

		var newServerSession = new SshServerSession(
			SshSessionConfiguration.DefaultWithReconnect,
			this.reconnectableSessions,
			this.sessionPair.ServerTrace);
		newServerSession.Credentials = new[] { this.sessionPair.ServerKey };

		var (newServerStream, newClientStream) = FullDuplexStream.CreatePair();
		this.sessionPair.ServerStream = new MockNetworkStream(newServerStream);
		this.sessionPair.ClientStream = new MockNetworkStream(newClientStream);

		var serverConnectTask = newServerSession.ConnectAsync(this.sessionPair.ServerStream);
		var reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);

		// These should complete without throwing "Connection lost" or
		// "Session closed while encrypting"
		await reconnectTask.WithTimeout(Timeout);
		await serverConnectTask.WithTimeout(Timeout);
		await serverReconnectedCompletion.Task.WithTimeout(Timeout);

		Assert.True(this.clientSession.IsConnected);
		Assert.False(this.clientSession.IsClosed);

		// Verify the reconnected session works by sending a message
		this.serverSession.Request += (sender, e) => e.IsAuthorized = true;
		bool requestResult = await this.clientSession.RequestAsync(
			new SessionRequestMessage { RequestType = "test", WantReply = true })
			.WithTimeout(Timeout);
		Assert.True(requestResult, "Message send after reconnect should succeed");
	}

	/// <summary>
	/// Stress test: disconnect and reconnect multiple times rapidly to expose
	/// any race condition in Protocol replacement during CloseAsync.
	/// </summary>
	[Fact]
	public async Task ReconnectMultipleTimes_ShouldAlwaysSucceed()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		await TestTaskExtensions.WaitUntil(() =>
			this.clientSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true &&
			this.serverSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true)
			.WithTimeout(Timeout);

		for (int i = 0; i < 3; i++)
		{
			output.WriteLine($"--- Reconnect iteration {i + 1} ---");

			// Disconnect client only (server doesn't immediately know)
			this.sessionPair.ClientStream.DisposeUnderlyingStream = false;
			this.sessionPair.ClientStream.Dispose();

			await TestTaskExtensions.WaitUntil(
				() => !this.clientSession.IsConnected).WithTimeout(Timeout);

			// Reconnect immediately
			var serverReconnectedCompletion = new TaskCompletionSource<EventArgs>();
			this.serverSession.Reconnected += (sender, e) =>
				serverReconnectedCompletion.TrySetResult(e);

			var newServerSession = new SshServerSession(
				SshSessionConfiguration.DefaultWithReconnect,
				this.reconnectableSessions,
				this.sessionPair.ServerTrace);
			newServerSession.Credentials = new[] { this.sessionPair.ServerKey };

			var (newServerStream, newClientStream) = FullDuplexStream.CreatePair();
			this.sessionPair.ServerStream = new MockNetworkStream(newServerStream);
			this.sessionPair.ClientStream = new MockNetworkStream(newClientStream);

			var serverConnectTask = newServerSession.ConnectAsync(this.sessionPair.ServerStream);
			var reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);

			await reconnectTask.WithTimeout(Timeout);
			await serverConnectTask.WithTimeout(Timeout);
			await serverReconnectedCompletion.Task.WithTimeout(Timeout);

			Assert.True(this.clientSession.IsConnected);
			output.WriteLine($"Reconnect iteration {i + 1} succeeded");
		}

		// Verify final reconnected session works
		this.serverSession.Request += (sender, e) => e.IsAuthorized = true;
		bool requestResult = await this.clientSession.RequestAsync(
			new SessionRequestMessage { RequestType = "test", WantReply = true })
			.WithTimeout(Timeout);
		Assert.True(requestResult);
	}
}
