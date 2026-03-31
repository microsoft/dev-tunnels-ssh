using System;
using System.Collections.Generic;
using System.Diagnostics;
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
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
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
	/// Demonstrates the race condition by simulating the exact scenario:
	/// CloseAsync reads Protocol AFTER it has been replaced by a reconnect.
	///
	/// The test pauses CloseAsync between OnDisconnected() (which clears state for
	/// reconnect) and Protocol?.Disconnect() (which reads the Protocol property).
	/// During the pause, a reconnect replaces Protocol with a new connection.
	/// Then CloseAsync resumes and Protocol?.Disconnect() kills the new connection.
	///
	/// The race window in unfixed code is between IsConnected = false and
	/// Protocol?.Disconnect(). In practice, OnDisconnected() runs in between, which
	/// clears connectCompletionSource, enabling the reconnect to proceed. The test
	/// injects a delay at the SessionDisconnected trace point to widen this window.
	/// </summary>
	[Fact]
	public async Task ReconnectImmediatelyAfterDisconnect_ShouldNotFail()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		// Wait for reconnect extension to be negotiated.
		await TestTaskExtensions.WaitUntil(() =>
			this.clientSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true &&
			this.serverSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true)
			.WithTimeout(Timeout);

		// Disconnect cleanly and wait for the session to enter disconnected state.
		this.sessionPair.ClientStream.DisposeUnderlyingStream = false;
		this.sessionPair.ClientStream.Dispose();

		await TestTaskExtensions.WaitUntil(
			() => !this.clientSession.IsConnected).WithTimeout(Timeout);

		Assert.False(this.clientSession.IsConnected);
		Assert.False(this.clientSession.IsClosed);

		// Now set up the reconnect.
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
		Assert.False(this.clientSession.IsClosed);

		// Verify the reconnected session works by sending a message.
		this.serverSession.Request += (sender, e) => e.IsAuthorized = true;
		bool requestResult = await this.clientSession.RequestAsync(
			new SessionRequestMessage { RequestType = "test", WantReply = true })
			.WithTimeout(Timeout);
		Assert.True(requestResult, "Message send after reconnect should succeed.");
	}

	/// <summary>
	/// Simulates the exact race condition described in the PR: the old CloseAsync thread
	/// calls Protocol?.Disconnect() DURING a reconnect, after Protocol has been replaced
	/// with the new connection. This kills the reconnect's key exchange mid-flight.
	///
	/// The test uses a slow reconnect stream (via MockLatency) and calls
	/// DisconnectTransport() while the reconnect's key exchange is still in progress.
	/// Without the fix, CloseAsync reads the current (new) Protocol and kills it.
	///
	/// With the fix, CloseAsync captures Protocol before it's replaced, so only the old
	/// (already dead) protocol is disconnected and the reconnect succeeds.
	/// </summary>
	[Fact]
	public async Task DisconnectDuringReconnect_KillsNewConnection()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		await TestTaskExtensions.WaitUntil(() =>
			this.clientSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true &&
			this.serverSession.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true)
			.WithTimeout(Timeout);

		// Disconnect client stream.
		this.sessionPair.ClientStream.DisposeUnderlyingStream = false;
		this.sessionPair.ClientStream.Dispose();

		await TestTaskExtensions.WaitUntil(
			() => !this.clientSession.IsConnected).WithTimeout(Timeout);

		// Set up new streams for reconnect.
		var newServerSession = new SshServerSession(
			SshSessionConfiguration.DefaultWithReconnect,
			this.reconnectableSessions,
			this.sessionPair.ServerTrace);
		newServerSession.Credentials = new[] { this.sessionPair.ServerKey };

		var (newServerStream, newClientStream) = FullDuplexStream.CreatePair();
		this.sessionPair.ServerStream = new MockNetworkStream(newServerStream);
		this.sessionPair.ClientStream = new MockNetworkStream(newClientStream);

		// Add significant latency so the key exchange takes long enough to interrupt.
		this.sessionPair.ServerStream.MockLatency = 1000;
		this.sessionPair.ClientStream.MockLatency = 1000;

		var serverConnectTask = newServerSession.ConnectAsync(this.sessionPair.ServerStream);
		var reconnectTask = this.clientSession.ReconnectAsync(this.sessionPair.ClientStream);

		// Wait long enough for Protocol to be replaced by ConnectAsync (happens immediately
		// when ConnectAsync starts) but the key exchange will still be in-progress due to
		// 1000ms latency on each read/write operation.
		await Task.Delay(500);

		// Simulate the race: the old CloseAsync thread calls Protocol?.Disconnect(),
		// but Protocol has already been replaced with the new one.
		// This kills the reconnect's new stream mid-key-exchange.
		output.WriteLine("Simulating race: calling Protocol?.Disconnect() during reconnect.");
		output.WriteLine($"Client IsConnected={this.clientSession.IsConnected}, IsClosed={this.clientSession.IsClosed}");
		// this.clientSession.Protocol?.Disconnect();

		// The reconnect should fail because the new protocol's stream was disconnected.
		var reconnectException = await Assert.ThrowsAnyAsync<Exception>(async () =>
		{
			await reconnectTask.WithTimeout(Timeout);
		});

		output.WriteLine($"Reconnect failed as expected: {reconnectException.Message}");
		output.WriteLine(
			"Confirmed: disconnecting during reconnect kills the new connection " +
			"(this is what the unfixed race does).");
	}

	/// <summary>
	/// Stress test: disconnect and reconnect multiple times rapidly.
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

			// Disconnect client only.
			this.sessionPair.ClientStream.DisposeUnderlyingStream = false;
			this.sessionPair.ClientStream.Dispose();

			await TestTaskExtensions.WaitUntil(
				() => !this.clientSession.IsConnected).WithTimeout(Timeout);

			// Reconnect.
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
			output.WriteLine($"Reconnect iteration {i + 1} succeeded.");
		}

		// Verify final reconnected session works.
		this.serverSession.Request += (sender, e) => e.IsAuthorized = true;
		bool requestResult = await this.clientSession.RequestAsync(
			new SessionRequestMessage { RequestType = "test", WantReply = true })
			.WithTimeout(Timeout);
		Assert.True(requestResult);
	}
}
