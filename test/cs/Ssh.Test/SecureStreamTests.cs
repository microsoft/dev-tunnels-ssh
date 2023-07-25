using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.Events;
using Nerdbank.Streams;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class SecureStreamTests
{
	private static readonly TimeSpan Timeout = Debugger.IsAttached ?
		TimeSpan.FromDays(1) : TimeSpan.FromSeconds(10);
	private readonly CancellationToken TimeoutToken = new CancellationTokenSource(Timeout).Token;

	private readonly IKeyPair serverKey;
	private readonly IKeyPair clientKey;
	private readonly SshServerCredentials serverCredentials;
	private readonly SshClientCredentials clientCredentials;
	private Stream clientStream;
	private Stream serverStream;

	public SecureStreamTests()
	{
		this.serverKey = SshAlgorithms.PublicKey.ECDsaSha2Nistp384.GenerateKeyPair();
		this.serverCredentials = new SshServerCredentials(serverKey);
		this.clientKey = SshAlgorithms.PublicKey.ECDsaSha2Nistp384.GenerateKeyPair();
		this.clientCredentials = new SshClientCredentials("test", clientKey);

		(this.serverStream, this.clientStream) = FullDuplexStream.CreatePair();
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task AuthenticateServer(bool authenticateSuccess)
	{
		var server = new SecureStream(this.serverStream, this.serverCredentials);
		server.Authenticating += (_, e) =>
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());

		SshAuthenticatingEventArgs serverAuthenticatingEvent = null;
		var client = new SecureStream(this.clientStream, this.clientCredentials);
		client.Authenticating += (_, e) =>
		{
			serverAuthenticatingEvent = e;
			e.AuthenticationTask = Task.FromResult(
				authenticateSuccess ? new ClaimsPrincipal() : null);
		};

		var serverConnectTask = server.ConnectAsync(TimeoutToken);
		var clientConnectTask = client.ConnectAsync(TimeoutToken);
		try
		{
			await Task.WhenAll(serverConnectTask, clientConnectTask);
		}
		catch (Exception)
		{
			Assert.False(authenticateSuccess);
		}

		Assert.Equal(authenticateSuccess, !serverConnectTask.IsFaulted);
		Assert.Equal(authenticateSuccess, !clientConnectTask.IsFaulted);
		if (!authenticateSuccess)
		{
			var serverEx = await Assert.ThrowsAsync<SshConnectionException>(() => serverConnectTask);
			Assert.Equal(SshDisconnectReason.HostKeyNotVerifiable, serverEx.DisconnectReason);

			var clientEx = await Assert.ThrowsAsync<SshConnectionException>(() => clientConnectTask);
			Assert.Equal(SshDisconnectReason.HostKeyNotVerifiable, clientEx.DisconnectReason);
		}

		Assert.Null(serverAuthenticatingEvent?.Username);
		Assert.NotNull(serverAuthenticatingEvent?.PublicKey);
		Assert.True(serverAuthenticatingEvent.PublicKey.GetPublicKeyBytes().Equals(
			this.serverKey.GetPublicKeyBytes()));
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task AuthenticateClient(bool authenticateSuccess)
	{
		SshAuthenticatingEventArgs clientAuthenticatingEvent = null;
		var server = new SecureStream(this.serverStream, this.serverCredentials);
		server.Authenticating += (_, e) =>
		{
			clientAuthenticatingEvent = e;
			e.AuthenticationTask = Task.FromResult(
				authenticateSuccess ? new ClaimsPrincipal() : null);
		};

		var client = new SecureStream(this.clientStream, this.clientCredentials);
		client.Authenticating += (_, e) =>
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());

		var serverConnectTask = server.ConnectAsync(TimeoutToken);
		var clientConnectTask = client.ConnectAsync(TimeoutToken);
		try
		{
			await Task.WhenAll(serverConnectTask, clientConnectTask);
		}
		catch (Exception)
		{
			Assert.False(authenticateSuccess);
		}

		Assert.Equal(authenticateSuccess, !serverConnectTask.IsFaulted);
		Assert.Equal(authenticateSuccess, !clientConnectTask.IsFaulted);
		if (!authenticateSuccess)
		{
			var serverEx = await Assert.ThrowsAsync<SshConnectionException>(() => serverConnectTask);
			Assert.Equal(SshDisconnectReason.NoMoreAuthMethodsAvailable, serverEx.DisconnectReason);

			var clientEx = await Assert.ThrowsAsync<SshConnectionException>(() => clientConnectTask);
			Assert.Equal(SshDisconnectReason.NoMoreAuthMethodsAvailable, clientEx.DisconnectReason);
		}

		Assert.Equal(this.clientCredentials.Username, clientAuthenticatingEvent.Username);
		Assert.NotNull(clientAuthenticatingEvent?.PublicKey);
		Assert.True(clientAuthenticatingEvent.PublicKey.GetPublicKeyBytes().Equals(
			this.clientKey.GetPublicKeyBytes()));
	}

	[Fact]
	public async Task ReadWrite()
	{
		var (server, client) = await ConnectAsync();

		await ExchangeDataAsync(server, client);

		await server.CloseAsync();
		await client.CloseAsync();
	}

	private async Task<(SecureStream Server, SecureStream Client)> ConnectAsync(
		ICollection<SshServerSession> reconnectableSessions = null)
	{
		var server = new SecureStream(
			this.serverStream, this.serverCredentials, reconnectableSessions);
		server.Authenticating += (_, e) =>
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		var client = new SecureStream(
			this.clientStream, this.clientCredentials, enableReconnect: reconnectableSessions != null);
		client.Authenticating += (_, e) =>
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());

		await Task.WhenAll(server.ConnectAsync(TimeoutToken), client.ConnectAsync(TimeoutToken));

		return (server, client);
	}

	private static async Task ExchangeDataAsync(SecureStream server, SecureStream client)
	{
		const string payloadString = "Hello!";
		byte[] payload = Encoding.UTF8.GetBytes(payloadString);
		byte[] result = new byte[100];

		// Write from client, read from server
		await client.WriteAsync(payload, 0, payload.Length);
		int resultCount = await server.ReadAsync(result, 0, result.Length);
		Assert.Equal(payload.Length, resultCount);
		Assert.Equal(payloadString, Encoding.UTF8.GetString(result, 0, resultCount));

		// Write from server, read from client
		await server.WriteAsync(payload, 0, payload.Length);
		resultCount = await client.ReadAsync(result, 0, result.Length);
		Assert.Equal(payload.Length, resultCount);
		Assert.Equal(payloadString, Encoding.UTF8.GetString(result, 0, resultCount));
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task DisposeClosesTransportStream(bool disposeAsync)
	{
		var stream = new MemoryStream();

		var server = new SecureStream(stream, this.serverCredentials);
		Assert.False(server.IsClosed);
		var closedEventRaised = false;
		server.Closed += (_, _) => closedEventRaised = true;

		await DisposeSecureStreamAsync(server, disposeAsync);
		Assert.True(server.IsClosed);
		Assert.True(closedEventRaised);

		// The transport stream should have been disposed.
		Assert.Throws<ObjectDisposedException>(() => stream.WriteByte(0));
	}

	private async ValueTask DisposeSecureStreamAsync(SecureStream stream, bool disposeAsync)
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
	public async Task DisposeRaisesCloseEvent(bool isConnected, bool disposeAsync)
	{
		var server = new SecureStream(this.serverStream, this.serverCredentials);
		server.Authenticating += (_, e) =>
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());

		using var client = new SecureStream(this.clientStream, this.clientCredentials);
		client.Authenticating += (_, e) =>
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());

		var closedEventRaised = false;
		server.Closed += (sender, e) =>
		{
			Assert.Equal(server, sender);
			Assert.Equal(SshDisconnectReason.None, e.Reason);
			Assert.Equal(typeof(SshServerSession).Name + " disposed.", e.Message);
			closedEventRaised = true;
		};

		if (isConnected)
		{
			await Task.WhenAll(
				client.ConnectAsync(TimeoutToken),
				server.ConnectAsync(TimeoutToken));
		}

		await DisposeSecureStreamAsync(server, disposeAsync);

		Assert.True(server.IsClosed);
		Assert.True(closedEventRaised);
	}

	[Fact]
	public async Task ReconnectSecureStream()
	{
		var disconnectableServerStream = new MockNetworkStream(this.serverStream);
		var disconnectableClientStream = new MockNetworkStream(this.clientStream);
		this.serverStream = disconnectableServerStream;
		this.clientStream = disconnectableClientStream;

		List<SshServerSession> reconnectableSessions = new();
		var (server, client) = await ConnectAsync(reconnectableSessions);

		TaskCompletionSource<EventArgs> serverDisconnected = new();
		server.Disconnected += (_, e) => serverDisconnected.TrySetResult(e);
		TaskCompletionSource<EventArgs> clientDisconnected = new();
		client.Disconnected += (_, e) => clientDisconnected.TrySetResult(e);

		await ExchangeDataAsync(server, client);

		disconnectableServerStream.MockDisconnect(new Exception("Mock disconnect."));
		disconnectableClientStream.MockDisconnect(new Exception("Mock disconnect."));

		await serverDisconnected.Task.WithTimeout(Timeout);
		await clientDisconnected.Task.WithTimeout(Timeout);

		var (serverStream2, clientStream2) = FullDuplexStream.CreatePair();
		serverStream2 = new MockNetworkStream(serverStream2);
		clientStream2 = new MockNetworkStream(clientStream2);

		var server2 = new SecureStream(
			serverStream2, this.serverCredentials, reconnectableSessions);
		server2.Authenticating += (_, e) =>
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());

		await Task.WhenAll(
			server2.ConnectAsync(TimeoutToken),
			client.ReconnectAsync(clientStream2, TimeoutToken));

		await ExchangeDataAsync(server, client);
	}
}
