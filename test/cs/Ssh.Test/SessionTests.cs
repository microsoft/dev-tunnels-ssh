using System;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class SessionTests : IDisposable
{
	private const string TestUsername = "test";
	private const string TestPassword = "password";
	private const SshDisconnectReason TestDisconnectReason = (SshDisconnectReason)(9999);
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

	private readonly SessionPair sessionPair;
	private readonly SshClientSession clientSession;
	private readonly SshServerSession serverSession;
	private SemaphoreSlim clientClosedSemaphore = new SemaphoreSlim(0);
	private SemaphoreSlim serverClosedSemaphore = new SemaphoreSlim(0);
	private SshSessionClosedEventArgs clientClosedEvent = null;
	private SshSessionClosedEventArgs serverClosedEvent = null;

	public SessionTests()
	{
		var config = new SshSessionConfiguration();

#if SSH_ENABLE_AESGCM
		config.EncryptionAlgorithms.Clear();
		config.EncryptionAlgorithms.Add(SshAlgorithms.Encryption.Aes256Gcm);
#endif

		this.sessionPair = new SessionPair(config);
		this.clientSession = sessionPair.ClientSession;
		this.serverSession = sessionPair.ServerSession;

		this.clientSession.Closed += (sender, e) =>
		{
			this.clientClosedEvent = e;
			this.clientClosedSemaphore.Release();
		};
		this.serverSession.Closed += (sender, e) =>
		{
			this.serverClosedEvent = e;
			this.serverClosedSemaphore.Release();
		};
	}

	public void Dispose()
	{
		this.clientSession.Dispose();
		this.serverSession.Dispose();
	}

	[Fact]
	public async Task CloseSessionStream()
	{
		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		this.sessionPair.ServerStream.Close();
		this.sessionPair.ClientStream.Close();

		await Task.WhenAll(
			this.serverClosedSemaphore.WaitAsync(),
			this.clientClosedSemaphore.WaitAsync()).WithTimeout(Timeout);

		Assert.NotNull(this.serverClosedEvent);
		Assert.Equal(SshDisconnectReason.ConnectionLost, this.serverClosedEvent.Reason);
		Assert.IsType<SshConnectionException>(this.serverClosedEvent.Exception);
		Assert.Equal(
			SshDisconnectReason.ConnectionLost,
			((SshConnectionException)this.serverClosedEvent.Exception).DisconnectReason);
		Assert.NotNull(this.clientClosedEvent);
		Assert.Equal(SshDisconnectReason.ConnectionLost, this.clientClosedEvent.Reason);
		Assert.IsType<SshConnectionException>(this.clientClosedEvent.Exception);
		Assert.Equal(
			SshDisconnectReason.ConnectionLost,
			((SshConnectionException)this.clientClosedEvent.Exception).DisconnectReason);
	}

	[Fact]
	public async Task CloseServerSession()
	{
		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		await this.serverSession.CloseAsync(TestDisconnectReason);

		await Task.WhenAll(
			this.serverClosedSemaphore.WaitAsync(),
			this.clientClosedSemaphore.WaitAsync()).WithTimeout(Timeout);

		Assert.NotNull(this.clientClosedEvent);
		Assert.Equal(TestDisconnectReason, this.clientClosedEvent.Reason);
		Assert.IsType<SshConnectionException>(this.clientClosedEvent.Exception);
		Assert.Equal(
			TestDisconnectReason,
			((SshConnectionException)this.clientClosedEvent.Exception).DisconnectReason);
	}

	[Fact]
	public async Task CloseClientSession()
	{
		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		await this.clientSession.CloseAsync(TestDisconnectReason);

		await Task.WhenAll(
			this.serverClosedSemaphore.WaitAsync(),
			this.clientClosedSemaphore.WaitAsync()).WithTimeout(Timeout);

		Assert.NotNull(this.serverClosedEvent);
		Assert.Equal(TestDisconnectReason, this.serverClosedEvent.Reason);
		Assert.IsType<SshConnectionException>(this.clientClosedEvent.Exception);
		Assert.Equal(
			TestDisconnectReason,
			((SshConnectionException)this.clientClosedEvent.Exception).DisconnectReason);
	}

	private void OnSessionAuthenticating(object sender, SshAuthenticatingEventArgs e) =>
		e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task NegotiateNoKeyExchange(bool clientForce)
	{
		var clientConfig = new SshSessionConfiguration();
		var serverConfig = new SshSessionConfiguration();

		if (clientForce)
		{
			// Clear all the client algorithms except for kex:none; support kex:none on the server.
			clientConfig.KeyExchangeAlgorithms.Clear();
			clientConfig.KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.None);
			clientConfig.PublicKeyAlgorithms.Clear();
			clientConfig.EncryptionAlgorithms.Clear();
			clientConfig.HmacAlgorithms.Clear();
			serverConfig.KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.None);
		}
		else
		{
			// Clear all the server algorithms except for kex:none; support kex:none on the client.
			serverConfig.KeyExchangeAlgorithms.Clear();
			serverConfig.KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.None);
			serverConfig.PublicKeyAlgorithms.Clear();
			serverConfig.EncryptionAlgorithms.Clear();
			serverConfig.HmacAlgorithms.Clear();
			clientConfig.KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.None);
		}

		var sessionPair2 = new SessionPair(serverConfig, clientConfig);
		await sessionPair2.ConnectAsync(authenticate: false).WithTimeout(Timeout);
	}

	[Fact]
	public async Task AuthenticateClientWithNoCredentials()
	{
		SshAuthenticationType authenticationType = default;
		string authenticatedClientUsername = null;
		string authenticatedClientPassword = null;
		IKeyPair authenticatedClientKey = null;
		var clientPrincipal = new ClaimsPrincipal();

		this.serverSession.Authenticating += (sender, e) =>
		{
			authenticationType = e.AuthenticationType;
			if (e.PublicKey != null)
			{
				e.AuthenticationTask = null;
			}
			else
			{
				authenticatedClientUsername = e.Username;
				authenticatedClientPassword = e.Password;
				authenticatedClientKey = e.PublicKey;
				e.AuthenticationTask = Task.FromResult(clientPrincipal);
			}

		};

		var clientAuthenticatedCompletion = new TaskCompletionSource<bool>();
		this.serverSession.ClientAuthenticated += (sender, e) =>
		{
			clientAuthenticatedCompletion.TrySetResult(true);
		};

		this.clientSession.Authenticating += (sender, e) =>
		{
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		};

		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		bool authenticated = await this.clientSession.AuthenticateAsync(
			new SshClientCredentials(TestUsername));
		Assert.True(authenticated);
		await clientAuthenticatedCompletion.Task.WithTimeout(Timeout);

		Assert.Equal(SshAuthenticationType.ClientNone, authenticationType);
		Assert.Equal(TestUsername, authenticatedClientUsername);
		Assert.Null(authenticatedClientPassword);
		Assert.Null(authenticatedClientKey);
		Assert.Same(clientPrincipal, this.serverSession.Principal);
	}

	[Theory]
	[InlineData(ECDsa.ECDsaSha2Nistp256)]
	[InlineData(ECDsa.ECDsaSha2Nistp384)]
	[InlineData(Rsa.RsaWithSha256, 2048)]
	[InlineData(Rsa.RsaWithSha512, 4096)]
	public async Task AuthenticateClientWithPublicKey(
		string pkAlgorithmName, int? keySize = null)
	{
		var pkAlg = GetAlgorithmByName<PublicKeyAlgorithm>(
			typeof(SshAlgorithms.PublicKey), pkAlgorithmName);
		var clientKey = pkAlg.GenerateKeyPair(keySize);

		SshAuthenticationType authenticationType = default;
		string authenticatedClientUsername = null;
		string authenticatedClientPassword = null;
		IKeyPair authenticatedClientKey = null;
		var clientPrincipal = new ClaimsPrincipal();

		this.serverSession.Authenticating += (sender, e) =>
		{
			authenticationType = e.AuthenticationType;
			authenticatedClientUsername = e.Username;
			authenticatedClientPassword = e.Password;
			authenticatedClientKey = e.PublicKey;
			e.AuthenticationTask = Task.FromResult(clientPrincipal);
		};

		var clientAuthenticatedCompletion = new TaskCompletionSource<bool>();
		this.serverSession.ClientAuthenticated += (sender, e) =>
		{
			clientAuthenticatedCompletion.TrySetResult(true);
		};

		IKeyPair authenticatedServerKey = null;
		var serverPrincipal = new ClaimsPrincipal();

		this.clientSession.Authenticating += (sender, e) =>
		{
			authenticatedServerKey = e.PublicKey;
			e.AuthenticationTask = Task.FromResult(serverPrincipal);
		};

		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		bool authenticated = await this.clientSession.AuthenticateAsync((TestUsername, clientKey));
		Assert.True(authenticated);
		await clientAuthenticatedCompletion.Task.WithTimeout(Timeout);

		Assert.Equal(SshAuthenticationType.ClientPublicKey, authenticationType);
		Assert.Equal(TestUsername, authenticatedClientUsername);
		Assert.Null(authenticatedClientPassword);
		Assert.Equal(clientKey.GetPublicKeyBytes(), authenticatedClientKey.GetPublicKeyBytes());
		Assert.Equal(clientKey.KeyAlgorithmName, authenticatedClientKey.KeyAlgorithmName);
		Assert.Same(clientPrincipal, this.serverSession.Principal);

		Assert.Equal(this.sessionPair.ServerKey.GetPublicKeyBytes(),
			authenticatedServerKey.GetPublicKeyBytes());
		Assert.Equal(
			this.sessionPair.ServerKey.KeyAlgorithmName,
			authenticatedServerKey.KeyAlgorithmName);
		Assert.Same(serverPrincipal, this.clientSession.Principal);
	}

	[Fact]
	public async Task AuthenticateServerFail()
	{
		this.serverSession.Authenticating += (sender, e) =>
		{
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		};
		this.clientSession.Authenticating += (sender, e) =>
		{
				// Client fails to authenticate the server.
				e.AuthenticationTask = Task.FromResult<ClaimsPrincipal>(null);
		};

		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		bool authenticated = await this.clientSession.AuthenticateAsync(
			new SshClientCredentials());
		Assert.False(authenticated);

		await this.clientSession.CloseAsync(SshDisconnectReason.NoMoreAuthMethodsAvailable);
	}

	[Fact]
	public async Task AuthenticateClientWithPublicKeyFail()
	{
		this.serverSession.Authenticating += (sender, e) =>
		{
				// Server fails to authenticate the client.
				e.AuthenticationTask = Task.FromResult<ClaimsPrincipal>(null);
		};

		bool serverRaisedClientAuthenticated = false;
		this.serverSession.ClientAuthenticated += (sender, e) =>
		{
			serverRaisedClientAuthenticated = true;
		};

		this.clientSession.Authenticating += (sender, e) =>
		{
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		};

		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		bool authenticated = await this.clientSession.AuthenticateAsync(
			(TestUsername, this.sessionPair.ClientKey));
		Assert.False(authenticated);
		Assert.False(serverRaisedClientAuthenticated);

		await this.clientSession.CloseAsync(SshDisconnectReason.NoMoreAuthMethodsAvailable);
	}

	[Fact]
	public async Task AuthenticateCallbackException()
	{
		this.serverSession.Authenticating += (sender, e) =>
		{
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		};
		this.clientSession.Authenticating += (sender, e) =>
		{
				// Client throws exception while authenticating the server
				e.AuthenticationTask = Task.FromException<ClaimsPrincipal>(new ArgumentException());
		};

		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		await Assert.ThrowsAsync<ArgumentException>(
			async () => await this.clientSession.AuthenticateAsync(new SshClientCredentials()));

		await this.clientSession.CloseAsync(SshDisconnectReason.NoMoreAuthMethodsAvailable);
	}

	[Fact]
	public async Task AuthenticateConnectionException()
	{
		this.clientSession.Authenticating += OnSessionAuthenticating;

		this.serverSession.Authenticating += (sender, e) =>
		{
				// Lost connection while authenticating.
				this.sessionPair.ServerStream.Close();
		};

		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		await Assert.ThrowsAsync<SshConnectionException>(
			async () => await this.clientSession.AuthenticateAsync(
				(TestUsername, this.sessionPair.ClientKey)));
	}

	[Fact]
	public async Task AuthenticateClientWithPassword()
	{
		SshAuthenticationType authenticationType = default;
		string authenticatedClientUsername = null;
		string authenticatedClientPassword = null;
		IKeyPair authenticatedClientKey = null;
		var clientPrincipal = new ClaimsPrincipal();

		this.serverSession.Authenticating += (sender, e) =>
		{
			authenticationType = e.AuthenticationType;
			if (e.PublicKey != null)
			{
				e.AuthenticationTask = null;
			}
			else
			{
				authenticatedClientUsername = e.Username;
				authenticatedClientPassword = e.Password;
				authenticatedClientKey = e.PublicKey;
				e.AuthenticationTask = Task.FromResult(clientPrincipal);
			}

		};

		var clientAuthenticatedCompletion = new TaskCompletionSource<bool>();
		this.serverSession.ClientAuthenticated += (sender, e) =>
		{
			clientAuthenticatedCompletion.TrySetResult(true);
		};

		this.clientSession.Authenticating += (sender, e) =>
		{
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		};

		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		bool authenticated = await this.clientSession.AuthenticateAsync(
			(TestUsername, TestPassword));
		Assert.True(authenticated);
		await clientAuthenticatedCompletion.Task.WithTimeout(Timeout);

		Assert.Equal(SshAuthenticationType.ClientPassword, authenticationType);
		Assert.Equal(TestUsername, authenticatedClientUsername);
		Assert.Equal(TestPassword, authenticatedClientPassword);
		Assert.Null(authenticatedClientKey);
		Assert.Same(clientPrincipal, this.serverSession.Principal);
	}

	[Fact]
	public async Task AuthenticateClientWithPasswordFail()
	{
		this.serverSession.Authenticating += (sender, e) =>
		{
				// Server fails to authenticate the client.
				e.AuthenticationTask = Task.FromResult<ClaimsPrincipal>(null);
		};

		bool serverRaisedClientAuthenticated = false;
		this.serverSession.ClientAuthenticated += (sender, e) =>
		{
			serverRaisedClientAuthenticated = true;
		};

		this.clientSession.Authenticating += (sender, e) =>
		{
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		};

		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		bool authenticated = await this.clientSession.AuthenticateAsync(
			(TestUsername, TestPassword));
		Assert.False(authenticated);
		Assert.False(serverRaisedClientAuthenticated);
	}

	[Fact]
	public async Task SendWhileDisconnected()
	{
		bool clientDisconnectedEvent = false;
		bool serverDisconnectedEvent = false;
		this.clientSession.Disconnected += (sender, e) => clientDisconnectedEvent = true;
		this.serverSession.Disconnected += (sender, e) => serverDisconnectedEvent = true;

		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		this.sessionPair.Disconnect();

		// Attempts to send messages should throw connection exceptions
		// or disposed exceptions, depending on timing.
		var testRequest = new Messages.SessionRequestMessage { RequestType = "test" };
		var ex = await Assert.ThrowsAnyAsync<Exception>(
			() => this.clientSession.RequestAsync(testRequest)).WithTimeout(Timeout);
		Assert.True(ex is SshConnectionException || ex is ObjectDisposedException);
		ex = await Assert.ThrowsAnyAsync<Exception>(
			() => this.serverSession.RequestAsync(testRequest)).WithTimeout(Timeout);
		Assert.True(ex is SshConnectionException || ex is ObjectDisposedException);

		// The sessions should both be closed (not merely disconnected).
		await TaskExtensions.WaitUntil(() =>
			!this.clientSession.IsConnected && this.clientSession.IsClosed &&
			!this.serverSession.IsConnected && this.serverSession.IsClosed)
			.WithTimeout(Timeout);

		// Disconnection events should not be raised when reconnect is not enabled.
		Assert.False(clientDisconnectedEvent);
		Assert.False(serverDisconnectedEvent);

		// Attempts to send messages should now throw disposed exceptions.
		await Assert.ThrowsAsync<ObjectDisposedException>(
			() => this.clientSession.RequestAsync(testRequest)).WithTimeout(Timeout);
		await Assert.ThrowsAsync<ObjectDisposedException>(
			() => this.serverSession.RequestAsync(testRequest)).WithTimeout(Timeout);
	}

	[Fact]
	public async Task SendMultipleMessages()
	{
		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);
		var testRequest = new Messages.SessionRequestMessage { RequestType = "test" };
		await this.clientSession.RequestAsync(testRequest).WithTimeout(Timeout);
	}


	[Fact]
	public async Task SessionRequestUnauthenticated()
	{
		await this.sessionPair.ConnectAsync(authenticate: false).WithTimeout(Timeout);

		SshRequestEventArgs<SessionRequestMessage> requestArgs = null;
		this.serverSession.Request += (sender, e) =>
		{
			requestArgs = e;
		};

		var request = new SessionRequestMessage { RequestType = "Test", WantReply = true };
		var result = await this.clientSession.RequestAsync(request);

		Assert.False(result);
		Assert.Null(requestArgs);
	}


	[Fact]
	public async Task OpenSessionWithMultipleRequests()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		TaskCompletionSource<bool> secondMessageCompletion = new TaskCompletionSource<bool>();
		TaskCompletionSource<bool> firstMessageCompletion = new TaskCompletionSource<bool>();

		var firstRequest = new SessionRequestMessage { RequestType = "first", WantReply = true };
		var secondRequest = new SessionRequestMessage { RequestType = "second", WantReply = true };

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
		this.serverSession.Request += (sender, e) =>
		{
			e.ResponseTask = responseTask(e);
		};

		var firstTask = this.clientSession.RequestAsync(firstRequest).WithTimeout(Timeout);
		var secondTask = this.clientSession.RequestAsync(secondRequest).WithTimeout(Timeout);
		Task.WaitAll(firstTask, secondTask);
		Assert.True(await secondMessageCompletion.Task);
		Assert.True(await firstMessageCompletion.Task);
	}

	private void ServerSession_Request(object sender, SshRequestEventArgs<Messages.SessionRequestMessage> e)
	{
		throw new NotImplementedException();
	}

	private static T GetAlgorithmByName<T>(Type algorithmClass, string name)
		where T : SshAlgorithm
	{
		return algorithmClass.GetProperties(BindingFlags.Public | BindingFlags.Static)
			.Select((p) => p.GetValue(null))
			.Cast<T>()
			.FirstOrDefault((a) => a?.Name == name) ??
			throw new ArgumentException($"Algorithm not found: {name}");
	}
}
