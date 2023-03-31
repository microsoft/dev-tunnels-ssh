using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Nerdbank.Streams;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

class SessionPair : IDisposable
{
	private const string TestUsername = "test";

	public readonly TraceSource ClientTrace = new TraceSource(nameof(SshClientSession));
	public readonly TraceSource ServerTrace = new TraceSource(nameof(SshServerSession));

	public SessionPair(
		SshSessionConfiguration serverConfig = null,
		SshSessionConfiguration clientConfig = null,
		ICollection<SshServerSession> disconnectedSessions = null)
	{
		if (serverConfig == null)
		{
			serverConfig = new SshSessionConfiguration();
			serverConfig.EnableKeyExchangeGuess = true;
		}

		if (clientConfig == null)
		{
			clientConfig = serverConfig;
		}

		ClientTrace.Switch.Level = SourceLevels.All;
		ServerTrace.Switch.Level = SourceLevels.All;

		var (serverStream, clientStream) = FullDuplexStream.CreatePair();
		ServerStream = new MockNetworkStream(serverStream);
		ClientStream = new MockNetworkStream(clientStream);

		if (SshAlgorithms.PublicKey.ECDsaSha2Nistp384.IsAvailable)
		{
			ServerKey = SshAlgorithms.PublicKey.ECDsaSha2Nistp384.GenerateKeyPair();
			ClientKey = SshAlgorithms.PublicKey.ECDsaSha2Nistp384.GenerateKeyPair();
		}
		else
		{
			ServerKey = SshAlgorithms.PublicKey.RsaWithSha256.GenerateKeyPair();
			ClientKey = SshAlgorithms.PublicKey.RsaWithSha256.GenerateKeyPair();
		}

		ServerSession = new SshServerSession(serverConfig, disconnectedSessions, ServerTrace);
		ServerSession.Credentials = new[] { ServerKey };

		ClientSession = new SshClientSession(clientConfig, ClientTrace);

		ServerSession.Authenticating += (sender, e) =>
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		ClientSession.Authenticating += (sender, e) =>
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
	}

	public async Task ConnectAsync(bool authenticate = true)
	{
		await Task.WhenAll(
			ServerSession.ConnectAsync(ServerStream),
			ClientSession.ConnectAsync(ClientStream));

		if (authenticate)
		{
			bool authenticated = await ClientSession.AuthenticateAsync(new SshClientCredentials());
			Assert.True(authenticated);
		}
	}

	public async Task<(SshChannel, SshChannel)> OpenChannelAsync()
	{
		var serverChannelTask = ServerSession.AcceptChannelAsync();
		var clientChannel = await ClientSession.OpenChannelAsync();
		var serverChannel = await serverChannelTask;
		return (clientChannel, serverChannel);
	}

	public void Disconnect(Exception disconnectException = null)
	{
		if (disconnectException != null)
		{
			ClientStream.MockDisconnect(disconnectException);
			ServerStream.MockDisconnect(disconnectException);
		}
		else
		{
			ClientStream.Close();
			ServerStream.Close();
		}
	}

	public void Dispose()
	{
		try
		{
			ClientSession.Dispose();
		}
		catch (Exception ex)
		{
			ClientTrace.TraceEvent(TraceEventType.Error, 0, ex.ToString());
		}

		try
		{
			ServerSession.Dispose();
		}
		catch (Exception ex)
		{
			ServerTrace.TraceEvent(TraceEventType.Error, 0, ex.ToString());
		}
	}

	public IKeyPair ClientKey { get; }
	public IKeyPair ServerKey { get; }
	public MockNetworkStream ClientStream { get; set; }
	public MockNetworkStream ServerStream { get; set; }
	public SshClientSession ClientSession { get; }
	public SshServerSession ServerSession { get; }
}
