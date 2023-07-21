using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Tcp;
using Microsoft.DevTunnels.Ssh.Tcp.Events;

namespace Microsoft.DevTunnels.Ssh.Benchmark;

#if NETSTANDARD2_0 || NET4
using ValueTask = System.Threading.Tasks.Task;
#endif

class PortForwardBenchmark : Benchmark
{
	private const string ConnectTimeMeasurement = "Connect time (ms)";

	private readonly IPAddress listenAddress;
	private readonly string hostAddress;

	private readonly SshServer server;
	private readonly Task serverTask;
	private readonly SshClient client;

	public PortForwardBenchmark(IPAddress listenAddress, string hostAddress)
		: base($"Port forward to {hostAddress} ({listenAddress})")
	{
		HigherIsBetter[ConnectTimeMeasurement] = false;

		this.listenAddress = listenAddress;
		this.hostAddress = hostAddress;

		var config = new SshSessionConfiguration();
		config.AddService(typeof(PortForwardingService));

		var trace = new TraceSource(nameof(PortForwardBenchmark));
		this.server = new SshServer(config, trace);
		this.client = new SshClient(config, trace);

		var serverKey = SshAlgorithms.PublicKey.RsaWithSha512.GenerateKeyPair();
		this.server.Credentials = new[] { serverKey };

		this.server.SessionAuthenticating += OnServerSessionAuthenticating;

		this.serverTask = this.server.AcceptSessionsAsync(Benchmark.ServerPort, IPAddress.Loopback);
	}

	protected override async Task RunAsync(Stopwatch stopwatch)
	{
		var serverSessionCompletion = new TaskCompletionSource<SshServerSession>();
		EventHandler<SshServerSession> sessionOpenedHandler = null;
		sessionOpenedHandler = (sender, session) =>
		{
			serverSessionCompletion.SetResult(session);
			this.server.SessionOpened -= sessionOpenedHandler;
		};
		this.server.SessionOpened += sessionOpenedHandler;

		var clientSession = await this.client.OpenSessionAsync(
			IPAddress.Loopback.ToString(), ServerPort);
		clientSession.Authenticating += OnClientSessionAuthenticating;
		clientSession.Request += OnClientSessionRequest;
		await clientSession.AuthenticateAsync(("benchmark", "benchmark"));
		var serverSession = await serverSessionCompletion.Task;

		var connectServer = new TcpListener(this.listenAddress, 0);
		connectServer.Start();
		var serverPort = ((IPEndPoint)connectServer.LocalEndpoint).Port;

		var availablePortListener = new TcpListener(IPAddress.Loopback, 0);
		availablePortListener.Start();
		var clientPort = ((IPEndPoint)availablePortListener.LocalEndpoint).Port;
		availablePortListener.Stop();

		var forwarder = await serverSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, clientPort, this.hostAddress, serverPort);
		if (forwarder == null)
		{
			throw new InvalidOperationException("Failed to forward port");
		}

		var channelOpenedCompletion = new TaskCompletionSource<ForwardedPortChannelEventArgs>();
		clientSession.GetService<PortForwardingService>().RemoteForwardedPorts.PortChannelAdded +=
			(sender, e) => channelOpenedCompletion.SetResult(e);

		var connectClient = new TcpClient();
		double connectStartMark = stopwatch.Elapsed.TotalMilliseconds;

		var clientConnectTask = connectClient.ConnectAsync(IPAddress.Loopback, clientPort);
		var serverAcceptTask = connectServer.AcceptTcpClientAsync();
		await Task.WhenAll(clientConnectTask, serverAcceptTask, channelOpenedCompletion.Task);
		double connectEndMark = stopwatch.Elapsed.TotalMilliseconds;

		AddMeasurement(ConnectTimeMeasurement, connectEndMark - connectStartMark);
	}

	private void OnClientSessionAuthenticating(object sender, SshAuthenticatingEventArgs e)
	{
		e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
	}

	private void OnServerSessionAuthenticating(object sender, SshAuthenticatingEventArgs e)
	{
		e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
	}

	private void OnClientSessionRequest(object sender, SshRequestEventArgs<SessionRequestMessage> e)
	{
		e.IsAuthorized = true;
	}

	public override async ValueTask DisposeAsync()
	{
		this.server.Dispose();
		this.client.Dispose();
		await this.serverTask;
	}
}