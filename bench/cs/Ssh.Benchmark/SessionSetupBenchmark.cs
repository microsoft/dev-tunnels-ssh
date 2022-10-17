
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Tcp;

namespace Microsoft.DevTunnels.Ssh.Benchmark;

class SessionSetupBenchmark : Benchmark
{
	private const string ConnectTimeMeasurement = "Connect time (ms)";
	private const string EncryptTimeMeasurement = "Encrypt time (ms)";
	private const string AuthTimeMeasurement = "Authenticate time (ms)";
	private const string ChannelTimeMeasurement = "Channnel open time (ms)";
	private const string TotalTimeMeasurement = "Total setup time (ms)";
	private const string BytesAllocatedMeasurement = "Bytes allocated (KB)";
	private const string BytesCopiedMeasurement = "Bytes copied (KB)";
	private const string LatencyMeasurement = "Latency (ms)";

	private static readonly TimeSpan latency = TimeSpan.FromMilliseconds(100);

	private readonly SshServer server;
	private readonly Task serverTask;
	private readonly SshClient client;

	public SessionSetupBenchmark(bool withLatency)
		: base("Session setup" + (withLatency ? " with latency" : ""))
	{
		HigherIsBetter[ConnectTimeMeasurement] = false;
		HigherIsBetter[EncryptTimeMeasurement] = false;
		HigherIsBetter[AuthTimeMeasurement] = false;
		HigherIsBetter[ChannelTimeMeasurement] = false;
		HigherIsBetter[TotalTimeMeasurement] = false;
		HigherIsBetter[BytesAllocatedMeasurement] = false;
		HigherIsBetter[BytesCopiedMeasurement] = false;
		HigherIsBetter[LatencyMeasurement] = false;

		var config = SshSessionConfiguration.DefaultWithReconnect;

		var trace = new TraceSource(nameof(SessionSetupBenchmark));
		this.server = withLatency
			? new SshServerWithLatency(config, trace)
			: new SshServer(config, trace);
		this.client = withLatency
			? new SshClientWithLatency(config, trace)
			: new SshClient(config, trace);

		var serverKey = SshAlgorithms.PublicKey.RsaWithSha512.GenerateKeyPair();
		this.server.Credentials = new[] { serverKey };

		this.server.SessionAuthenticating += OnServerSessionAuthenticating;
		this.server.ChannelRequest += OnServerChannelRequest;

		this.serverTask = this.server.AcceptSessionsAsync(Benchmark.ServerPort, IPAddress.Loopback);
	}

	protected override async Task RunAsync(Stopwatch stopwatch)
	{
#if DEBUG
		Buffer.Allocations.Clear();
		Buffer.Copies.Clear();
#endif

		double connectMark = 0;
		EventHandler<SshServerSession> sessionOpenedHandler = null;
		sessionOpenedHandler = (sender, serverSession) =>
		{
			connectMark = stopwatch.Elapsed.TotalMilliseconds;
			this.server.SessionOpened -= sessionOpenedHandler;
		};
		this.server.SessionOpened += sessionOpenedHandler;

		var clientSession = await client.OpenSessionAsync(
			IPAddress.Loopback.ToString(), ServerPort);

		var encryptMark = stopwatch.Elapsed.TotalMilliseconds;

		clientSession.Authenticating += OnClientSessionAuthenticating;
		await clientSession.AuthenticateServerAsync();

		var clientAuthCompletion = new TaskCompletionSource<bool>();
		await clientSession.AuthenticateClientAsync(
			("benchmark", "benchmark"), clientAuthCompletion);

		var authMark = stopwatch.Elapsed.TotalMilliseconds;

		var channelRequest = new ChannelRequestMessage
		{
			RequestType = "benchmark",
			WantReply = true,
		};

		// Protocol extension: Send initial request when opening channel.
		var clientChannel = await clientSession.OpenChannelAsync(
			new ChannelOpenMessage(), channelRequest);

		await clientAuthCompletion.Task;

		var channelMark = stopwatch.Elapsed.TotalMilliseconds;

		AddMeasurement(ConnectTimeMeasurement, connectMark);
		AddMeasurement(EncryptTimeMeasurement, encryptMark - connectMark);
		AddMeasurement(AuthTimeMeasurement, authMark - encryptMark);
		AddMeasurement(ChannelTimeMeasurement, channelMark - authMark);
		AddMeasurement(TotalTimeMeasurement, channelMark);

		// Add an additional request-reply to enable latency measurement,
		// which doesn't start until after the extension-info exchange.
		await clientChannel.RequestAsync(
			new ChannelRequestMessage { RequestType = "benchmark", WantReply = true, });

		AddMeasurement(LatencyMeasurement, clientSession.Metrics.LatencyAverageMs);

#if DEBUG
		lock (Buffer.Allocations)
		{
			long bytesAllocated = Buffer.Allocations.Values
				.Select((list) => list.Select(count => (long)count).Sum()).Sum();
			double kilobytesAllocated = (double)bytesAllocated / 1024;
			AddMeasurement(BytesAllocatedMeasurement, kilobytesAllocated);
		}

		lock (Buffer.Copies)
		{
			long bytesCopied = Buffer.Copies.Values
				.Select((list) => list.Select(count => (long)count).Sum()).Sum();
			double kilobytesCopied = (double)bytesCopied / 1024;
			AddMeasurement(BytesCopiedMeasurement, kilobytesCopied);
		}
#endif
	}

	private void OnClientSessionAuthenticating(object sender, SshAuthenticatingEventArgs e)
	{
		e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
	}

	private void OnServerSessionAuthenticating(object sender, SshAuthenticatingEventArgs e)
	{
		e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
	}

	private void OnServerChannelRequest(object sender, SshRequestEventArgs<ChannelRequestMessage> e)
	{
		e.IsAuthorized = true;
	}

	public override async ValueTask DisposeAsync()
	{
		this.server.Dispose();
		this.client.Dispose();
		await this.serverTask;
	}

	private class SshServerWithLatency : SshServer
	{
		public SshServerWithLatency(SshSessionConfiguration config, TraceSource trace) : base(config, trace) { }

		protected override async Task<(Stream Stream, IPAddress RemoteIPAddress)> AcceptConnectionAsync(TcpListener listener)
		{
			(var stream, var ipAddress) = await base.AcceptConnectionAsync(listener);
			return stream == null ? (null, null) : (new SlowStream(stream, SessionSetupBenchmark.latency), ipAddress);
		}
	}

	private class SshClientWithLatency : SshClient
	{
		public SshClientWithLatency(SshSessionConfiguration config, TraceSource trace) : base(config, trace) { }

		protected override async Task<(Stream Stream, IPAddress RemomoteIPAddress)> OpenConnectionAsync(
			string host, int port, CancellationToken cancellation)
		{
			(var stream, var ipAddress) = await base.OpenConnectionAsync(host, port, cancellation);
			return (new SlowStream(stream,SessionSetupBenchmark.latency), ipAddress);
		}
	}
}
