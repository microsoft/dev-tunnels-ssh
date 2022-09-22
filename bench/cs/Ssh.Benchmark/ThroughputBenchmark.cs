using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Tcp;

namespace Microsoft.DevTunnels.Ssh.Benchmark;

class ThroughputBenchmark : Benchmark
{
	private const string MessageCountMeasurement = "Throughput (msgs/s)";
	private const string ByteCountMeasurement = "Throughput (MB/s)";
	private const string BytesAllocatedMeasurement = "Bytes allocated (KB/msg)";
	private const string BytesCopiedMeasurement = "Bytes copied (KB/msg)";

	private readonly TimeSpan duration;
	private readonly SshServer server;
	private readonly Task serverTask;
	private readonly SshClient client;
	private readonly byte[] messageData;
	private readonly bool withEncryption;

	public ThroughputBenchmark(TimeSpan duration, int messageSize, bool withEncryption)
		: base($"Throughput - {messageSize} byte messages {(withEncryption ? "with" : "without")} encryption")
	{
		HigherIsBetter[BytesAllocatedMeasurement] = false;
		HigherIsBetter[BytesCopiedMeasurement] = false;

		var trace = new TraceSource(nameof(SessionSetupBenchmark));

		var config = withEncryption
			? SshSessionConfiguration.Default : SshSessionConfiguration.NoSecurity;
		this.server = new SshServer(config, trace);
		this.client = new SshClient(config, trace);

		this.messageData = new byte[messageSize];
		new Random(1).NextBytes(this.messageData);
		this.withEncryption = withEncryption;
		this.duration = duration;

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

		EventHandler<SshServerSession> sessionOpenedHandler = null;
		sessionOpenedHandler = (_, serverSession) =>
		{
			this.server.SessionOpened -= sessionOpenedHandler;
			serverSession.ChannelOpening += (__, e) =>
			{
				e.Channel.DataReceived += (___, data) =>
				{
					e.Channel.AdjustWindow((uint)data.Count);
				};
			};
		};
		this.server.SessionOpened += sessionOpenedHandler;

		using (var clientSession = await client.OpenSessionAsync(
			IPAddress.Loopback.ToString(), ServerPort))
		{
			if (this.withEncryption)
			{
				clientSession.Authenticating += OnClientSessionAuthenticating;
				await clientSession.AuthenticateAsync(("benchmark", "benchmark"));
			}

			var channel = await clientSession.OpenChannelAsync();

			var cancellationSource = new CancellationTokenSource(2 * this.duration);

			int messageCount = 0;
			stopwatch.Restart();
			while (stopwatch.Elapsed < this.duration)
			{
				await channel.SendAsync(this.messageData, cancellationSource.Token);
				messageCount++;
			}

			stopwatch.Stop();

			var elapsedSeconds = stopwatch.Elapsed.TotalSeconds;
			double messagesPerSecond = messageCount / elapsedSeconds;
			double bytesPerSecond = (messageCount * this.messageData.Length) / elapsedSeconds;
			double megabytesPerSecond = bytesPerSecond / (1024 * 1024);
			AddMeasurement(MessageCountMeasurement, messagesPerSecond);
			AddMeasurement(ByteCountMeasurement, megabytesPerSecond);

#if DEBUG
			lock (Buffer.Allocations)
			{
				long bytesAllocated = Buffer.Allocations.Values
					.Select((list) => list.Select(count => (long)count).Sum()).Sum();
				double kilobytesPerMessage = (double)bytesAllocated / 1024 / messageCount;
				AddMeasurement(BytesAllocatedMeasurement, kilobytesPerMessage);
			}

			lock (Buffer.Copies)
			{
				long bytesCopied = Buffer.Copies.Values
					.Select((list) => list.Select(count => (long)count).Sum()).Sum();
				double kilobytesPerMessage = (double)bytesCopied / 1024 / messageCount;
				AddMeasurement(BytesCopiedMeasurement, kilobytesPerMessage);
			}
#endif
		}
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
}
