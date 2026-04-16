using System;
using System.Collections.Generic;
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

#if NETSTANDARD2_0 || NET4
using ValueTask = System.Threading.Tasks.Task;
#endif

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

	// Reuse a single session+channel across all runs (matching Go).
	// Creating a fresh TCP+SSH session per run causes backpressure deadlocks
	// with large encrypted messages where TCP send/receive buffers create
	// a circular dependency between the client's send and the server's
	// window update on a "cold" connection.
	private SshClientSession clientSession;
	private SshChannel channel;

	public ThroughputBenchmark(TimeSpan duration, int messageSize, bool withEncryption)
		: base(
			$"Throughput - {messageSize} byte messages {(withEncryption ? "with" : "without")} encryption",
			"session-throughput",
			new Dictionary<string, string>
			{
				{ "encryption", withEncryption ? "true" : "false" },
				{ "size", messageSize.ToString() },
			})
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

		// Set up server-side data drain for all sessions.
		this.server.SessionOpened += (_, serverSession) =>
		{
			serverSession.ChannelOpening += (__, e) =>
			{
				e.Channel.DataReceived += (___, data) =>
				{
					e.Channel.AdjustWindow((uint)data.Count);
				};
			};
		};

		this.serverTask = this.server.AcceptSessionsAsync(Benchmark.ServerPort, IPAddress.Loopback);
	}

	private async Task EnsureSessionAsync()
	{
		if (this.channel != null) return;

		this.clientSession = await client.OpenSessionAsync(
			IPAddress.Loopback.ToString(), ServerPort);

		if (this.withEncryption)
		{
			this.clientSession.Authenticating += OnClientSessionAuthenticating;
			await this.clientSession.AuthenticateAsync(("benchmark", "benchmark"));
		}

		this.channel = await this.clientSession.OpenChannelAsync();
	}

	protected override async Task RunAsync(Stopwatch stopwatch)
	{
#if DEBUG
		Buffer.Allocations.Clear();
		Buffer.Copies.Clear();
#endif

		await EnsureSessionAsync();

		// Safety timeout: 4x the benchmark duration catches true deadlocks
		// caused by TCP buffer circular dependencies with large encrypted
		// messages, without affecting normal runs.
		using var cancellationSource = new CancellationTokenSource(
			TimeSpan.FromSeconds(this.duration.TotalSeconds * 4));

		bool deadlocked = false;
		int messageCount = 0;
		stopwatch.Restart();
		while (stopwatch.Elapsed < this.duration)
		{
			try
			{
				await this.channel.SendAsync(this.messageData, cancellationSource.Token);
			}
			catch (OperationCanceledException)
			{
				deadlocked = true;
				break;
			}
			messageCount++;
		}

		stopwatch.Stop();

		// If the session deadlocked, reset it so the next run gets a fresh one.
		if (deadlocked)
		{
			this.clientSession?.Dispose();
			this.clientSession = null;
			this.channel = null;
		}

		if (messageCount == 0) return;

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

	public override async Task VerifyAsync()
	{
		// Send a known amount of data and verify the server receives the correct byte count.
		int totalReceived = 0;
		var receiveDone = new TaskCompletionSource<int>();

		var expectedSize = this.messageData.Length;

		EventHandler<SshServerSession> sessionOpenedHandler = null;
		sessionOpenedHandler = (_, serverSession) =>
		{
			this.server.SessionOpened -= sessionOpenedHandler;
			serverSession.ChannelOpening += (__, e) =>
			{
				e.Channel.DataReceived += (___, data) =>
				{
					e.Channel.AdjustWindow((uint)data.Count);
					var newTotal = Interlocked.Add(ref totalReceived, data.Count);
					if (newTotal >= expectedSize)
						receiveDone.TrySetResult(newTotal);
				};
			};
		};
		this.server.SessionOpened += sessionOpenedHandler;

		using var clientSession = await client.OpenSessionAsync(
			IPAddress.Loopback.ToString(), ServerPort);

		if (this.withEncryption)
		{
			clientSession.Authenticating += OnClientSessionAuthenticating;
			await clientSession.AuthenticateAsync(("benchmark", "benchmark"));
		}

		var channel = await clientSession.OpenChannelAsync();

		await channel.SendAsync(this.messageData, CancellationToken.None);

		var completed = await Task.WhenAny(receiveDone.Task, Task.Delay(5000));
		if (completed != receiveDone.Task)
			throw new Exception($"Timed out: received {totalReceived} of {expectedSize} bytes");

		var received = await receiveDone.Task;
		if (received != expectedSize)
			throw new Exception($"Byte count mismatch: expected {expectedSize}, got {received}");
	}

	public override async ValueTask DisposeAsync()
	{
		this.clientSession?.Dispose();
		this.server.Dispose();
		this.client.Dispose();
		await this.serverTask;
	}
}
