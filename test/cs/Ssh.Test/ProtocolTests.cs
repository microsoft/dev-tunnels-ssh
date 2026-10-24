using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Metrics;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class ProtocolTests
{
	[Fact]
	public async Task ReplaySnapshotWaitsForPendingCacheUpdate()
	{
		var timeout = TimeSpan.FromSeconds(10);
		var protocolType = typeof(SshSession).Assembly.GetType(
			"Microsoft.DevTunnels.Ssh.IO.SshProtocol");
		var bindingFlags = BindingFlags.NonPublic | BindingFlags.Instance;
		using var stream = new MemoryStream();
		var trace = new TraceSource(nameof(ProtocolTests));
		using var protocol = (IDisposable)Activator.CreateInstance(
			protocolType,
			stream,
			new SshSessionConfiguration(),
			Activator.CreateInstance(typeof(SessionMetrics), nonPublic: true),
			trace);
		protocolType.GetProperty("IncomingMessagesHaveReconnectInfo", bindingFlags)
			.SetValue(protocol, true);
		var sendMessage = (Func<SshMessage, CancellationToken, Task<bool>>)protocolType
			.GetMethod("SendMessageAsync", bindingFlags)
			.CreateDelegate(typeof(Func<SshMessage, CancellationToken, Task<bool>>), protocol);
		var getSentMessages = (Func<ulong, IList<SshMessage>>)protocolType
			.GetMethod("GetSentMessages", bindingFlags)
			.CreateDelegate(typeof(Func<ulong, IList<SshMessage>>), protocol);
		var cache = protocolType.GetField("recentSentMessages", bindingFlags).GetValue(protocol);
		var firstMessage = new SessionRequestMessage { RequestType = "first" };
		var secondMessage = new SessionRequestMessage { RequestType = "second" };
		await sendMessage(firstMessage, CancellationToken.None);

		var snapshot = new TaskCompletionSource<IList<SshMessage>>(
			TaskCreationOptions.RunContinuationsAsynchronously);
		var reader = new Thread(() =>
		{
			try
			{
				snapshot.SetResult(getSentMessages(0));
			}
			catch (Exception ex)
			{
				snapshot.SetException(ex);
			}
		}) { IsBackground = true };

		try
		{
			lock (cache)
			{
				// Pause a cache writer before it appends, then start the replay snapshot.
				reader.Start();
				Assert.True(SpinWait.SpinUntil(
					() => snapshot.Task.IsCompleted ||
						(reader.ThreadState & System.Threading.ThreadState.WaitSleepJoin) != 0,
					timeout), "Replay reader did not reach the cache.");

				// MemoryStream writes complete synchronously. Re-enter the cache lock on
				// this thread to finish the pending send before the snapshot can proceed.
				sendMessage(secondMessage, CancellationToken.None).GetAwaiter().GetResult();
			}
		}
		finally
		{
			Assert.True(reader.Join(timeout), "Replay reader did not finish.");
		}

		Assert.Equal(new SshMessage[] { firstMessage, secondMessage }, await snapshot.Task);
	}
}
