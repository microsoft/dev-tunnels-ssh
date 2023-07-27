using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Tcp;
using Microsoft.DevTunnels.Ssh.Tcp.Events;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class PortForwardingTests : IDisposable
{
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

	private readonly SessionPair sessionPair;

	private readonly Lazy<(int, int)> testPorts = new Lazy<(int, int)>(() =>
	{
		// Get any available local tcp port
		var listener1 = new TcpListener(IPAddress.Loopback, 0);
		listener1.Start();
		var listener2 = new TcpListener(IPAddress.Loopback, 0);
		listener2.Start();
		int port1 = ((IPEndPoint)listener1.LocalEndpoint).Port;
		int port2 = ((IPEndPoint)listener2.LocalEndpoint).Port;
		listener1.Stop();
		listener2.Stop();
		return (port1, port2);
	});

	private int TestPort1 => this.testPorts.Value.Item1;
	private int TestPort2 => this.testPorts.Value.Item2;

	public PortForwardingTests()
	{
		this.sessionPair = CreateSessionPair();
	}

	private SessionPair CreateSessionPair(bool withPortForwardingServer = true)
	{
		var clientConfig = new SshSessionConfiguration();
		clientConfig.AddService(typeof(PortForwardingService));
		var serverConfig = new SshSessionConfiguration();
        if (withPortForwardingServer)
        {
            serverConfig.AddService(typeof(PortForwardingService));
        }

        return new SessionPair(serverConfig, clientConfig);
	}

	public void Dispose()
	{
		this.sessionPair.Dispose();
	}

	[Theory]
	[InlineData(true, true)]
	[InlineData(true, false)]
	[InlineData(false, false)]
	public async Task ForwardFromRemotePortRequest(bool isRegistered, bool isAuthorized)
	{
		await this.sessionPair.ConnectAsync();

		SessionRequestMessage requestMessage = null;
		this.sessionPair.ServerSession.Request += (_, e) =>
		{
			requestMessage = e.Request;
			e.IsAuthorized = isAuthorized;
		};

		if (!isRegistered)
		{
			this.sessionPair.ServerSession.Config.Services.Remove(
				this.sessionPair.ServerSession.Config.Services.Keys.Single(
					(t) => t.Name.Contains("Port")));
		}

		var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1);

		Assert.Equal("tcpip-forward", requestMessage.RequestType);
		Assert.IsType(
			isRegistered ? typeof(PortForwardRequestMessage) : typeof(SessionRequestMessage),
			requestMessage);
		if (isRegistered)
		{
			Assert.Equal((uint)TestPort1, ((PortForwardRequestMessage)requestMessage).Port);
		}

		Assert.Equal(isRegistered && isAuthorized, forwarder != null);
		if (isRegistered && isAuthorized)
		{
			Assert.Equal(IPAddress.Loopback, forwarder.RemoteIPAddress);
			Assert.Equal(TestPort1, forwarder.RemotePort);
			Assert.Equal(IPAddress.Loopback.ToString(), forwarder.LocalHost);
			Assert.Equal(TestPort1, forwarder.LocalPort);
		}
	}

	[Fact]
	public async Task ForwardFromRemotePortWithListenerFactory()
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
		{
			e.IsAuthorized = true;
		};

		var pfs = this.sessionPair.ServerSession.ActivateService<PortForwardingService>();
		pfs.TcpListenerFactory = new TestTcpListenerFactory(TestPort2);

		var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1);

		Assert.NotNull(forwarder);
		Assert.Equal(IPAddress.Loopback, forwarder.RemoteIPAddress);

		// The client does not know (or need to know) that the remote side chose a different port.
		Assert.Equal(TestPort1, forwarder.RemotePort);

		Assert.Equal(IPAddress.Loopback.ToString(), forwarder.LocalHost);
		Assert.Equal(TestPort1, forwarder.LocalPort);

		var localServer = new TcpListener(IPAddress.Loopback, TestPort1);
		localServer.Start();
		try
		{
			var acceptTask = localServer.AcceptTcpClientAsync();

			var remoteClient = new TcpClient();
			await remoteClient.ConnectAsync(IPAddress.Loopback, TestPort2);
			var remoteStream = remoteClient.GetStream();

			var localClient = await acceptTask.WithTimeout(Timeout);
			var localStream = localClient.GetStream();
		}
		finally
		{
			localServer.Stop();
		}
	}

	private class TestTcpListenerFactory : ITcpListenerFactory
	{
		private int localPortOverride;
		private readonly bool autoIncrement;

		public TestTcpListenerFactory(int localPortOverride, bool autoIncrement = false)
		{
			this.localPortOverride = localPortOverride;
			this.autoIncrement = autoIncrement;
		}

		public Task<TcpListener> CreateTcpListenerAsync(
			IPAddress localIPAddress,
			int localPort,
			bool canChangePort,
			TraceSource trace,
			CancellationToken cancellation)
		{
			var listener = new TcpListener(localIPAddress, this.localPortOverride);
			listener.Start();

			if (this.autoIncrement)
			{
				this.localPortOverride++;
			}

			return Task.FromResult(listener);
		}
	}

	[Fact]
	public async Task ForwardFromRemotePortAutoChoose()
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
		{
			e.IsAuthorized = true;
		};

		var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, 0, IPAddress.Loopback.ToString(), TestPort1);

		Assert.NotNull(forwarder);
		Assert.Equal(IPAddress.Loopback, forwarder.RemoteIPAddress);
		Assert.NotEqual(0, forwarder.RemotePort);
		Assert.Equal(IPAddress.Loopback.ToString(), forwarder.LocalHost);
		Assert.Equal(TestPort1, forwarder.LocalPort);
	}

	[Fact]
	public async Task ForwardFromRemotePortInUse()
	{
		var tcpListener = new TcpListener(IPAddress.Loopback, TestPort1);
		tcpListener.Start();
		try
		{
			await this.sessionPair.ConnectAsync();
			this.sessionPair.ServerSession.Request += (_, e) =>
			{
				e.IsAuthorized = true;
			};

			var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
				IPAddress.Loopback, TestPort1);
			Assert.Null(forwarder);
		}
		finally
		{
			tcpListener.Stop();
		}
	}

	[Theory]
	[InlineData("0.0.0.0", "127.0.0.1", "localhost", "127.0.0.1")]
	[InlineData("127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1")]
	[InlineData("127.0.0.1", "127.0.0.1", "localhost", "127.0.0.1")]
#if !NETCOREAPP2_1 && !NET4
	[InlineData("0.0.0.0", "::1", "::1", "::1")]
	[InlineData("127.0.0.1", "::1", "localhost", "::1")]
	[InlineData("::", "::1", "localhost", "::1")]
	[InlineData("::1", "::1", "::1", "::1")]
	[InlineData("::1", "::1", "localhost", "::1")]
#endif
	public async Task ForwardFromRemotePortReadWrite(
		string remoteServerIPAddress,
		string remoteClientIPAddress,
		string localForwardHost,
		string localServerIPAddress)
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
			e.IsAuthorized = e.Request is PortForwardRequestMessage;

		var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Parse(remoteServerIPAddress), TestPort1, localForwardHost, TestPort2);
		Assert.NotNull(forwarder);

		var localServer = new TcpListener(IPAddress.Parse(localServerIPAddress), TestPort2);
		localServer.Start();
		try
		{
			var acceptTask = localServer.AcceptTcpClientAsync();

			var remoteClient = new TcpClient();
			await remoteClient.ConnectAsync(IPAddress.Parse(remoteClientIPAddress), TestPort1);
			var remoteStream = remoteClient.GetStream();

			var localClient = await acceptTask.WithTimeout(Timeout);
			var localStream = localClient.GetStream();

			await Task.WhenAll(
				WriteAndReadAsync(localStream, remoteStream, 100),
				WriteAndReadAsync(remoteStream, localStream, 100));
		}
		finally
		{
			localServer.Stop();
		}
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task ForwardFromRemotePortClose(bool remoteClose)
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
			e.IsAuthorized = e.Request is PortForwardRequestMessage;

		SshChannel forwardingChannel = null;
		this.sessionPair.ClientSession.ChannelOpening += (_, e) =>
		{
			if (e.Request is PortForwardChannelOpenMessage)
			{
				forwardingChannel = e.Channel;
			}
		};

		var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder);
		Assert.Null(forwardingChannel);

		var localServer = new TcpListener(IPAddress.Loopback, TestPort2);
		localServer.Start();
		try
		{
			var acceptTask = localServer.AcceptTcpClientAsync();

			var remoteClient = new TcpClient();
			await remoteClient.ConnectAsync(IPAddress.Loopback, TestPort1);
			var remoteStream = remoteClient.GetStream();

			var localClient = await acceptTask.WithTimeout(Timeout);
			var localStream = localClient.GetStream();
			Assert.NotNull(forwardingChannel);

			(remoteClose ? remoteStream : localStream).Close();

			var readBuffer = new byte[1];
			int count = await (remoteClose ? localStream : remoteStream).ReadAsync(
				readBuffer, 0, readBuffer.Length).WithTimeout(Timeout);
			Assert.Equal(0, count);

			// The channel will be closed asnynchronously.
			await TaskExtensions.WaitUntil(() => forwardingChannel.IsClosed).WithTimeout(Timeout);
		}
		finally
		{
			localServer.Stop();
		}
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task ForwardFromRemotePortError(bool remoteError)
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
			e.IsAuthorized = e.Request is PortForwardRequestMessage;

		SshChannel clientForwardingChannel = null;
		SshChannel serverForwardingChannel = null;
		this.sessionPair.ClientSession.ChannelOpening += (_, e) =>
		{
			clientForwardingChannel = e.Channel;
		};
		this.sessionPair.ServerSession.ChannelOpening += (_, e) =>
		{
			serverForwardingChannel = e.Channel;
		};

		var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder);

		var localServer = new TcpListener(IPAddress.Loopback, TestPort2);
		localServer.Start();
		try
		{
			var acceptTask = localServer.AcceptTcpClientAsync();

			var remoteClient = new TcpClient();
			await remoteClient.ConnectAsync(IPAddress.Loopback, TestPort1);
			var remoteStream = remoteClient.GetStream();

			var localClient = await acceptTask.WithTimeout(Timeout);
			var localStream = localClient.GetStream();

			await TaskExtensions.WaitUntil(() =>
			{
				return clientForwardingChannel != null && serverForwardingChannel != null;
			}).WithTimeout(Timeout);

			await (remoteError ? serverForwardingChannel : clientForwardingChannel).CloseAsync(
				"SIGABRT", "Test error.");

			await AssertSocketStreamClosedAsync(remoteError ? localStream : remoteStream);
		}
		finally
		{
			localServer.Stop();
		}
	}

	[Fact]
	public async Task ForwardFromRemotePortCancel()
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
			e.IsAuthorized = e.Request is PortForwardRequestMessage;

		var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder);

		forwarder.Dispose();

		// Wait until a connection failure indicates forwarding was successfully cancelled.
		await TaskExtensions.WaitUntil(async () =>
		{
			var remoteClient = new TcpClient();
			try
			{
				await remoteClient.ConnectAsync(IPAddress.Loopback, TestPort1);
			}
			catch (SocketException)
			{
				return true;
			}

			remoteClient.Close();
			return false;
		}).WithTimeout(Timeout);

		// Forward the same port again after the previous forwarding was cancelled.
		var forwarder2 = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder2);

		var remoteClient2 = new TcpClient();
		await remoteClient2.ConnectAsync(IPAddress.Loopback, TestPort1);
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task ForwardFromRemotePortEndSession(bool remoteEnd)
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
			e.IsAuthorized = e.Request is PortForwardRequestMessage;

		SshChannel clientForwardingChannel = null;
		SshChannel serverForwardingChannel = null;
		this.sessionPair.ClientSession.ChannelOpening += (_, e) =>
		{
			clientForwardingChannel = e.Channel;
		};
		this.sessionPair.ServerSession.ChannelOpening += (_, e) =>
		{
			serverForwardingChannel = e.Channel;
		};

		var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder);

		var localServer = new TcpListener(IPAddress.Loopback, TestPort2);
		localServer.Start();
		try
		{
			var acceptTask = localServer.AcceptTcpClientAsync();

			var remoteClient = new TcpClient();
			await remoteClient.ConnectAsync(IPAddress.Loopback, TestPort1);
			var remoteStream = remoteClient.GetStream();

			var localClient = await acceptTask.WithTimeout(Timeout);
			var localStream = localClient.GetStream();

			await TaskExtensions.WaitUntil(() =>
			{
				return clientForwardingChannel != null && serverForwardingChannel != null;
			}).WithTimeout(Timeout);

			(remoteEnd ? this.sessionPair.ServerSession : (SshSession)this.sessionPair.ClientSession)
				.Dispose();

			await AssertSocketStreamClosedAsync(remoteEnd ? localStream : remoteStream);

			// The channel will be closed asnynchronously.
			await TaskExtensions.WaitUntil(() => clientForwardingChannel.IsClosed)
				.WithTimeout(Timeout);
		}
		finally
		{
			localServer.Stop();
		}
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task ForwardFromRemotePortRace(bool acceptLocalConnections)
	{
		await this.sessionPair.ConnectAsync();
		var clientSession = this.sessionPair.ClientSession;
		var serverSession = this.sessionPair.ServerSession;
		clientSession.Request += (_, e) => e.IsAuthorized = true;
		clientSession.ActivateService<PortForwardingService>()
			.AcceptLocalConnectionsForForwardedPorts = acceptLocalConnections;

		var forwarder1Task = serverSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1);
		var forwarder2Task = serverSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1);
		await Task.WhenAll(forwarder1Task, forwarder2Task).WithTimeout(Timeout);

		// The same port was forwarded twice concurrently.
		// Only one forwarder should have been returned.
		Assert.Equal(
			1,
			(await forwarder1Task != null ? 1 : 0) + (await forwarder2Task != null ? 1 : 0));
	}

	[Fact]
	public async Task ForwardToRemotePortRequest()
	{
		await this.sessionPair.ConnectAsync();

		var forwarder = await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
			IPAddress.Loopback, TestPort1);

		Assert.NotNull(forwarder);
		Assert.Equal(IPAddress.Loopback, forwarder.LocalIPAddress);
		Assert.Equal(TestPort1, forwarder.LocalPort);
		Assert.Equal(IPAddress.Loopback.ToString(), forwarder.RemoteHost);
		Assert.Equal(TestPort1, forwarder.RemotePort);
	}

	[Fact]
	public async Task ForwardToRemotePortAutoChoose()
	{
		await this.sessionPair.ConnectAsync();

		var forwarder = await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
			IPAddress.Loopback, 0, IPAddress.Loopback.ToString(), TestPort1);

		Assert.NotNull(forwarder);
		Assert.Equal(IPAddress.Loopback, forwarder.LocalIPAddress);
		Assert.NotEqual(0, forwarder.LocalPort);
		Assert.Equal(IPAddress.Loopback.ToString(), forwarder.RemoteHost);
		Assert.Equal(TestPort1, forwarder.RemotePort);
	}

	[Fact]
	public async Task ForwardToRemotePortInUse()
	{
		await this.sessionPair.ConnectAsync();

		var tcpListener = new TcpListener(IPAddress.Loopback, TestPort1);
		tcpListener.Start();
		try
		{
			await this.sessionPair.ConnectAsync();

			var sockex = await Assert.ThrowsAsync<SocketException>(async () =>
			{
				await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
					IPAddress.Loopback, TestPort1);
			});
			Assert.True(sockex.SocketErrorCode == SocketError.AccessDenied ||
				sockex.SocketErrorCode == SocketError.AddressAlreadyInUse);
		}
		finally
		{
			tcpListener.Stop();
		}
	}

	[Fact]
	public async Task ForwardToRemotePortUnauthorized()
	{
		await this.sessionPair.ConnectAsync();

		var forwarder = await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
			IPAddress.Loopback, TestPort1);
		Assert.NotNull(forwarder);

		SshChannel forwardingChannel = null;
		this.sessionPair.ServerSession.ChannelOpening += (_, e) =>
		{
			if (e.Request is PortForwardChannelOpenMessage)
			{
				forwardingChannel = e.Channel;
				e.FailureReason = SshChannelOpenFailureReason.ConnectFailed;
			}
		};

		var localClient = new TcpClient();
		await localClient.ConnectAsync(IPAddress.Loopback, TestPort1);
		var localStream = localClient.GetStream();

		await TaskExtensions.WaitUntil(() => forwardingChannel != null);

		var ioex = await Assert.ThrowsAsync<IOException>(async () =>
		{
			var buffer = new byte[1];
			await localStream.ReadAsync(buffer, 0, buffer.Length);
		});
		Assert.IsType<SocketException>(ioex.InnerException);

		// The channel will be closed asnynchronously.
		await TaskExtensions.WaitUntil(() => forwardingChannel.IsClosed).WithTimeout(Timeout);
	}

	[Theory]
	[InlineData("0.0.0.0", "127.0.0.1", "localhost", "127.0.0.1")]
	[InlineData("127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1")]
	[InlineData("127.0.0.1", "127.0.0.1", "localhost", "127.0.0.1")]
#if !NETCOREAPP2_1 && !NET4
	[InlineData("127.0.0.1", "::1", "localhost", "::1")]
	[InlineData("::1", "::1", "::1", "::1")]
	[InlineData("::1", "::1", "localhost", "::1")]
	[InlineData("::", "::1", "localhost", "::1")]
#endif
	public async Task ForwardToRemotePortReadWrite(
		string localServerIPAddress,
		string localClientIPAddress,
		string remoteForwardHost,
		string remoteServerIPAddress)
	{
		await this.sessionPair.ConnectAsync();

		var forwarder = await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
			IPAddress.Parse(localServerIPAddress), TestPort1, remoteForwardHost, TestPort2);
		Assert.NotNull(forwarder);

		SshChannel forwardingChannel = null;
		this.sessionPair.ServerSession.ChannelOpening += (_, e) =>
		{
			if (e.Request is PortForwardChannelOpenMessage)
			{
				forwardingChannel = e.Channel;
			}
		};

		var remoteServer = new TcpListener(IPAddress.Parse(remoteServerIPAddress), TestPort2);
		remoteServer.Start();
		try
		{
			var acceptTask = remoteServer.AcceptTcpClientAsync();

			var localClient = new TcpClient();
			await localClient.ConnectAsync(IPAddress.Parse(localClientIPAddress), TestPort1);
			var localStream = localClient.GetStream();

			var remoteClient = await acceptTask.WithTimeout(Timeout);
			var remoteStream = remoteClient.GetStream();

			Assert.NotNull(forwardingChannel);

			await Task.WhenAll(
				WriteAndReadAsync(localStream, remoteStream, 100),
				WriteAndReadAsync(remoteStream, localStream, 100));
		}
		finally
		{
			remoteServer.Stop();
		}
	}

	private static async Task WriteAndReadAsync(Stream writeStream, Stream readStream, int count)
	{
		var writeBuffer = new byte[count];
		for (int i = 0; i < count; i++) writeBuffer[i] = (byte)(i % 256);
		await writeStream.WriteAsync(writeBuffer, 0, writeBuffer.Length);

#if NET4
		if (writeStream is System.IO.Compression.DeflateStream)
		{
			// .NET Framework DeflateStream doesn't write to the underlying stream until it is closed.
			writeStream.Close();
		}
		else
#endif
		{
			await writeStream.FlushAsync();
		}

		var readBuffer = new byte[count + 10];
		int totalReadCount = 0;
		while (totalReadCount < count)
		{
			int readCount = await readStream.ReadAsync(
				readBuffer, totalReadCount, readBuffer.Length - totalReadCount)
				.WithTimeout(Timeout);
			if (readCount == 0) break;
			totalReadCount += readCount;
		}

		Assert.Equal(count, totalReadCount);
		Assert.True(writeBuffer.SequenceEqual(readBuffer.Take(count)));
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task ForwardToRemotePortClose(bool remoteClose)
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
			e.IsAuthorized = e.Request is PortForwardRequestMessage;

		SshChannel forwardingChannel = null;
		this.sessionPair.ServerSession.ChannelOpening += (_, e) =>
		{
			forwardingChannel = e.Channel;
		};

		var forwarder = await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder);
		Assert.Null(forwardingChannel);

		var remoteServer = new TcpListener(IPAddress.Loopback, TestPort2);
		remoteServer.Start();
		try
		{
			var acceptTask = remoteServer.AcceptTcpClientAsync();

			var localClient = new TcpClient();
			await localClient.ConnectAsync(IPAddress.Loopback, TestPort1);
			var localStream = localClient.GetStream();

			var remoteClient = await acceptTask.WithTimeout(Timeout);
			var remoteStream = remoteClient.GetStream();

			Assert.NotNull(forwardingChannel);

			(remoteClose ? remoteStream : localStream).Close();

			var readBuffer = new byte[1];
			int count = await (remoteClose ? localStream : remoteStream).ReadAsync(
				readBuffer, 0, readBuffer.Length).WithTimeout(Timeout);
			Assert.Equal(0, count);

			// The channel will be closed asnynchronously.
			await TaskExtensions.WaitUntil(() => forwardingChannel.IsClosed).WithTimeout(Timeout);
		}
		finally
		{
			remoteServer.Stop();
		}
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task ForwardToRemotePortError(bool remoteError)
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
			e.IsAuthorized = e.Request is PortForwardRequestMessage;

		SshChannel clientForwardingChannel = null;
		SshChannel serverForwardingChannel = null;
		this.sessionPair.ClientSession.ChannelOpening += (_, e) =>
		{
			clientForwardingChannel = e.Channel;
		};
		this.sessionPair.ServerSession.ChannelOpening += (_, e) =>
		{
			serverForwardingChannel = e.Channel;
		};

		var forwarder = await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder);

		var remoteServer = new TcpListener(IPAddress.Loopback, TestPort2);
		remoteServer.Start();
		try
		{
			var acceptTask = remoteServer.AcceptTcpClientAsync();

			var localClient = new TcpClient();
			await localClient.ConnectAsync(IPAddress.Loopback, TestPort1);
			var localStream = localClient.GetStream();

			var remoteClient = await acceptTask.WithTimeout(Timeout);
			var remoteStream = remoteClient.GetStream();

			await TaskExtensions.WaitUntil(() =>
			{
				return clientForwardingChannel != null && serverForwardingChannel != null;
			}).WithTimeout(Timeout);

			await (remoteError ? serverForwardingChannel : clientForwardingChannel).CloseAsync(
				"SIGABRT", "Test error.");

			await AssertSocketStreamClosedAsync(remoteError ? localStream : remoteStream);
		}
		finally
		{
			remoteServer.Stop();
		}
	}

	[Fact]
	public async Task ForwardToRemotePortCancel()
	{
		await this.sessionPair.ConnectAsync();

		var forwarder = await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder);

		forwarder.Dispose();

		// Wait until a connection failure indicates forwarding was successfully cancelled.
		await TaskExtensions.WaitUntil(async () =>
		{
			var localClient = new TcpClient();
			try
			{
				await localClient.ConnectAsync(IPAddress.Loopback, TestPort1);
			}
			catch (SocketException)
			{
				return true;
			}

			localClient.Close();
			return false;
		}).WithTimeout(Timeout);

		// Forward the same port again after the previous forwarding was cancelled.
		var forwarder2 = await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder2);

		var remoteClient2 = new TcpClient();
		await remoteClient2.ConnectAsync(IPAddress.Loopback, TestPort1);
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	public async Task ForwardToRemotePortEndSession(bool remoteEnd)
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
			e.IsAuthorized = e.Request is PortForwardRequestMessage;

		SshChannel forwardingChannel = null;
		this.sessionPair.ServerSession.ChannelOpening += (_, e) =>
		{
			forwardingChannel = e.Channel;
		};

		var forwarder = await this.sessionPair.ClientSession.ForwardToRemotePortAsync(
			IPAddress.Loopback, TestPort1, "localhost", TestPort2);
		Assert.NotNull(forwarder);

		var remoteServer = new TcpListener(IPAddress.Loopback, TestPort2);
		remoteServer.Start();
		try
		{
			var acceptTask = remoteServer.AcceptTcpClientAsync();

			var localClient = new TcpClient();
			await localClient.ConnectAsync(IPAddress.Loopback, TestPort1);
			var localStream = localClient.GetStream();

			var remoteClient = await acceptTask.WithTimeout(Timeout);
			var remoteStream = remoteClient.GetStream();

			Assert.NotNull(forwardingChannel);

			(remoteEnd ? this.sessionPair.ServerSession : (SshSession)this.sessionPair.ClientSession)
				.Dispose();

			await AssertSocketStreamClosedAsync(remoteEnd ? localStream : remoteStream);

			// The channel will be closed asnynchronously.
			await TaskExtensions.WaitUntil(() => forwardingChannel.IsClosed).WithTimeout(Timeout);
		}
		finally
		{
			remoteServer.Stop();
		}
	}

	private static async Task AssertSocketStreamClosedAsync(Stream stream)
	{
		// The read may return 0 bytes or throw an IOException, depending on timing.
		var readBuffer = new byte[1];
		var ioex = await Assert.ThrowsAnyAsync<IOException>(async () =>
		{
			var result = await stream.ReadAsync(readBuffer, 0, readBuffer.Length).WithTimeout(Timeout);
			Assert.Equal(0, result);
			throw new EndOfStreamException();
		});
		if (!(ioex is EndOfStreamException)) {
			Assert.IsType<SocketException>(ioex.InnerException);
		}
	}

	[Fact]
	public async Task StreamToRemotePort()
	{
		await this.sessionPair.ConnectAsync();

		var remoteServer = new TcpListener(IPAddress.Loopback, TestPort2);
		remoteServer.Start();
		try
		{
			var acceptTask = remoteServer.AcceptTcpClientAsync();

			var localStream = await this.sessionPair.ClientSession.StreamToRemotePortAsync(
				"localhost", TestPort2);
			Assert.NotNull(localStream);

			var remoteClient = await acceptTask.WithTimeout(Timeout);
			var remoteStream = remoteClient.GetStream();

			var writeBuffer = new byte[] { 1, 2, 3 };
			await remoteStream.WriteAsync(writeBuffer, 0, writeBuffer.Length);
			await localStream.WriteAsync(writeBuffer, 0, writeBuffer.Length);

			var readBuffer = new byte[10];
			int count = await localStream.ReadAsync(readBuffer, 0, readBuffer.Length)
				.WithTimeout(Timeout);
			Assert.Equal(writeBuffer.Length, count);
			Assert.True(writeBuffer.SequenceEqual(readBuffer.Take(count)));

			count = await remoteStream.ReadAsync(readBuffer, 0, readBuffer.Length)
				.WithTimeout(Timeout);
			Assert.Equal(writeBuffer.Length, count);
			Assert.True(writeBuffer.SequenceEqual(readBuffer.Take(count)));
		}
		finally
		{
			remoteServer.Stop();
		}
	}

	[Fact]
	public async Task StreamToRemotePortError()
	{
		await this.sessionPair.ConnectAsync();
		this.sessionPair.ServerSession.ChannelOpening += (_, e) =>
		{
			e.FailureReason = SshChannelOpenFailureReason.AdministrativelyProhibited;
		};

		await Assert.ThrowsAsync<SshChannelException>(async () =>
		{
			await this.sessionPair.ClientSession.StreamToRemotePortAsync("localhost", TestPort2);
		});
	}


	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task StreamFromRemotePort(bool autoChoose)
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) =>
			e.IsAuthorized = e.Request is PortForwardRequestMessage;

		var streamer = await this.sessionPair.ClientSession.StreamFromRemotePortAsync(
			IPAddress.Loopback, autoChoose ? 0 : TestPort1);
		Assert.NotNull(streamer);

		if (!autoChoose)
		{
			Assert.Equal(TestPort1, streamer.RemotePort);
		}

		var openCompletion = new TaskCompletionSource<SshStream>();
		streamer.StreamOpened += (sender, stream) =>
		{
			openCompletion.SetResult(stream);
		};

		var remoteClient = new TcpClient();
		await remoteClient.ConnectAsync(
			IPAddress.Loopback, autoChoose ? streamer.RemotePort : TestPort1);
		var remoteStream = remoteClient.GetStream();

		var localStream = await openCompletion.Task.WithTimeout(Timeout);

		var writeBuffer = new byte[] { 1, 2, 3 };
		await remoteStream.WriteAsync(writeBuffer, 0, writeBuffer.Length);
		await localStream.WriteAsync(writeBuffer, 0, writeBuffer.Length);

		var readBuffer = new byte[10];
		int count = await localStream.ReadAsync(readBuffer, 0, readBuffer.Length)
			.WithTimeout(Timeout);
		Assert.Equal(writeBuffer.Length, count);
		Assert.True(writeBuffer.SequenceEqual(readBuffer.Take(count)));

		count = await remoteStream.ReadAsync(readBuffer, 0, readBuffer.Length)
			.WithTimeout(Timeout);
		Assert.Equal(writeBuffer.Length, count);
		Assert.True(writeBuffer.SequenceEqual(readBuffer.Take(count)));
	}

	[Fact]
	public async Task ConnectToForwardedPort()
	{
		this.sessionPair.ServerSession.Request += (_, e) => e.IsAuthorized = true;

		await this.sessionPair.ConnectAsync();
		var serverPfs = this.sessionPair.ServerSession.ActivateService<PortForwardingService>();
		serverPfs.AcceptLocalConnectionsForForwardedPorts = false;

		var localServer = new TcpListener(IPAddress.Loopback, TestPort1);
		localServer.Start();
		try
		{
			var acceptTask = localServer.AcceptTcpClientAsync();

			var waitTask = this.sessionPair.ServerSession.WaitForForwardedPortAsync(TestPort1)
				.WithTimeout(Timeout);
			var forwardTask = this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
				IPAddress.Loopback, TestPort1).WithTimeout(Timeout);
			await waitTask;

			var remoteStream = await this.sessionPair.ServerSession
					.ConnectToForwardedPortAsync(TestPort1).WithTimeout(Timeout);
			var localClient = await acceptTask.WithTimeout(Timeout);

			// Don't wait for the forward response until after connecting.
			// The side that receives the forward request can open a port-forwarding channel
			// immediately (before the request sender has received the response).
			await forwardTask;
		}
		finally
		{
			localServer.Stop();
		}
	}

	[Fact]
	public async Task ConnectToForwardedPortWithTransform()
	{
		this.sessionPair.ServerSession.Config.TraceChannelData = true;
		this.sessionPair.ClientSession.Config.TraceChannelData = true;

		this.sessionPair.ServerSession.Request += (_, e) => e.IsAuthorized = true;

		await this.sessionPair.ConnectAsync();
		var clientPfs = this.sessionPair.ClientSession.ActivateService<PortForwardingService>();
		var serverPfs = this.sessionPair.ServerSession.ActivateService<PortForwardingService>();
		serverPfs.AcceptLocalConnectionsForForwardedPorts = false;

		var localServer = new TcpListener(IPAddress.Loopback, TestPort1);
		localServer.Start();
		try
		{
			var acceptTask = localServer.AcceptTcpClientAsync();

			var waitTask = this.sessionPair.ServerSession.WaitForForwardedPortAsync(TestPort1)
				.WithTimeout(Timeout);
			var forwardTask = this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
				IPAddress.Loopback, TestPort1).WithTimeout(Timeout);
			await waitTask;

			// For testing, insert compression and decompression transform streams.
			serverPfs.ForwardedPortConnecting += (_, e) =>
			{
				e.TransformTask = Task.FromResult<Stream>(
					new System.IO.Compression.DeflateStream(
						e.Stream, System.IO.Compression.CompressionMode.Compress, leaveOpen: true));
			};
			clientPfs.ForwardedPortConnecting += (_, e) =>
			{
				e.TransformTask = Task.FromResult<Stream>(
					new System.IO.Compression.DeflateStream(
						e.Stream, System.IO.Compression.CompressionMode.Decompress));
			};

			var remoteStream = await this.sessionPair.ServerSession
					.ConnectToForwardedPortAsync(TestPort1).WithTimeout(Timeout);
			Assert.IsType<System.IO.Compression.DeflateStream>(remoteStream);
			var localClient = await acceptTask.WithTimeout(Timeout);
			var localStream = localClient.GetStream();

			await WriteAndReadAsync(remoteStream, localStream, 10_000);

			await forwardTask;
		}
		finally
		{
			localServer.Stop();
		}
	}

	[Fact]
	public async Task ConnectToForwardedPortWithoutForwardingConnectionToLocalPort()
	{
		this.sessionPair.ServerSession.Request += (_, e) => e.IsAuthorized = true;

		await this.sessionPair.ConnectAsync();
		var serverPfs = this.sessionPair.ServerSession.ActivateService<PortForwardingService>();
		serverPfs.AcceptLocalConnectionsForForwardedPorts = false;

		var clientPfs = this.sessionPair.ClientSession.ActivateService<PortForwardingService>();
		clientPfs.ForwardConnectionsToLocalPorts = false;

		SshStream localStream = null;
		this.sessionPair.ClientSession.ChannelOpening += (object sender, Events.SshChannelOpeningEventArgs e) =>
		{
			localStream = new SshStream(e.Channel);
		};

		var waitTask = this.sessionPair.ServerSession.WaitForForwardedPortAsync(TestPort1)
			.WithTimeout(Timeout);
		var forwardTask = this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1).WithTimeout(Timeout);
		await waitTask;

		var remoteStream = await this.sessionPair.ServerSession
				.ConnectToForwardedPortAsync(TestPort1).WithTimeout(Timeout);

		Assert.NotNull(localStream);
		Assert.NotNull(remoteStream);
	}

	[Fact]
	public async Task BlockConnectToNonForwardedPort()
	{
		await this.sessionPair.ConnectAsync();
		var serverPfs = this.sessionPair.ServerSession.ActivateService<PortForwardingService>();
		serverPfs.AcceptRemoteConnectionsForNonForwardedPorts = false;

		var ex = await Assert.ThrowsAsync<SshChannelException>(async () =>
		{
			await this.sessionPair.ClientSession.StreamToRemotePortAsync(
				"localhost", TestPort2).WithTimeout(Timeout);
		});
		Assert.Equal(SshChannelOpenFailureReason.AdministrativelyProhibited, ex.OpenFailureReason);
	}

	[Fact]
	public async Task BlockForwardAlreadyForwardedPort()
	{
		this.sessionPair.ServerSession.Request += (_, e) => e.IsAuthorized = true;

		var pfs = this.sessionPair.ServerSession.ActivateService<PortForwardingService>();
		pfs.TcpListenerFactory = new TestTcpListenerFactory(TestPort2, autoIncrement: true);

		await this.sessionPair.ConnectAsync();

		using var forwarder1 = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1);
		Assert.NotNull(forwarder1);

		// Bypass the ForwardFromRemotePort API because it has a client-side check
		// that prevents validation of the remote block.
		var portRequest = new PortForwardRequestMessage();
		portRequest.Port = (uint)TestPort1;
		var result = await this.sessionPair.ClientSession.RequestAsync(portRequest);
		Assert.False(result);

		forwarder1.Dispose();

		// After disposing (cancelling the forwarding), now try again.
		using var forwarder3 = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1).WithTimeout(Timeout);
		Assert.NotNull(forwarder3);
	}

	[Fact]
	public async Task RaiseForwardedPortEvents()
	{
		this.sessionPair.ServerSession.Request += (_, e) => e.IsAuthorized = true;

		await this.sessionPair.ConnectAsync();
		var clientPfs = this.sessionPair.ClientSession.ActivateService<PortForwardingService>();
		var serverPfs = this.sessionPair.ServerSession.ActivateService<PortForwardingService>();

		ForwardedPortEventArgs clientLocalPortAddedEvent = null;
		clientPfs.LocalForwardedPorts.PortAdded += (_, e) => clientLocalPortAddedEvent = e;
		ForwardedPortEventArgs clientRemotePortAddedEvent = null;
		clientPfs.RemoteForwardedPorts.PortAdded += (_, e) => clientRemotePortAddedEvent = e;

		ForwardedPortEventArgs serverLocalPortAddedEvent = null;
		serverPfs.LocalForwardedPorts.PortAdded += (_, e) => serverLocalPortAddedEvent = e;
		ForwardedPortEventArgs serverRemotePortAddedEvent = null;
		serverPfs.RemoteForwardedPorts.PortAdded += (_, e) => serverRemotePortAddedEvent = e;

		ForwardedPortEventArgs clientLocalPortRemovedEvent = null;
		clientPfs.LocalForwardedPorts.PortRemoved += (_, e) => clientLocalPortRemovedEvent = e;
		ForwardedPortEventArgs clientRemotePortRemovedEvent = null;
		clientPfs.RemoteForwardedPorts.PortRemoved += (_, e) => clientRemotePortRemovedEvent = e;

		ForwardedPortEventArgs serverLocalPortRemovedEvent = null;
		serverPfs.LocalForwardedPorts.PortRemoved += (_, e) => serverLocalPortRemovedEvent = e;
		ForwardedPortEventArgs serverRemotePortRemovedEvent = null;
		serverPfs.RemoteForwardedPorts.PortRemoved += (_, e) => serverRemotePortRemovedEvent = e;

		ForwardedPortChannelEventArgs clientLocalChannelAddedEvent = null;
		clientPfs.LocalForwardedPorts.PortChannelAdded += (_, e) => clientLocalChannelAddedEvent = e;
		ForwardedPortChannelEventArgs clientRemoteChannelAddedEvent = null;
		clientPfs.RemoteForwardedPorts.PortChannelAdded += (_, e) => clientRemoteChannelAddedEvent = e;

		ForwardedPortChannelEventArgs serverLocalChannelAddedEvent = null;
		serverPfs.LocalForwardedPorts.PortChannelAdded += (_, e) => serverLocalChannelAddedEvent = e;
		ForwardedPortChannelEventArgs serverRemoteChannelAddedEvent = null;
		serverPfs.RemoteForwardedPorts.PortChannelAdded += (_, e) => serverRemoteChannelAddedEvent = e;

		ForwardedPortChannelEventArgs clientLocalChannelRemovedEvent = null;
		clientPfs.LocalForwardedPorts.PortChannelRemoved += (_, e) => clientLocalChannelRemovedEvent = e;
		ForwardedPortChannelEventArgs clientRemoteChannelRemovedEvent = null;
		clientPfs.RemoteForwardedPorts.PortChannelRemoved += (_, e) => clientRemoteChannelRemovedEvent = e;

		ForwardedPortChannelEventArgs serverLocalChannelRemovedEvent = null;
		serverPfs.LocalForwardedPorts.PortChannelRemoved += (_, e) => serverLocalChannelRemovedEvent = e;
		ForwardedPortChannelEventArgs serverRemoteChannelRemovedEvent = null;
		serverPfs.RemoteForwardedPorts.PortChannelRemoved += (_, e) => serverRemoteChannelRemovedEvent = e;

		ForwardedPortConnectingEventArgs serverConnectingEvent = null;
		serverPfs.ForwardedPortConnecting += (_, e) => serverConnectingEvent = e;
		ForwardedPortConnectingEventArgs clientConnectingEvent = null;
		clientPfs.ForwardedPortConnecting += (_, e) => clientConnectingEvent = e;

		// This causes the server to choose a different port than the one that was requested.
		serverPfs.TcpListenerFactory = new TestTcpListenerFactory(TestPort2);

		var forwarder = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(
			IPAddress.Loopback, TestPort1).WithTimeout(Timeout);

		Assert.Single(clientPfs.LocalForwardedPorts);
		Assert.Empty(clientPfs.RemoteForwardedPorts);
		Assert.Empty(serverPfs.LocalForwardedPorts);
		Assert.Single(serverPfs.RemoteForwardedPorts);

		// The client does not know (or need to know) that the remote side chose a different port.
		Assert.Contains(
			clientPfs.LocalForwardedPorts,
			(p) => p.LocalPort == TestPort1 && p.RemotePort == TestPort1);

		Assert.Contains(
			serverPfs.RemoteForwardedPorts,
			(p) => p.LocalPort == TestPort2 && p.RemotePort == TestPort1);

		Assert.NotNull(clientLocalPortAddedEvent);
		Assert.Equal(TestPort1, clientLocalPortAddedEvent.Port.LocalPort);
		Assert.Equal(TestPort1, clientLocalPortAddedEvent.Port.RemotePort);
		Assert.Null(clientRemotePortAddedEvent);
		Assert.Null(serverLocalPortAddedEvent);
		Assert.NotNull(serverRemotePortAddedEvent);
		Assert.Equal(TestPort2, serverRemotePortAddedEvent.Port.LocalPort);
		Assert.Equal(TestPort1, serverRemotePortAddedEvent.Port.RemotePort);

		Assert.Null(clientLocalChannelAddedEvent);
		Assert.Null(clientRemoteChannelAddedEvent);
		Assert.Null(serverLocalChannelAddedEvent);
		Assert.Null(serverRemoteChannelAddedEvent);

		Assert.Null(serverConnectingEvent);
		Assert.Null(clientConnectingEvent);

		var localServer = new TcpListener(IPAddress.Loopback, TestPort1);
		localServer.Start();
		try
		{
			var acceptTask = localServer.AcceptTcpClientAsync();

			var remoteStream = await this.sessionPair.ServerSession
					.ConnectToForwardedPortAsync(TestPort1).WithTimeout(Timeout);
			var localClient = await acceptTask.WithTimeout(Timeout);

			var clientLocalForwardedPort = clientPfs.LocalForwardedPorts.Single();
			Assert.Single(clientPfs.LocalForwardedPorts.GetChannels(clientLocalForwardedPort));
			Assert.Empty(clientPfs.RemoteForwardedPorts);
			Assert.Empty(serverPfs.LocalForwardedPorts);
			var serverRemoteForwardedPort = serverPfs.RemoteForwardedPorts.Single();
			Assert.Single(serverPfs.RemoteForwardedPorts.GetChannels(serverRemoteForwardedPort));

			Assert.NotNull(clientLocalChannelAddedEvent);
			Assert.Equal(TestPort1, clientLocalChannelAddedEvent.Port.LocalPort);
			Assert.Equal(TestPort1, clientLocalChannelAddedEvent.Port.RemotePort);
			Assert.NotNull(clientLocalChannelAddedEvent.Channel);
			Assert.Null(clientRemoteChannelAddedEvent);

			Assert.Null(serverLocalChannelAddedEvent);
			Assert.NotNull(serverRemoteChannelAddedEvent);
			Assert.Equal(TestPort2, serverRemoteChannelAddedEvent.Port.LocalPort);
			Assert.Equal(TestPort1, serverRemoteChannelAddedEvent.Port.RemotePort);
			Assert.NotNull(serverRemoteChannelAddedEvent.Channel);

			Assert.Null(clientLocalChannelRemovedEvent);
			Assert.Null(clientRemoteChannelRemovedEvent);
			Assert.Null(serverLocalChannelRemovedEvent);
			Assert.Null(serverRemoteChannelRemovedEvent);

			Assert.NotNull(serverConnectingEvent);
			Assert.Equal(TestPort1, serverConnectingEvent.Port);
			Assert.False(serverConnectingEvent.IsIncoming);
			Assert.NotNull(serverConnectingEvent.Stream);

			Assert.NotNull(clientConnectingEvent);
			Assert.Equal(TestPort1, clientConnectingEvent.Port);
			Assert.True(clientConnectingEvent.IsIncoming);
			Assert.NotNull(clientConnectingEvent.Stream);

			remoteStream.Close();
		}
		finally
		{
			localServer.Stop();
		}

		await TaskExtensions.WaitUntil(() => serverRemoteChannelRemovedEvent != null)
			.WithTimeout(Timeout);
		await TaskExtensions.WaitUntil(() => clientLocalChannelRemovedEvent != null)
			.WithTimeout(Timeout);

		var clientLocalForwardedPort2 = clientPfs.LocalForwardedPorts.Single();
		Assert.Empty(clientPfs.LocalForwardedPorts.GetChannels(clientLocalForwardedPort2));
		var serverRemoteForwardedPort2 = serverPfs.RemoteForwardedPorts.Single();
		Assert.Empty(serverPfs.RemoteForwardedPorts.GetChannels(serverRemoteForwardedPort2));

		Assert.NotNull(clientLocalChannelRemovedEvent);
		Assert.Equal(TestPort1, clientLocalChannelRemovedEvent.Port.LocalPort);
		Assert.Equal(TestPort1, clientLocalChannelRemovedEvent.Port.RemotePort);
		Assert.NotNull(clientLocalChannelRemovedEvent.Channel);
		Assert.Null(clientRemoteChannelRemovedEvent);
		Assert.Null(serverLocalChannelRemovedEvent);
		Assert.Equal(TestPort2, serverRemoteChannelRemovedEvent.Port.LocalPort);
		Assert.Equal(TestPort1, serverRemoteChannelRemovedEvent.Port.RemotePort);
		Assert.NotNull(serverRemoteChannelRemovedEvent.Channel);

		forwarder.Dispose();

		await TaskExtensions.WaitUntil(() => clientLocalPortRemovedEvent != null)
			.WithTimeout(Timeout);
		await TaskExtensions.WaitUntil(() => serverRemotePortRemovedEvent != null)
			.WithTimeout(Timeout);

		Assert.Empty(clientPfs.LocalForwardedPorts);
		Assert.Empty(clientPfs.RemoteForwardedPorts);
		Assert.Empty(serverPfs.LocalForwardedPorts);
		Assert.Null(clientRemotePortRemovedEvent);
		Assert.Null(serverLocalPortRemovedEvent);
	}


	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task ForwardThroughPipe(bool fromRemote)
	{
		var sessionPair1 = CreateSessionPair(false);
		var sessionPair2 = CreateSessionPair(false);
		await sessionPair1.ConnectAsync();
		await sessionPair2.ConnectAsync();

		_ = sessionPair1.ServerSession.PipeAsync(sessionPair2.ServerSession);

		if (fromRemote)
		{
			// Authorize piped port-forwarding requests.
			sessionPair2.ClientSession.Request += (_, e) =>
			{
				e.IsAuthorized = true;
			};

			var forwarder = await sessionPair1.ClientSession.ForwardFromRemotePortAsync(
				IPAddress.Loopback, TestPort1, "localhost", TestPort2);
			Assert.NotNull(forwarder);

			var localServer = new TcpListener(IPAddress.Loopback, TestPort2);
			localServer.Start();
			try
			{
				var acceptTask = localServer.AcceptTcpClientAsync();
				var remoteClient = new TcpClient();
				await remoteClient.ConnectAsync(IPAddress.Loopback, TestPort1);
				await acceptTask.WithTimeout(Timeout);
			}
			finally
			{
				localServer.Stop();
			}
		}
		else
		{
			var forwarder = await sessionPair1.ClientSession.ForwardToRemotePortAsync(
				IPAddress.Loopback, TestPort1, "localhost", TestPort2);
			Assert.NotNull(forwarder);

			var remoteServer = new TcpListener(IPAddress.Loopback, TestPort2);
			remoteServer.Start();
			try
			{
				var acceptTask = remoteServer.AcceptTcpClientAsync();
				var localClient = new TcpClient();
				await localClient.ConnectAsync(IPAddress.Loopback, TestPort1);
				await acceptTask.WithTimeout(Timeout);
			}
			finally
			{
				remoteServer.Stop();
			}
		}
	}

	[Fact]
	public async Task ForwardAndConnectTwoPorts()
	{
		// Previously there was a deadlock in the following scernario:
		// 1. Server sends request tcpip-forward for port one, and receives response
		// 2. Client sends channel-open for port one
		// 3. Server sends request tcpip-forward for port two
		// 4. Server receives channel-open for port one
		// 5. Server deadlocks waiting for response to port two request

		await this.sessionPair.ConnectAsync();

		var clientPfs = this.sessionPair.ClientSession.ActivateService<PortForwardingService>();
		clientPfs.AcceptLocalConnectionsForForwardedPorts = false;

		var localServer = new TcpListener(IPAddress.Loopback, TestPort1);
		localServer.Start();
		try
		{
			var acceptTask = localServer.AcceptTcpClientAsync();
			this.sessionPair.ClientSession.Request += (_, e) =>
			{
				var pfr = e.Request.ConvertTo<PortForwardRequestMessage>(copy: true);
				if (pfr.Port == TestPort2)
				{
					// This sleep would (usually) trigger the deadlock.
					Thread.Sleep(100);
				}

				e.IsAuthorized = true;
			};

			await this.sessionPair.ServerSession.ForwardFromRemotePortAsync(
				IPAddress.Loopback, TestPort1);

			var forwardTaskTwo = this.sessionPair.ServerSession.ForwardFromRemotePortAsync(
				IPAddress.Loopback, TestPort2);
			var connectTaskOne = clientPfs.ConnectToForwardedPortAsync(
				TestPort1, CancellationToken.None);
			await Task.WhenAll(forwardTaskTwo, connectTaskOne);
		}
		finally
		{
			localServer.Stop();
		}
	}

	[Fact]
	public async Task ReforwardingTheSamePortWhenNotAcceptLocalConnectionsForForwardedPorts()
	{
		await this.sessionPair.ConnectAsync();

		this.sessionPair.ServerSession.Request += (_, e) => e.IsAuthorized = true;

		var clientPfs = this.sessionPair.ClientSession.ActivateService<PortForwardingService>();
		var serverPfs = this.sessionPair.ServerSession.ActivateService<PortForwardingService>();
		serverPfs.AcceptLocalConnectionsForForwardedPorts = false;

		var forwarder1 = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(IPAddress.Loopback, TestPort1);
		Assert.NotNull(forwarder1);

		forwarder1.Dispose();

		// Wait until a connection failure indicates forwarding was successfully cancelled.
		await TaskExtensions.WaitUntil(async () =>
		{
			var remoteClient = new TcpClient();
			try
			{
				await remoteClient.ConnectAsync(IPAddress.Loopback, TestPort1);
			}
			catch (SocketException)
			{
				return true;
			}

			remoteClient.Close();
			return false;
		}).WithTimeout(Timeout);

		var forwarder2 = await this.sessionPair.ClientSession.ForwardFromRemotePortAsync(IPAddress.Loopback, TestPort1);
		Assert.NotNull(forwarder2);
	}
}
