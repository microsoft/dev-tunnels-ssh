using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.IO;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Services;
using Xunit;
using Xunit.Sdk;

namespace Microsoft.DevTunnels.Ssh.Test;

public class ServiceTests : IDisposable
{
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

	private readonly TestServiceConfig testConfig = new TestServiceConfig();
	private readonly SessionPair sessionPair;
	private readonly SshClientSession clientSession;
	private readonly SshServerSession serverSession;
	private SemaphoreSlim clientClosedSemaphore = new SemaphoreSlim(0);
	private SemaphoreSlim serverClosedSemaphore = new SemaphoreSlim(0);
	private SshSessionClosedEventArgs clientClosedEvent = null;
	private SshSessionClosedEventArgs serverClosedEvent = null;
	private SshService activatedService = null;

	public ServiceTests()
	{
		var clientConfig = new SshSessionConfiguration();
		var serverConfig = new SshSessionConfiguration();
		clientConfig.Services.Add(typeof(MessageService), null);
		serverConfig.Services.Add(typeof(TestService1), null);
		serverConfig.Services.Add(typeof(TestService2), testConfig);
		serverConfig.Services.Add(typeof(TestService3), testConfig);
		serverConfig.Services.Add(typeof(TestService4), null);
		serverConfig.Services.Add(typeof(TestService5), null);

		this.sessionPair = new SessionPair(serverConfig, clientConfig);
		this.clientSession = sessionPair.ClientSession;
		this.serverSession = sessionPair.ServerSession;

		this.serverSession.ServiceActivated += (sender, e) =>
		{
			this.activatedService = e;
		};

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

	private async Task CloseSessions()
	{
		this.sessionPair.ServerStream.Close();
		this.sessionPair.ClientStream.Close();

		await Task.WhenAll(
			this.serverClosedSemaphore.WaitAsync(),
			this.clientClosedSemaphore.WaitAsync()).WithTimeout(Timeout);
	}

	[Fact]
	public async Task ActivateOnServiceRequest()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		Assert.DoesNotContain(this.serverSession.Services, (s) => s is TestService1);

		await this.clientSession.RequestServiceAsync(TestService1.Name).WithTimeout(Timeout);
		Assert.Contains(this.serverSession.Services, (s) => s is TestService1);
		Assert.IsType<TestService1>(this.activatedService);

		var testService = this.serverSession.Services.OfType<TestService1>().Single();
		Assert.Null(testService.Config);

		Assert.False(testService.DisposedTask.IsCompleted);
		await this.CloseSessions();
		await testService.DisposedTask.WithTimeout(Timeout);
	}

	[Fact]
	public async Task ActivateOnSessionRequest()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		Assert.DoesNotContain(this.serverSession.Services, (s) => s is TestService2);

		var request = new SessionRequestMessage
		{
			RequestType = TestService2.Request,
			WantReply = true,
		};
		var result = await this.clientSession.RequestAsync(request).WithTimeout(Timeout);
		Assert.True(result);
		Assert.Contains(this.serverSession.Services, (s) => s is TestService2);
		Assert.IsType<TestService2>(this.activatedService);

		var testService = this.serverSession.Services.OfType<TestService2>().Single();
		Assert.Equal(testConfig, testService.Config);
		Assert.NotNull(testService.RequestMessage);

		await this.CloseSessions();
	}

	[Fact]
	public async Task ActivateOnChannelType()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		Assert.DoesNotContain(this.serverSession.Services, (s) => s is TestService3);

		var channel = await this.clientSession.OpenChannelAsync(TestService3.ChannelType)
			.WithTimeout(Timeout);
		Assert.Contains(this.serverSession.Services, (s) => s is TestService3);
		Assert.IsType<TestService3>(this.activatedService);

		var testService = this.serverSession.Services.OfType<TestService3>().Single();
		Assert.Equal(testConfig, testService.Config);
		Assert.NotNull(testService.Channel);

		await this.CloseSessions();
	}

	[Fact]
	public async Task ActivateOnChannelRequest()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		Assert.DoesNotContain(this.serverSession.Services, (s) => s is TestService4);

		var channel = await this.clientSession.OpenChannelAsync()
			.WithTimeout(Timeout);
		Assert.DoesNotContain(this.serverSession.Services, (s) => s is TestService4);

		var request = new ChannelRequestMessage
		{
			RequestType = TestService4.Request,
			WantReply = true,
		};
		await channel.RequestAsync(request).WithTimeout(Timeout);
		Assert.Contains(this.serverSession.Services, (s) => s is TestService4);
		Assert.IsType<TestService4>(this.activatedService);

		var testService = this.serverSession.Services.OfType<TestService4>().Single();
		Assert.NotNull(testService.RequestMessage);

		await this.CloseSessions();
	}

	[Fact]
	public async Task ActivateOnChannelTypeChannelRequest()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);
		Assert.DoesNotContain(this.serverSession.Services, (s) => s is TestService5);

		var channel = await this.clientSession.OpenChannelAsync(TestService5.ChannelType)
			.WithTimeout(Timeout);
		Assert.DoesNotContain(this.serverSession.Services, (s) => s is TestService5);

		var request = new ChannelRequestMessage
		{
			RequestType = TestService5.Request,
			WantReply = true,
		};
		await channel.RequestAsync(request).WithTimeout(Timeout);
		Assert.Contains(this.serverSession.Services, (s) => s is TestService5);
		Assert.IsType<TestService5>(this.activatedService);

		var testService = this.serverSession.Services.OfType<TestService5>().Single();
		Assert.NotNull(testService.Channel);
		Assert.NotNull(testService.RequestMessage);

		await this.CloseSessions();
	}

	[Fact]
	public async Task SendUnimplementedMessage()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var messageService = this.sessionPair.ClientSession.ActivateService<MessageService>();
		await messageService.SendMessageAsync(new TestMessage(), CancellationToken.None);

		// Wait for open channel response, to ensure the message is processed.
		await this.sessionPair.ClientSession.OpenChannelAsync();
	}

	[Fact]
	public async Task SendDebugMessage()
	{
		await this.sessionPair.ConnectAsync().WithTimeout(Timeout);

		var messageService = this.sessionPair.ClientSession.ActivateService<MessageService>();
		await messageService.SendMessageAsync(new DebugMessage("test"), CancellationToken.None);

		// Wait for open channel response, to ensure the message is processed.
		await this.sessionPair.ClientSession.OpenChannelAsync();
	}

	private class TestServiceConfig
	{
	}

	[ServiceActivation(ServiceRequest = Name)]
	private class TestService1 : SshService
	{
		public const string Name = "test-service-1";
		private readonly TaskCompletionSource<bool> disposedCompletion =
			new TaskCompletionSource<bool>();

		public TestService1(SshSession session) : base(session) { }
		public TestService1(SshSession session, TestServiceConfig config) : base(session)
		{
			Config = config;
		}

		public TestServiceConfig Config { get; }

		public Task<bool> DisposedTask => this.disposedCompletion.Task;

		protected override void Dispose(bool disposing)
		{
			this.disposedCompletion.TrySetResult(disposing);
			base.Dispose(disposing);
		}
	}

	[ServiceActivation(SessionRequest = Request)]
	private class TestService2 : SshService
	{
		public const string Request = "test-service-2";

		public TestService2(SshSession session) : base(session) { }
		public TestService2(SshSession session, TestServiceConfig config) : base(session)
		{
			Config = config;
		}

		public TestServiceConfig Config { get; }

		public SessionRequestMessage RequestMessage { get; private set; }

		protected override async Task OnSessionRequestAsync(
			SshRequestEventArgs<SessionRequestMessage> request,
			CancellationToken cancellation)
		{
			RequestMessage = request.Request;
			request.IsAuthorized = true;

			if (request.Request.WantReply)
			{
				await SendMessageAsync(new SessionRequestSuccessMessage(), cancellation);
			}
		}
	}

	[ServiceActivation(ChannelType = ChannelType)]
	private class TestService3 : SshService
	{
		public const string ChannelType = "test-service-3";

		public TestService3(SshSession session, TestServiceConfig config) : base(session)
		{
			Config = config;
		}

		public TestServiceConfig Config { get; }

		public SshChannel Channel { get; private set; }

		protected override Task<ChannelMessage> OnChannelOpeningAsync(
			SshChannelOpeningEventArgs args,
			CancellationToken cancellation)
		{
			Channel = args.Channel;
			return Task.FromResult<ChannelMessage>(new ChannelOpenConfirmationMessage());
		}
	}

	[ServiceActivation(ChannelRequest = Request)]
	private class TestService4 : SshService
	{
		public const string Request = "test-service-4";

		public TestService4(SshSession session) : base(session) { }

		public ChannelRequestMessage RequestMessage { get; private set; }

		public SshChannel Channel { get; private set; }

		protected override Task OnChannelRequestAsync(
			SshChannel channel,
			SshRequestEventArgs<ChannelRequestMessage> request,
			CancellationToken cancellation)
		{
			Channel = channel;
			RequestMessage = request.Request;
			request.IsAuthorized = true;
			return Task.CompletedTask;
		}
	}

	[ServiceActivation(ChannelType = ChannelType, ChannelRequest = Request)]
	private class TestService5 : SshService
	{
		public const string ChannelType = "test-service-5-channel";
		public const string Request = "test-service-5";

		public TestService5(SshSession session) : base(session) { }

		public SshChannel Channel { get; private set; }

		public ChannelRequestMessage RequestMessage { get; private set; }

		protected override Task OnChannelRequestAsync(
			SshChannel channel,
			SshRequestEventArgs<ChannelRequestMessage> request,
			CancellationToken cancellation)
		{
			Channel = channel;
			RequestMessage = request.Request;
			request.IsAuthorized = true;
			return Task.CompletedTask;
		}
	}

	/// <summary>
	/// A test service capable of sending custom message types.
	/// </summary>
	[ServiceActivation(ServiceRequest = Name)]
	private class MessageService : SshService
	{
		public const string Name = "test-message-service";

		public MessageService(SshSession session) : base(session) { }

		public new Task SendMessageAsync(SshMessage message, CancellationToken cancellation)
			=> base.SendMessageAsync(message, cancellation);
	}

	private class TestMessage : SshMessage
	{
		public override byte MessageType => 199;

		protected override void OnRead(ref SshDataReader reader)
		{
		}

		protected override void OnWrite(ref SshDataWriter writer)
		{
		}
	}
}
