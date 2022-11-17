// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Metrics;
using Microsoft.DevTunnels.Ssh.Services;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Represents a channel on an SSH session. A sesssion may include multiple channels, which
/// are multiplexed over the connection. Each channel within a session has a unique integer ID.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
public class SshChannel : IDisposable
{
	/// <summary>
	/// Default channel type.
	/// </summary>
	public const string SessionChannelType = "session";

	/// <summary>
	/// Default maximum packet size. Channel data payloads larger than the max packet size will
	/// be broken into chunks before sending.
	/// </summary>
	/// <remarks>
	/// The actual <see cref="MaxPacketSize"/> may be smaller (but never larger) than the default
	/// if requested by the other side.
	/// </remarks>
	public const uint DefaultMaxPacketSize = 32 * 1024;

	/// <summary>
	/// Default maximum window size for received data. The other side will not send more data than
	/// the window size until it receives an acknowledgement that some of the data was received and
	/// processed by this side.
	/// </summary>
	/// <remarks>
	/// A non-default <see cref="MaxWindowSize"/> may be configured at the time of opening the
	/// channel.
	/// </remarks>
	public const uint DefaultMaxWindowSize = DefaultMaxPacketSize * 32;

	private readonly ConnectionService connectionService;
	private readonly SemaphoreSlim sendSemaphore = new SemaphoreSlim(0);
	private readonly SemaphoreSlim sendingWindowSemaphore = new SemaphoreSlim(1);
	private readonly ConcurrentQueue<TaskCompletionSource<bool>> requestCompletionSources = new ();
	private readonly TaskChain taskChain;
	private readonly SemaphoreSlim channelRequestSemaphore = new SemaphoreSlim(1);

	private uint remoteWindowSize;
	private uint maxWindowSize;
	private uint windowSize;
	private bool remoteClosed;
	private bool localClosed;
	private bool disposed;
	private bool sentEof;
	private uint? exitStatus;
	private string? exitSignal;
	private string? exitErrorMessage;

	internal SshChannel(
		ConnectionService connectionService,
		string channelType,
		uint channelId,
		uint remoteChannelId,
		uint remoteMaxWindowSize,
		uint remoteMaxPacketSize)
	{
		if (connectionService == null) throw new ArgumentNullException(nameof(connectionService));
		if (channelType == null) throw new ArgumentNullException(channelType);

		this.connectionService = connectionService;
		Trace = connectionService.Session.Trace;
		taskChain = new TaskChain(Trace);
		ChannelType = channelType;
		ChannelId = channelId;
		RemoteChannelId = remoteChannelId;
		this.remoteWindowSize = remoteMaxWindowSize;
		this.maxWindowSize = DefaultMaxWindowSize;
		this.windowSize = this.maxWindowSize;
		MaxPacketSize = Math.Min(remoteMaxPacketSize, DefaultMaxPacketSize);
	}

	/// <summary>
	/// The session that carries this channel.
	/// </summary>
	public SshSession Session => this.connectionService.Session;

	public TraceSource Trace { get; }

	/// <summary>
	/// Gets an object that reports measurements about the channel.
	/// </summary>
	public ChannelMetrics Metrics { get; } = new ChannelMetrics();

	/// <summary>
	/// Type of the channel, often <see cref="SessionChannelType"/> but may be another
	/// value for a nonstandard channel type. (A session may carry multiple channels of the
	/// same type.)
	/// </summary>
	public string ChannelType { get; private set; }

	public uint ChannelId { get; private set; }

	public uint RemoteChannelId { get; private set; }

	public bool IsClosed => this.localClosed || this.remoteClosed;

	/// <summary>
	/// Event raised when a request message is received on the channel.
	/// </summary>
	public event EventHandler<SshRequestEventArgs<ChannelRequestMessage>>? Request;

	/// <summary>
	/// Event raised when a data message is received on the channel.
	/// </summary>
	/// <remarks>
	/// Users of a channel MUST add a `DataReceived` event handler immediately after a
	/// channel is opened/accepted, or else all sesssion communication will be blocked.
	/// (The `SshStream` class does this automatically.)
	/// <para/>
	/// The event handler must call <see cref="AdjustWindow" /> when the data has been
	/// consumed, to notify the remote side that it may send more data.
	/// </remarks>
	public event EventHandler<Buffer>? DataReceived;

	/// <summary>
	/// Event raised when the channel is closed (from either side).
	/// </summary>
	public event EventHandler<SshChannelClosedEventArgs> Closed
	{
		add
		{
			if (value == null) throw new ArgumentNullException(nameof(value));

			ClosedEventHandler += value;
			if (this.localClosed)
			{
				value.Invoke(this, SshChannelClosedEventArgs.Empty);
			}
		}
		remove
		{
			ClosedEventHandler -= value;
		}
	}

	private EventHandler<SshChannelClosedEventArgs>? ClosedEventHandler { get; set; }

	/// <summary>
	/// Gets or sets the maximum window size for received data. The other side will not send more
	/// data than the window size until it receives an acknowledgement that some of the data was
	/// received and processed by this side.
	/// </summary>
	/// <remarks>
	/// The default value is <see cref="DefaultMaxWindowSize"/>. The value may be configured for
	/// a channel opened by this side by setting <see cref="ChannelOpenMessage.MaxWindowSize"/>
	/// in the message object passed to
	/// <see cref="SshSession.OpenChannelAsync(ChannelOpenMessage, ChannelRequestMessage?, CancellationToken)"/>,
	/// or for a channel opened by the other side by assigning to this property while handling the
	/// <see cref="SshSession.ChannelOpening"/> event. Changing the maximum window size at any
	/// other time is not valid because the other side would not be aware of the change. 
	/// </remarks>
	public uint MaxWindowSize
	{
		get
		{
			return this.maxWindowSize;
		}
		set
		{
			if (IsMaxWindowSizeLocked)
			{
				throw new InvalidOperationException(
					"Cannot change the max window size after opening the channel.");
			}

			if (value < MaxPacketSize)
			{
				throw new ArgumentException(
					"Maximum window size cannot be less than maximum packet size.",
					nameof(value));
			}

			this.maxWindowSize = value;
		}
	}

	/// <summary>
	/// Gets or sets a value indicating whether <see cref="MaxWindowSize"/> is locked, so that it
	/// cannot be changed after the channel is opened.
	/// </summary>
	internal bool IsMaxWindowSizeLocked { get; set; }

	/// <summary>
	/// Gets the maximum packet size. Channel data payloads larger than the max packet size will
	/// be broken into chunks before sending.
	/// </summary>
	/// <remarks>
	/// The actual max packet size may be smaller (but never larger) than
	/// <see cref="DefaultMaxPacketSize"/> if requested by the other side.
	/// </remarks>
	public uint MaxPacketSize { get; }

	/// <summary>
	/// Sends a channel request and waits for a response.
	/// </summary>
	/// <param name="request">Request details</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The authorization status of the response; if false, the other side denied the
	/// request.</returns>
	/// <exception cref="ObjectDisposedException">The channel was closed before sending the
	/// request.</exception>
	/// <exception cref="SshChannelException">The channel was closed while waiting for a
	/// reply to the request.</exception>
	/// <remarks>
	/// Note if <see cref="ChannelRequestMessage.WantReply" /> is false, this method returns
	/// true immediately after sending the request, without waiting for a reply.
	/// </remarks>
	public async Task<bool> RequestAsync(
		ChannelRequestMessage request,
		CancellationToken cancellation = default)
	{
		if (request == null) throw new ArgumentNullException(nameof(request));
		if (this.disposed) throw new ObjectDisposedException(nameof(SshChannel));

		request.RecipientChannel = RemoteChannelId;
		if (!request.WantReply)
		{
			// If a reply is not requested, there's no need to set up a completion source.
			await Session.SendMessageAsync(request, cancellation).ConfigureAwait(false);
			return true;
		}

		// Capture as a local variable because the member may change.
		var requestCompletionSource = new TaskCompletionSource<bool>(
			TaskCreationOptions.RunContinuationsAsynchronously);
		if (cancellation.CanBeCanceled)
		{
			cancellation.Register(() => requestCompletionSource.TrySetCanceled());
			cancellation.ThrowIfCancellationRequested();
		}

		await channelRequestSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			this.requestCompletionSources.Enqueue(requestCompletionSource);
			await Session.SendMessageAsync(request, cancellation).ConfigureAwait(false);
		}
		finally
		{
			channelRequestSemaphore.Release();
		}

		return await requestCompletionSource.Task.ConfigureAwait(false);
	}

	/// <summary>
	/// Sends data over the channel. Does not wait for any response.
	/// </summary>
	/// <remarks>
	/// If the data length is zero, this sends an EOF message, and the channel should be
	/// closed immediately afterward.
	/// </remarks>
	public async Task SendAsync(Buffer data, CancellationToken cancellation)
	{
		if (this.disposed) throw new ObjectDisposedException(nameof(SshChannel));

		if (data.Count == 0)
		{
			await SendEofAsync(cancellation).ConfigureAwait(false);
			return;
		}
		else if (this.sentEof)
		{
			throw new InvalidOperationException("Cannot send more data after EOF.");
		}

		// Unfortunately the data must be copied to a new buffer at this point in case
		// the caller does not await while large data is sent in multiple chunks. This also
		// ensures the data is still available to be re-sent later in case of disconnect.
		// (The caller may re-use the data buffer that was passed in.)
		data = data.Copy();

		// Prevent out-of-order message chunks even if the caller does not await.
		// Also don't send until the channel is fully opened.
		await this.sendSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			int offset = 0;
			int count = data.Count;
			while (count > 0)
			{
				var packetSize = Math.Min(
					(int)Math.Min(this.remoteWindowSize, MaxPacketSize), count);
				if (packetSize == 0)
				{
					Trace.TraceEvent(
						TraceEventType.Warning,
						SshTraceEventIds.ChannelWaitForWindowAdjust,
						$"{this} send window is full. Waiting for window adjustment before sending.");
					await this.sendingWindowSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
					continue;
				}

				var msg = new ChannelDataMessage
				{
					RecipientChannel = RemoteChannelId,
					Data = data.Slice(offset, packetSize),
				};

				await Session.SendMessageAsync(msg, cancellation).ConfigureAwait(false);

				this.remoteWindowSize -= (uint)packetSize;
				count -= packetSize;
				offset += packetSize;

				Metrics.AddBytesSent(packetSize);
			}
		}
		finally
		{
			this.sendSemaphore.TryRelease();
		}
	}

	internal void EnableSending()
	{
		this.sendSemaphore.TryRelease();
	}

	private async Task SendEofAsync(CancellationToken cancellation)
	{
		if (this.sentEof)
		{
			return;
		}

		await this.sendSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			this.sentEof = true;
			var msg = new ChannelEofMessage { RecipientChannel = RemoteChannelId };
			await Session.SendMessageAsync(msg, cancellation).ConfigureAwait(false);
		}
		finally
		{
			this.sendSemaphore.TryRelease();
		}
	}

	internal async Task<bool> HandleRequestAsync(
		ChannelRequestMessage request,
		CancellationToken cancellation)
	{
		if (string.IsNullOrEmpty(request.RequestType))
		{
			throw new SshConnectionException(
				"Channel request type not specified.", SshDisconnectReason.ProtocolError);
		}

		if (request.RequestType == ChannelRequestTypes.ExitStatus)
		{
			var signal = request.ConvertTo<ChannelSignalMessage>();
			this.exitStatus = signal.ExitStatus;
			return true;
		}
		else if (request.RequestType == ChannelRequestTypes.ExitSignal)
		{
			var signal = request.ConvertTo<ChannelSignalMessage>();
			this.exitSignal = signal.ExitSignal;
			this.exitErrorMessage = signal.ErrorMessage;
			return true;
		}
		else if (request.RequestType == ChannelRequestTypes.Signal)
		{
			request = request.ConvertTo<ChannelSignalMessage>();
		}

		var args = new SshRequestEventArgs<ChannelRequestMessage>(
			request.RequestType!, request, this.Session.Principal, cancellation);

		var (serviceType, serviceConfig) = ServiceActivationAttribute.FindService(
			Session.Config.Services,
			(a) =>
				(a.ChannelType == null || a.ChannelType == ChannelType) &&
				a.ChannelRequest == request.RequestType);

		var requestTask = async (Type? serviceType, object? serviceConfig) =>
		{
			if (serviceType != null)
			{
				// A service was configured for activation via this session request type.
				var service = Session.ActivateService(serviceType, serviceConfig);
				await service.OnChannelRequestAsync(this, args, cancellation).ConfigureAwait(false);
			}
			else
			{
				try
				{
					Request?.Invoke(this, args);
				}
				catch (Exception ex)
				{
					Trace.TraceEvent(
						TraceEventType.Error,
						SshTraceEventIds.ChannelRequestFailed,
						$"Channel request failed with exception ${ex.ToString()}.");

					// Send a failure response on exception
					args.ResponseTask = null;
					args.IsAuthorized = false;
				}
			}
		};

		var sendResponseMessageTask = async (SshRequestEventArgs<ChannelRequestMessage> sshRequestArgs) =>
		{
			SshMessage? response = null;
			if (sshRequestArgs.ResponseTask != null)
			{
				try
				{
					response = await sshRequestArgs.ResponseTask.ConfigureAwait(false);
					sshRequestArgs.IsAuthorized = (response is ChannelSuccessMessage);
				}
				catch (Exception ex)
				{
					Trace.TraceEvent(
						 TraceEventType.Error,
						 SshTraceEventIds.ChannelRequestFailed,
						 $"Channel request response task failed with exception ${ex.ToString()}.");
					response = new ChannelFailureMessage();
					sshRequestArgs.IsAuthorized = false;
				}
			}

			if (sshRequestArgs.Request.WantReply)
			{
				if (sshRequestArgs.IsAuthorized)
				{
					response ??= new ChannelSuccessMessage();
					((ChannelSuccessMessage)response).RecipientChannel = RemoteChannelId;
				}
				else
				{
					if (!(response is ChannelFailureMessage))
					{
						response = new ChannelFailureMessage();
					}

					((ChannelFailureMessage)response).RecipientChannel = RemoteChannelId;
				}

				await Session.SendMessageAsync(response!, cancellation).ConfigureAwait(false);
			}
		};

		await taskChain.RunInSequence(
			() => sendResponseMessageTask(args),
			(ex) =>
			{
				Trace.TraceEvent(
					TraceEventType.Error,
					SshTraceEventIds.ChannelRequestFailed,
					$"Channel request run in sequence failed with exception ${ex?.ToString()}.");
			},
			() => requestTask(serviceType, serviceConfig),
			cancellation).ConfigureAwait(false);

		return args.IsAuthorized;
	}

	internal void HandleResponse(bool result)
	{
		if (this.requestCompletionSources.TryDequeue(out var completion))
		{
			completion.TrySetResult(result);
		}
	}

	internal async Task HandleDataReceivedAsync(Buffer data, CancellationToken cancellation)
	{
		Metrics.AddBytesReceived(data.Count);

		int delayMilliseconds = 1;
		while (DataReceived == null)
		{
			cancellation.ThrowIfCancellationRequested();

			// A data message was received before a DataReceived event handler was added!
			// This should normally only happen in artificial tests that use an in-proc stream.
			await Task.Delay(delayMilliseconds, cancellation).ConfigureAwait(false);
			if (delayMilliseconds < 1000)
			{
				delayMilliseconds *= 2;
			}
		}

		// DataRecieved handler is to adjust the window when it's done with the data.
		DataReceived.Invoke(this, data);
	}

	internal void OnEof()
	{
		Trace.TraceEvent(
			TraceEventType.Verbose, SshTraceEventIds.ChannelEofReceived, $"{this} EOF received");
		DataReceived?.Invoke(this, Buffer.Empty);
	}

	internal void AdjustRemoteWindow(uint bytesToAdd)
	{
		this.remoteWindowSize += bytesToAdd;

		// If the semaphore count is 0, a sender is waiting for the window to open.
		if (this.sendingWindowSemaphore.CurrentCount == 0)
		{
			this.sendingWindowSemaphore.Release();
		}
	}

	/// <summary>
	/// Adjusts the local receiving window size by the specified amount, notifying
	/// the remote side that it is free to send more data.
	/// </summary>
	/// <remarks>
	/// This method MUST be called either immediately or eventually by the
	/// <see cref="DataReceived" /> event handler as incoming data is processed.
	/// </remarks>
	public void AdjustWindow(uint messageLength)
	{
		if (this.disposed)
		{
			return;
		}

		if (messageLength > this.windowSize)
		{
			throw new ArgumentOutOfRangeException(
				nameof(messageLength),
				"Window adjustment cannot be larger than current window size.");
		}

		this.windowSize -= messageLength;

		// If at least half of the receive window is consumed, then send a message to the other side
		// acknowledging the received data and indicating it's OK for it to send more data.
		if (this.windowSize <= this.maxWindowSize / 2)
		{
			uint bytesToAdd = this.maxWindowSize - this.windowSize;
			this.windowSize = this.maxWindowSize;
			this.TrySendAdjustWindowMessage(bytesToAdd);
		}
	}

	/// <summary>
	/// Tries to send a message informing the other end of the channel that more bytes
	/// may be sent.
	/// </summary>
	/// <remarks>
	/// This method is `async void` because callers should not be expected to wait for it.
	/// </remarks>
	private async void TrySendAdjustWindowMessage(uint bytesToAdd)
	{
		try
		{
			await Session.SendMessageAsync(
				new ChannelWindowAdjustMessage
				{
					RecipientChannel = RemoteChannelId,
					BytesToAdd = bytesToAdd,
				},
				CancellationToken.None).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ChannelWindowAdjustFailed,
				$"{this} {nameof(AdjustWindow)} failed: {ex.Message}");
		}
	}

	/// <summary>
	/// Sends a close message over the channel and then closes the channel.
	/// </summary>
	public async Task CloseAsync(
		CancellationToken cancellation = default)
	{
		if (this.disposed)
		{
			return;
		}

		var tcs = new TaskCompletionSource<bool>();

		await taskChain.RunInSequence(
			async () =>
			{
				if (!this.remoteClosed && !this.localClosed)
				{
					this.remoteClosed = true;

					bool acquiredSemaphore = false;
					try
					{
						// Wait for any messages to complete before sending the close message.
						await this.sendSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
						acquiredSemaphore = true;

						await Session.SendMessageAsync(
							new ChannelCloseMessage
							{
								RecipientChannel = RemoteChannelId,
							},
							cancellation).ConfigureAwait(false);
					}
					catch (ObjectDisposedException)
					{
						// The session was already closed.
					}
					catch (OperationCanceledException)
					{
						tcs.TrySetCanceled();
					}
					finally
					{
						if (acquiredSemaphore)
						{
							this.sendSemaphore.TryRelease();
						}
					}
				}

				if (!this.localClosed)
				{
					this.localClosed = true;
					var closedMessage = RaiseClosedEvent();
					RequestCompletionSourcesSetException(new SshChannelException(closedMessage));
				}

				DisposeInternal();
				tcs.TrySetResult(true);
			},
			(ex) =>
			{
				Trace.TraceEvent(
					TraceEventType.Error,
					SshTraceEventIds.ChannelCloseFailed,
					$"Channel close failed with exception ${ex.ToString()}.");
				DisposeInternal();
				if (ex is ObjectDisposedException)
				{
					tcs.TrySetResult(false);
				}
				else
				{
					tcs.TrySetException(ex);
				}
			}, CancellationToken.None).ConfigureAwait(false);
		await tcs.Task.ConfigureAwait(false);
	}

	/// <summary>
	/// Sends an exit status message over the channel and then closes the channel.
	/// </summary>
	public async Task CloseAsync(
		uint exitStatus,
		CancellationToken cancellation = default)
	{
		if (!this.remoteClosed && !this.localClosed)
		{
			this.exitStatus = exitStatus;

			await Session.SendMessageAsync(
				new ChannelSignalMessage
				{
					RecipientChannel = RemoteChannelId,
					ExitStatus = exitStatus,
				},
				cancellation).ConfigureAwait(false);
		}

		await CloseAsync(cancellation).ConfigureAwait(false);
	}

	/// <summary>
	/// Sends an exit signal message over the channel and then closes the channel.
	/// </summary>
	public async Task CloseAsync(
		string exitSignal,
		string? errorMessage,
		CancellationToken cancellation = default)
	{
		if (!this.remoteClosed && !this.localClosed)
		{
			this.exitSignal = exitSignal;
			this.exitErrorMessage = errorMessage;

			await Session.SendMessageAsync(
				new ChannelSignalMessage
				{
					RecipientChannel = RemoteChannelId,
					ExitSignal = exitSignal,
					ErrorMessage = errorMessage,
				},
				cancellation).ConfigureAwait(false);
		}

		await CloseAsync(cancellation).ConfigureAwait(false);
	}

	/// <summary>
	/// Called by the ConnectionService when a ChannelCloseMessage was received.
	/// </summary>
	internal void Close()
	{
		if (!this.localClosed)
		{
			this.localClosed = true;
			var closedMessage = RaiseClosedEvent(closedByRemote: true);
			RequestCompletionSourcesSetException(new SshChannelException(closedMessage));
		}

		DisposeInternal();
	}

	private string RaiseClosedEvent(bool closedByRemote = false)
	{
		var metricsMessage = $" (S: {Metrics.BytesSent}, R: {Metrics.BytesReceived})";
		var originMessage = closedByRemote ? "remotely" : "locally";
		string closedMessage;
		SshChannelClosedEventArgs args;

		if (this.exitStatus.HasValue)
		{
			closedMessage = $"{this} closed {originMessage}: status={this.exitStatus}.";
			args = new SshChannelClosedEventArgs(this.exitStatus.Value);
		}
		else if (!string.IsNullOrEmpty(this.exitSignal))
		{
			closedMessage = $"{this} closed {originMessage}: signal={this.exitSignal} {this.exitErrorMessage}.";
			args = new SshChannelClosedEventArgs(this.exitSignal!, this.exitErrorMessage);
		}
		else
		{
			closedMessage = $"{this} closed {originMessage}.";
			args = SshChannelClosedEventArgs.Empty;
		}

		Trace.TraceEvent(
			TraceEventType.Verbose,
			SshTraceEventIds.ChannelClosed,
			closedMessage + metricsMessage);
		ClosedEventHandler?.Invoke(this, args);
		return closedMessage;
	}

	internal void Close(Exception ex)
	{
		if (!this.localClosed)
		{
			this.localClosed = true;
			Trace.TraceEvent(
				TraceEventType.Verbose, SshTraceEventIds.ChannelClosed, $"{this} closed: {ex.Message}");
			ClosedEventHandler?.Invoke(this, new SshChannelClosedEventArgs(ex));
		}

		DisposeInternal();
	}

	public void Dispose()
	{
		this.Dispose(true);
		GC.SuppressFinalize(this);
	}

	protected virtual void Dispose(bool disposing)
	{
		if (disposing && !this.disposed)
		{
			if (!this.localClosed)
			{
				if (!this.remoteClosed)
				{
					this.remoteClosed = true;
					if (!Session.IsClosed)
					{
						try
						{
							// TODO: Implement IAsyncDisposable (requires .NET Standard 2.1).
							_ = Session.SendMessageAsync(
								new ChannelCloseMessage
								{
									RecipientChannel = RemoteChannelId,
								},
								CancellationToken.None);
						}
						catch (Exception)
						{
							// Don't throw from Dispose().
							// Exception details have already been traced.
						}
					}
				}

				this.localClosed = true;
				var message = Session.IsClosed ? $"{Session} closed." : $"{this} disposed.";
				Trace.TraceEvent(TraceEventType.Verbose, SshTraceEventIds.ChannelClosed, message);
				ClosedEventHandler?.Invoke(this, new SshChannelClosedEventArgs("SIGABRT", message));
			}

			DisposeInternal();
		}
	}

	private void DisposeInternal()
	{
		if (this.disposed)
		{
			return;
		}

		this.disposed = true;

		RequestCompletionSourcesSetException(new ObjectDisposedException(GetType().Name));

		this.connectionService.RemoveChannel(this);
		this.sendSemaphore.Dispose();
		this.sendingWindowSemaphore.Dispose();
		this.channelRequestSemaphore.Dispose();
		this.taskChain.Dispose();
	}

	private void RequestCompletionSourcesSetException(Exception ex)
	{
		foreach (var completion in this.requestCompletionSources)
		{
			completion.TrySetException(ex);
		}
	}

	public override string ToString()
	{
		return $"{GetType().Name}(Type: {ChannelType}, " +
			$"Id: {ChannelId}, RemoteId: {RemoteChannelId})";
	}
}
