// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Services;

/// <summary>
/// Handles SSH protocol messages related to opening channels.
/// </summary>
[ServiceActivation(ServiceRequest = Name)]
#pragma warning disable CA1812 // Avoid Uninstantiated Internal Classes
internal class ConnectionService : SshService
#pragma warning restore CA1812 // Avoid Uninstantiated Internal Classes
{
	/// <summary>
	/// Tracks a channel open request that has been sent and not yet acknowledged.
	/// Used as a value in the 'pendingChannels' dictionary; the channel ID is the key.
	/// </summary>
	private class PendingChannel
	{
		public PendingChannel(
			 ChannelOpenMessage openMessage,
			 TaskCompletionSource<SshChannel> completionSource)
		{
			OpenMessage = openMessage;
			CompletionSource = completionSource;
		}

		public ChannelOpenMessage OpenMessage { get; }
		public TaskCompletionSource<SshChannel> CompletionSource { get; }
		public CancellationTokenRegistration CancellationRegistration { get; set; }
	}

	public const string Name = "ssh-connection";

	private readonly object lockObject = new object();
	private readonly IDictionary<uint, SshChannel> channels;
	private readonly IDictionary<uint, SshChannel> nonAcceptedChannels;
	private readonly IDictionary<uint, PendingChannel> pendingChannels;
	private readonly IDictionary<string, IList<TaskCompletionSource<SshChannel>>> pendingAcceptChannels;
	private bool disposed;
	private long channelCounter = -1;
	private Exception? closedException = null;

	public ConnectionService(SshSession session) : base(session)
	{
		this.channels = new Dictionary<uint, SshChannel>();
		this.nonAcceptedChannels = new Dictionary<uint, SshChannel>();
		this.pendingChannels = new Dictionary<uint, PendingChannel>();
		this.pendingAcceptChannels =
			new Dictionary<string, IList<TaskCompletionSource<SshChannel>>>();
	}

	public ICollection<SshChannel> Channels => this.channels.Values;

	public void Close(Exception ex)
	{
		this.closedException = ex;

		SshChannel[] channels;
		TaskCompletionSource<SshChannel>[] channelCompletions;
		lock (this.lockObject)
		{
			channels = Channels.ToArray();
			channelCompletions = this.pendingChannels.Select((c) => c.Value.CompletionSource)
				.Concat(this.pendingAcceptChannels.SelectMany(pac => pac.Value)).ToArray();
		}

		foreach (var channel in channels)
		{
			channel.Close(ex);
		}

		foreach (var channelCompletion in channelCompletions)
		{
			channelCompletion.TrySetException(ex);
		}
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			SshChannel[] channels;
			TaskCompletionSource<SshChannel>[] channelCompletions;
			lock (this.lockObject)
			{
				channels = Channels.ToArray();
				channelCompletions = this.pendingChannels.Select((c) => c.Value.CompletionSource)
					.Concat(this.pendingAcceptChannels.SelectMany(pac => pac.Value)).ToArray();
				this.disposed = true;
			}

			foreach (var channel in channels)
			{
				channel.Dispose();
			}

			foreach (var channelCompletion in channelCompletions)
			{
				channelCompletion.TrySetException(
					new ObjectDisposedException(Session.ToString(), "Session closed."));
			}
		}

		base.Dispose(disposing);
	}

	internal async Task<uint> OpenChannelAsync(
		ChannelOpenMessage openMessage,
		TaskCompletionSource<SshChannel> completionSource,
		CancellationToken cancellation)
	{
		uint channelId = (uint)Interlocked.Increment(ref this.channelCounter);
		if (channelId > int.MaxValue)
		{
			this.channelCounter = int.MaxValue;
			throw new InvalidOperationException("Maximum number of channels reached.");
		}

		openMessage.SenderChannel = channelId;

		lock (this.lockObject)
		{
			if (this.disposed)
			{
				throw this.closedException ??
					new ObjectDisposedException(Session.ToString(), "Session closed.");
			}

			// Add pending channel before registering cancellation because the delegate may fire immediately
			// if the cancellation is already cancelled, and that will remove the channelId from the pendingChannels.
			var pendingChannel = new PendingChannel(openMessage, completionSource);
			this.pendingChannels.Add(channelId, pendingChannel);
			pendingChannel.CancellationRegistration = cancellation.Register(() =>
			{
				lock (this.lockObject)
				{
					if (this.pendingChannels.Remove(channelId))
					{
						pendingChannel.CancellationRegistration.Dispose();
						completionSource.TrySetCanceled(cancellation);
					}
				}
			});
		}

		await Session.SendMessageAsync(
			openMessage,
			cancellation).ConfigureAwait(false);

		return channelId;
	}

	internal async Task<SshChannel> AcceptChannelAsync(
		string channelType,
		CancellationToken cancellation)
	{
		var completionSource = new TaskCompletionSource<SshChannel>(
			TaskCreationOptions.RunContinuationsAsynchronously);

		CancellationTokenRegistration cancellationRegistration;
		SshChannel? channel = null;
		lock (this.lockObject)
		{
			if (this.disposed)
			{
				throw this.closedException ??
					new ObjectDisposedException(Session.ToString(), "Session closed.");
			}

			channel = this.nonAcceptedChannels.Values
				.FirstOrDefault(c => c.ChannelType == channelType);
			if (channel != null)
			{
				// Found a channel that was already opened but not accepted.
				this.nonAcceptedChannels.Remove(channel.ChannelId);
				return channel;
			}

			// Set up the completion source to wait for a channel of the requested type.
			if (!this.pendingAcceptChannels.TryGetValue(channelType, out var list))
			{
				list = new List<TaskCompletionSource<SshChannel>>();
				this.pendingAcceptChannels.Add(channelType, list);
			}

			list.Add(completionSource);

			// Register cancellation delegate after adding to pendingAcceptChannels because if it is already cancelled,
			// the delegate will fire immediately and that will remove the completion source from pendingAcceptChannels.
			cancellationRegistration = cancellation.Register(() =>
			{
				lock (this.lockObject)
				{
					if (this.pendingAcceptChannels.TryGetValue(channelType, out var list))
					{
						list.Remove(completionSource);
						if (list.Count == 0)
						{
							this.pendingAcceptChannels.Remove(channelType);
						}
					}
				}

				completionSource.TrySetCanceled(cancellation);
			});
		}

		try
		{
			return await completionSource.Task.ConfigureAwait(false);
		}
		finally
		{
			cancellationRegistration.Dispose();
		}
	}

	internal Task HandleMessageAsync(
		ConnectionMessage message, CancellationToken cancellation)
	{
		if (message == null) throw new ArgumentNullException(nameof(message));

		return message switch
		{
			ChannelDataMessage m => HandleMessageAsync(m, cancellation),
			ChannelWindowAdjustMessage m => HandleMessageAsync(m, cancellation),
			ChannelOpenMessage m => HandleMessageAsync(m, cancellation),
			ChannelOpenConfirmationMessage m => HandleMessageAsync(m, cancellation),
			ChannelOpenFailureMessage m => HandleMessageAsync(m, cancellation),
			ChannelRequestMessage m => HandleMessageAsync(m, cancellation),
			ChannelSuccessMessage m => HandleMessageAsync(m, cancellation),
			ChannelFailureMessage m => HandleMessageAsync(m, cancellation),
			ChannelEofMessage m => HandleMessageAsync(m, cancellation),
			ChannelCloseMessage m => HandleMessageAsync(m, cancellation),
			_ => Task.CompletedTask, // Ignore unrecognized connection messages.
		};
	}

	private async Task HandleMessageAsync(
		ChannelOpenMessage message, CancellationToken cancellation)
	{
		var senderChannel = message.SenderChannel;

		if (!Session.CanAcceptRequests)
		{
			Session.Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ChannelOpenFailed,
				"Channel open request blocked because the session is not yet authenticated.");
			await Session.SendMessageAsync(
				new ChannelOpenFailureMessage
				{
					RecipientChannel = senderChannel,
					ReasonCode = SshChannelOpenFailureReason.AdministrativelyProhibited,
					Description = "Authenticate before opening channels.",
				},
				cancellation).ConfigureAwait(false);
			return;
		}

		uint channelId = (uint)Interlocked.Increment(ref this.channelCounter);
		if (channelId > int.MaxValue)
		{
			this.channelCounter = int.MaxValue;

			await Session.SendMessageAsync(
				new ChannelOpenFailureMessage
				{
					RecipientChannel = senderChannel,
					ReasonCode = SshChannelOpenFailureReason.ResourceShortage,
					Description = "Maximum number of channels reached.",
				},
				cancellation).ConfigureAwait(false);
			return;
		}

		if (message.ChannelType == null)
		{
			await Session.SendMessageAsync(
				new ChannelOpenFailureMessage
				{
					RecipientChannel = senderChannel,
					ReasonCode = SshChannelOpenFailureReason.UnknownChannelType,
					Description = "Channel type not specified.",
				},
				cancellation).ConfigureAwait(false);
			return;
		}

		// Save a copy of the message because its buffer will be overwritten by the next receive.
		message = message.ConvertTo<ChannelOpenMessage>(copy: true);

		// The confirmation message may be reassigned if the opening task returns a custom message.
		var confirmationMessage = new ChannelOpenConfirmationMessage();

		var channel = new SshChannel(
			this,
			message.ChannelType!,
			channelId: channelId,
			remoteChannelId: senderChannel,
			remoteMaxWindowSize: message.MaxWindowSize,
			remoteMaxPacketSize: message.MaxPacketSize,
			message,
			confirmationMessage);

		ChannelMessage responseMessage;
		var e = new SshChannelOpeningEventArgs(message, channel, isRemoteRequest: true);
		try
		{
			await Session.OnChannelOpeningAsync(e, cancellation).ConfigureAwait(false);
			if (e.OpeningTask != null)
			{
				responseMessage = await e.OpeningTask.ConfigureAwait(false);
			}
			else if (e.FailureReason != SshChannelOpenFailureReason.None)
			{
				responseMessage = new ChannelOpenFailureMessage
				{
					ReasonCode = e.FailureReason,
					Description = e.FailureDescription,
				};
			}
			else
			{
				responseMessage = confirmationMessage;
			}
		}
		catch (ArgumentException aex)
		{
			responseMessage = new ChannelOpenFailureMessage
			{
				ReasonCode = SshChannelOpenFailureReason.ConnectFailed,
				Description = aex.Message,
			};
		}
		catch (Exception)
		{
			channel.Dispose();
			throw;
		}

		if (responseMessage is ChannelOpenFailureMessage)
		{
			responseMessage.RecipientChannel = senderChannel;
			try
			{
				await Session.SendMessageAsync(responseMessage, cancellation).ConfigureAwait(false);
				return;
			}
			finally
			{
				channel.Dispose();
			}
		}

		// Prevent any changes to the channel max window size after sending the value in the
		// open confirmation message.
		channel.IsMaxWindowSizeLocked = true;

		lock (this.lockObject)
		{
			this.channels.Add(channel.ChannelId, channel);
		}

		if (this.disposed)
		{
			// A lot can happen while opening a channel (as when channels route to other services).
			// Ensure the channel gets cleaned up if this object was already disposed.
			channel.Dispose();
			return;
		}

		confirmationMessage = (ChannelOpenConfirmationMessage)responseMessage;
		confirmationMessage.RecipientChannel = channel.RemoteChannelId;
		confirmationMessage.SenderChannel = channel.ChannelId;
		confirmationMessage.MaxWindowSize = channel.MaxWindowSize;
		confirmationMessage.MaxPacketSize = channel.MaxPacketSize;
		confirmationMessage.Rewrite();

		channel.OpenConfirmationMessage = confirmationMessage;
		await Session.SendMessageAsync(confirmationMessage, cancellation).ConfigureAwait(false);

		lock (this.lockObject)
		{
			// Check if there are any accept operations waiting on this channel type.
			bool accepted = false;
			if (this.pendingAcceptChannels.TryGetValue(channel.ChannelType, out var list))
			{
				while (list.Count > 0)
				{
					var acceptCompletionSource = list[0];
					list.RemoveAt(0);

					if (acceptCompletionSource.TrySetResult(channel))
					{
						accepted = true;
						break;
					}
				}

				if (list.Count == 0)
				{
					this.pendingAcceptChannels.Remove(channel.ChannelType);
				}
			}

			if (!accepted)
			{
				this.nonAcceptedChannels.Add(channel.ChannelId, channel);
			}
		}

		OnChannelOpenCompleted(channel.ChannelId, channel);
		channel.EnableSending();
	}

	private async Task HandleMessageAsync(
		ChannelRequestMessage message, CancellationToken cancellation)
	{
		var channel = TryGetChannelForMessage(message);
		if (channel != null)
		{
			await channel.HandleRequestAsync(message, cancellation).ConfigureAwait(false);
		}
	}

	private Task HandleMessageAsync(ChannelSuccessMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		var channel = TryGetChannelForMessage(message);
		channel?.HandleResponse(true);
		return Task.CompletedTask;
	}

	private Task HandleMessageAsync(ChannelFailureMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		var channel = TryGetChannelForMessage(message);
		channel?.HandleResponse(false);
		return Task.CompletedTask;
	}

	private async Task HandleMessageAsync(
		ChannelDataMessage message, CancellationToken cancellation)
	{
		var channel = TryGetChannelForMessage(message);
		if (channel != null)
		{
			await channel.HandleDataReceivedAsync(message.Data, cancellation).ConfigureAwait(false);
		}
	}

	private Task HandleMessageAsync(
		ChannelWindowAdjustMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		var channel = TryGetChannelForMessage(message);
		channel?.AdjustRemoteWindow(message.BytesToAdd);
		return Task.CompletedTask;
	}

	private Task HandleMessageAsync(ChannelEofMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		var channel = TryFindChannelById(message.RecipientChannel);
		channel?.OnEof();
		return Task.CompletedTask;
	}

	private Task HandleMessageAsync(ChannelCloseMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		var channel = TryFindChannelById(message.RecipientChannel);
		channel?.Close();
		return Task.CompletedTask;
	}

	private async Task HandleMessageAsync(
		ChannelOpenConfirmationMessage message, CancellationToken cancellation)
	{
		SshChannel channel;
		cancellation.ThrowIfCancellationRequested();

		TaskCompletionSource<SshChannel>? completionSource = null;
		ChannelOpenMessage openMessage;
		lock (this.lockObject)
		{
			if (this.pendingChannels.TryGetValue(
				message.RecipientChannel, out var pendingChannel))
			{
				openMessage = pendingChannel.OpenMessage;
				completionSource = pendingChannel.CompletionSource;
				pendingChannel.CancellationRegistration.Dispose();
				this.pendingChannels.Remove(message.RecipientChannel);
			}
			else if (this.channels.ContainsKey(message.RecipientChannel))
			{
				throw new SshConnectionException(
					"Duplicate channel confirmation.", SshDisconnectReason.ProtocolError);
			}
			else
			{
				throw new SshConnectionException(
					"Channel confirmation was not requested.", SshDisconnectReason.ProtocolError);
			}

			// Save a copy of the message because its buffer will be overwritten by the next receive.
			message = message.ConvertTo<ChannelOpenConfirmationMessage>(copy: true);

			channel = new SshChannel(
				this,
				openMessage.ChannelType ?? SshChannel.SessionChannelType,
				channelId: message.RecipientChannel,
				remoteChannelId: message.SenderChannel,
				remoteMaxWindowSize: message.MaxWindowSize,
				remoteMaxPacketSize: message.MaxPacketSize,
				openMessage,
				message);

			// Set the channel max window size property to match the value sent in the open message,
			// and lock it to prevent any further changes.
			channel.MaxWindowSize = openMessage.MaxWindowSize;
			channel.IsMaxWindowSizeLocked = true;

			this.channels.Add(channel.ChannelId, channel);
		}

		var args = new SshChannelOpeningEventArgs(openMessage, channel, isRemoteRequest: false);
		await Session.OnChannelOpeningAsync(args, cancellation).ConfigureAwait(false);

		if (completionSource != null)
		{
			if (args.FailureReason == SshChannelOpenFailureReason.None)
			{
				completionSource.TrySetResult(channel);
			}
			else
			{
				completionSource.TrySetException(new SshChannelException(
					args.FailureDescription ?? "Channel open failure: " + args.FailureReason,
					args.FailureReason));
				return;
			}
		}
		else if (args.FailureReason == SshChannelOpenFailureReason.None)
		{
			OnChannelOpenCompleted(channel.ChannelId, channel);
		}

		channel.EnableSending();
	}

	private Task HandleMessageAsync(
		ChannelOpenFailureMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();

		TaskCompletionSource<SshChannel>? completionSource = null;
		lock (this.lockObject)
		{
			if (this.pendingChannels.TryGetValue(
				message.RecipientChannel, out var pendingChannel))
			{
				completionSource = pendingChannel.CompletionSource;
				pendingChannel.CancellationRegistration.Dispose();
				this.pendingChannels.Remove(message.RecipientChannel);
			}
		}

		if (completionSource != null)
		{
			completionSource.TrySetException(new SshChannelException(
				message.Description ?? "Channel open failure: " + message.ReasonCode,
				message.ReasonCode));
		}
		else
		{
			OnChannelOpenCompleted(message.RecipientChannel, null);
		}

		return Task.CompletedTask;
	}

	private void OnChannelOpenCompleted(uint channelId, SshChannel? channel)
	{
		if (channel != null)
		{
			Session.Trace.TraceEvent(
				TraceEventType.Verbose,
				SshTraceEventIds.ChannelOpened,
				$"{Session} {nameof(OnChannelOpenCompleted)}({channel})");
		}
		else
		{
			Session.Trace.TraceEvent(
				TraceEventType.Verbose,
				SshTraceEventIds.ChannelOpenFailed,
				$"{Session} {nameof(OnChannelOpenCompleted)}({channelId} failed)");
		}
	}

	/// <summary>
	/// Gets the channel object based on the message <see cref="ChannelMessage.RecipientChannel" />
	/// property. Logs a warning if the channel was not found.
	/// </summary>
	private SshChannel? TryGetChannelForMessage(ChannelMessage channelMessage)
	{
		var channel = TryFindChannelById(channelMessage.RecipientChannel);
		if (channel == null)
		{
			string messageString = (channelMessage is ChannelDataMessage) ?
				nameof(ChannelDataMessage) : channelMessage.ToString();
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ChannelRequestFailed,
				$"{Session}: Invalid channel ID {channelMessage.RecipientChannel} in {messageString}");
		}

		return channel;
	}

	private SshChannel? TryFindChannelById(uint id)
	{
		lock (this.lockObject)
		{
			if (!this.channels.TryGetValue(id, out SshChannel? channel))
			{
				channel = null;
			}

			return channel;
		}
	}

	internal void RemoveChannel(SshChannel channel)
	{
		lock (this.lockObject)
		{
			this.channels.Remove(channel.ChannelId);
			this.nonAcceptedChannels.Remove(channel.ChannelId);
		}
	}
}
