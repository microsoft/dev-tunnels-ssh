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
			 TaskCompletionSource<SshChannel> completionSource,
			 CancellationTokenRegistration? cancellationRegistration)
		{
			OpenMessage = openMessage;
			CompletionSource = completionSource;
			CancellationRegistration = cancellationRegistration;
		}

		public ChannelOpenMessage OpenMessage { get; }
		public TaskCompletionSource<SshChannel> CompletionSource { get; }
		public CancellationTokenRegistration? CancellationRegistration { get; }
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

		CancellationTokenRegistration? cancellationRegistration = null;
		if (cancellation.CanBeCanceled)
		{
			cancellationRegistration = cancellation.Register(() =>
			{
				lock (this.lockObject)
				{
					if (this.pendingChannels.Remove(channelId))
					{
						completionSource.TrySetCanceled();
					}
				}
			});
		}

		lock (this.lockObject)
		{
			if (this.disposed)
			{
				throw this.closedException ??
					new ObjectDisposedException(Session.ToString(), "Session closed.");
			}

			this.pendingChannels.Add(
				channelId,
				new PendingChannel(openMessage, completionSource, cancellationRegistration));
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

		CancellationTokenRegistration? cancellationRegistration = null;
		if (cancellation.CanBeCanceled)
		{
			cancellationRegistration = cancellation.Register(() =>
			{
				lock (this.lockObject)
				{
					if (this.pendingAcceptChannels.TryGetValue(channelType, out var list))
					{
						list.Remove(completionSource);
					}
				}

				completionSource.TrySetCanceled(cancellation);
			});
		}

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
			}
			else
			{
				// Set up the completion source to wait for a channel of the requested type.
				if (!this.pendingAcceptChannels.TryGetValue(channelType, out var list))
				{
					list = new List<TaskCompletionSource<SshChannel>>();
					this.pendingAcceptChannels.Add(channelType, list);
				}

				list.Add(completionSource);
			}
		}

		try
		{
			return channel ?? await completionSource.Task.ConfigureAwait(false);
		}
		finally
		{
			cancellationRegistration?.Dispose();
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

		var channel = new SshChannel(
			this,
			message.ChannelType,
			channelId: channelId,
			remoteChannelId: senderChannel,
			remoteMaxWindowSize: message.MaxWindowSize,
			remoteMaxPacketSize: message.MaxPacketSize);

		var e = new SshChannelOpeningEventArgs(message, channel, isRemoteRequest: true);
		try
		{
			await Session.OnChannelOpeningAsync(e, cancellation).ConfigureAwait(false);
		}
		catch (ArgumentException aex)
		{
			e.FailureReason = SshChannelOpenFailureReason.ConnectFailed;
			e.FailureDescription = aex.Message;
		}
		catch (Exception)
		{
			channel.Dispose();
			throw;
		}

		if (e.FailureReason != SshChannelOpenFailureReason.None)
		{
			try
			{
				await Session.SendMessageAsync(
					new ChannelOpenFailureMessage
					{
						RecipientChannel = senderChannel,
						ReasonCode = e.FailureReason,
						Description = e.FailureDescription,
					},
					cancellation).ConfigureAwait(false);
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

		await Session.SendMessageAsync(
			new ChannelOpenConfirmationMessage
			{
				RecipientChannel = channel.RemoteChannelId,
				SenderChannel = channel.ChannelId,
				MaxWindowSize = channel.MaxWindowSize,
				MaxPacketSize = channel.MaxPacketSize,
			},
			cancellation).ConfigureAwait(false);

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
		var channel = TryFindChannelById(message.RecipientChannel);
		if (channel == null)
		{
			Session.Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ChannelRequestFailed,
				$"Invalid channel ID in {message}");
			return;
		}

		await channel.HandleRequestAsync(message, cancellation).ConfigureAwait(false);
	}

	private Task HandleMessageAsync(ChannelSuccessMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		var channel = TryFindChannelById(message.RecipientChannel);
		if (channel == null)
		{
			Session.Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ChannelRequestFailed,
				$"Invalid channel ID in {message}");
			return Task.CompletedTask;
		}

		channel.HandleResponse(true);
		return Task.CompletedTask;
	}

	private Task HandleMessageAsync(ChannelFailureMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		var channel = TryFindChannelById(message.RecipientChannel);
		if (channel == null)
		{
			Session.Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ChannelRequestFailed,
				$"Invalid channel ID in {message}");
			return Task.CompletedTask;
		}

		channel.HandleResponse(false);
		return Task.CompletedTask;
	}

	private async Task HandleMessageAsync(
		ChannelDataMessage message, CancellationToken cancellation)
	{
		var channel = TryFindChannelById(message.RecipientChannel);
		if (channel == null)
		{
			return;
		}

		await channel.HandleDataReceivedAsync(message.Data, cancellation).ConfigureAwait(false);
	}

	private Task HandleMessageAsync(
		ChannelWindowAdjustMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		var channel = TryFindChannelById(message.RecipientChannel);
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
				pendingChannel.CancellationRegistration?.Dispose();
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

			channel = new SshChannel(
				this,
				openMessage.ChannelType ?? SshChannel.SessionChannelType,
				channelId: message.RecipientChannel,
				remoteChannelId: message.SenderChannel,
				remoteMaxWindowSize: message.MaxWindowSize,
				remoteMaxPacketSize: message.MaxPacketSize);

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
				completionSource.SetResult(channel);
			}
			else
			{
				completionSource.SetException(new SshChannelException(
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
				pendingChannel.CancellationRegistration?.Dispose();
				this.pendingChannels.Remove(message.RecipientChannel);
			}
		}

		if (completionSource != null)
		{
			completionSource.SetException(new SshChannelException(
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
