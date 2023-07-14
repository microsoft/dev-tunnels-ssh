// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Extension methods for piping between SSH session pairs and channel pairs.
/// </summary>
public static class PipeExtensions
{
	/// <summary>
	/// Pipes one SSH session into another, relaying all data between them.
	/// </summary>
	/// <param name="session">First session to be connected via the pipe.</param>
	/// <param name="toSession">Second session to be connected via the pipe.</param>
	/// <returns>A task that completes when the sessions are closed.</returns>
	/// <remarks>
	/// Any new channels opened from the remote side of either session will be piped into a
	/// new channel in the other session. Any channels opened before connecting the session pipe,
	/// or any channels opened from the local side, will not be piped.
	///
	/// When either of the two sessions is closed, the other session will be closed.
	/// </remarks>
	public static async Task PipeAsync(this SshSession session, SshSession toSession)
	{
		if (session == null) throw new ArgumentNullException(nameof(session));
		if (toSession == null) throw new ArgumentNullException(nameof(toSession));

		var endCompletion = new TaskCompletionSource<Task>();

		session.Request += (sender, e) =>
		{
			e.ResponseTask = ForwardSessionRequestAsync(e, toSession, e.Cancellation);
		};
		toSession.Request += (sender, e) =>
		{
			e.ResponseTask = ForwardSessionRequestAsync(e, session, e.Cancellation);
		};

		session.ChannelOpening += (sender, e) =>
		{
			if (e.IsRemoteRequest)
			{
				e.OpeningTask = ForwardChannelAsync(e, toSession, e.Cancellation);
			}
		};
		toSession.ChannelOpening += (sender, e) =>
		{
			if (e.IsRemoteRequest)
			{
				e.OpeningTask = ForwardChannelAsync(e, session, e.Cancellation);
			}
		};

		session.Closed += (sender, e) =>
		{
			endCompletion.TrySetResult(ForwardSessionCloseAsync(toSession, e));
		};
		toSession.Closed += (sender, e) =>
		{
			endCompletion.TrySetResult(ForwardSessionCloseAsync(session, e));
		};

		var endTask = await endCompletion.Task.ConfigureAwait(false);
		await endTask.ConfigureAwait(false);
	}

	/// <summary>
	/// Pipes one SSH channel into another, relaying all data between them.
	/// </summary>
	/// <param name="channel">First channel to be connected via the pipe.</param>
	/// <param name="toChannel">Second channel to be connected via the pipe.</param>
	/// <returns>A task that completes when the channels are closed.</returns>
	/// <remarks>
	/// When either of the two channels is closed, the other channel will be closed.
	/// </remarks>
	public static async Task PipeAsync(this SshChannel channel, SshChannel toChannel)
	{
		if (channel == null) throw new ArgumentNullException(nameof(channel));
		if (toChannel == null) throw new ArgumentNullException(nameof(toChannel));

		var endCompletion = new TaskCompletionSource<Task>();
		bool closed = false;

		channel.Request += (sender, e) =>
		{
			e.ResponseTask = ForwardChannelRequestAsync(e, toChannel, e.Cancellation);
		};
		toChannel.Request += (sender, e) =>
		{
			e.ResponseTask = ForwardChannelRequestAsync(e, channel, e.Cancellation);
		};

		channel.DataReceived += (sender, data) =>
		{
			_ = ForwardDataAsync(channel, toChannel, data);
		};
		toChannel.DataReceived += (sender, data) =>
		{
			_ = ForwardDataAsync(toChannel, channel, data);
		};

		channel.Closed += (sender, e) =>
		{
			if (!closed)
			{
				closed = true;
				endCompletion.TrySetResult(ForwardChannelCloseAsync(channel, toChannel, e));
			}
		};
		toChannel.Closed += (sender, e) =>
		{
			if (!closed)
			{
				closed = true;
				endCompletion.TrySetResult(ForwardChannelCloseAsync(toChannel, channel, e));
			}
		};

		var endTask = await endCompletion.Task.ConfigureAwait(false);
		await endTask.ConfigureAwait(false);
	}

	private static async Task<SshMessage> ForwardSessionRequestAsync(
		SshRequestEventArgs<SessionRequestMessage> e,
		SshSession toSession,
		CancellationToken cancellation)
	{
		var response = await toSession.RequestAsync
			<SessionRequestSuccessMessage, SessionRequestFailureMessage>(e.Request, cancellation)
			.ConfigureAwait(false);
		return (SshMessage?)response.Success ?? response.Failure!;
	}

	private static async Task<ChannelMessage> ForwardChannelAsync(
		SshChannelOpeningEventArgs e,
		SshSession toSession,
		CancellationToken cancellation)
	{
		SshChannel? toChannel = null;

		try
		{
			toChannel = await toSession.OpenChannelAsync(e.Request, null, cancellation)
				.ConfigureAwait(false);
			_ = PipeAsync(e.Channel, toChannel);
			return new ChannelOpenConfirmationMessage();
		}
		catch (SshChannelException cex)
		{
			return new ChannelOpenFailureMessage
			{
				ReasonCode = cex.OpenFailureReason,
				Description = cex.Message,
			};
		}
	}

	private static async Task<SshMessage> ForwardChannelRequestAsync(
		SshRequestEventArgs<ChannelRequestMessage> e,
		SshChannel toChannel,
		CancellationToken cancellation)
	{
		e.Request.RecipientChannel = toChannel.RemoteChannelId;
		bool result = await toChannel.RequestAsync(e.Request, cancellation)
			.ConfigureAwait(false);
		return result ? new ChannelSuccessMessage() : new ChannelFailureMessage();
	}

	private static Task ForwardSessionCloseAsync(SshSession session, SshSessionClosedEventArgs e)
	{
		if (e.Exception != null)
		{
			return session.CloseAsync(e.Reason, e.Exception);
		}
		else
		{
			return session.CloseAsync(e.Reason, e.Message);
		}
	}

	private static async Task ForwardDataAsync(
		SshChannel channel,
		SshChannel toChannel,
		Buffer data)
	{
		await toChannel.SendAsync(data, CancellationToken.None).ConfigureAwait(false);
		channel.AdjustWindow((uint)data.Count);
	}

	private static Task ForwardChannelCloseAsync(
		SshChannel fromChannel,
		SshChannel toChannel,
		SshChannelClosedEventArgs e)
	{
		var message = "Piping channel closure.\n" +
			$"  Source: {fromChannel.Session} {fromChannel}\n" +
			$"  Destination: {toChannel.Session} {toChannel}";
		toChannel.Trace.TraceEvent(TraceEventType.Verbose, SshTraceEventIds.ChannelClosed, message);

		if (e.ExitSignal != null)
		{
			return toChannel.CloseAsync(e.ExitSignal, e.ErrorMessage);
		}
		else if (e.ExitStatus.HasValue)
		{
			return toChannel.CloseAsync(e.ExitStatus.Value);
		}
		else
		{
			// The fromChannel may have been closed normally, or due to an exception. An exception
			// cannot be forwarded to toChannel because there is no SSH protocol for doing that.
			// So toChannel is just closed normally regardless.
			return toChannel.CloseAsync();
		}
	}
}
