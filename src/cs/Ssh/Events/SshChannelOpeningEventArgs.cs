// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Events;

/// <summary>
/// Event raised by an `SshSession` when a channel is opening.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
[DebuggerStepThrough]
public class SshChannelOpeningEventArgs
{
	public SshChannelOpeningEventArgs(
		ChannelOpenMessage request,
		SshChannel channel,
		bool isRemoteRequest,
		CancellationToken cancellation = default)
	{
		Request = request;
		Channel = channel ?? throw new ArgumentNullException(nameof(channel));
		IsRemoteRequest = isRemoteRequest;
		Cancellation = cancellation;
	}

	/// <summary>
	/// Gets the message that requested the channel.
	/// </summary>
	public ChannelOpenMessage Request { get; }

	/// <summary>
	/// The channel that is opening.
	/// </summary>
	public SshChannel Channel { get; }

	/// <summary>
	/// True if the channel was requested by the remote side; false if by the local side.
	/// </summary>
	public bool IsRemoteRequest { get; }

	/// <summary>
	/// Gets a cancellation token that could be used to cancel async handling of channel opening.
	/// </summary>
	public CancellationToken Cancellation { get; internal set; }

	/// <summary>
	/// Gets or sets an optional task that blocks opening the channel until the task is completed.
	/// An event-handler may assign a task to this property to handle the channel opening
	/// as an asynchronous operation. The task result must be an instance of
	/// <see cref="ChannelOpenConfirmationMessage" />, <see cref="ChannelOpenFailureMessage" />,
	/// or a subclass of one of those.
	/// </summary>
	public Task<ChannelMessage>? OpeningTask { get; set; }

	/// <summary>
	/// Specifies a reason that the channel could not be opened.
	/// </summary>
	/// <remarks>
	/// The handler of this event can optionally block the channel by setting
	/// a failure reason. If the event is not handled or the reason remains
	/// `None` then the channel is allowed to open.
	/// </remarks>
	public SshChannelOpenFailureReason FailureReason { get; set; }

	/// <summary>
	/// Optional message to go along with a failure reason.
	/// </summary>
	public string? FailureDescription { get; set; }

	public override string ToString()
	{
		return $"{Channel} {FailureReason}";
	}
}
