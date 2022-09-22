// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Receives SSH channels forwarded from a remote port and exposes them as streams.
/// </summary>
public class RemotePortStreamer : RemotePortConnector
{
	internal RemotePortStreamer(
		SshSession session,
		IPAddress remoteIPAddress,
		int remotePort)
		: base(session, remoteIPAddress, remotePort)
	{
	}

	/// <summary>
	/// Event raised when a new connection stream is forwarded from the remote port.
	/// </summary>
	public event EventHandler<SshStream>? StreamOpened;

	internal override Task OnChannelOpeningAsync(
		SshChannelOpeningEventArgs request,
		CancellationToken cancellation)
	{
		// The channel stream should be owned by the event-handler;
		// otherwise the channel is owned and disposed by the session.
#pragma warning disable CA2000 // Dispose objects before losing scope
		var stream = new SshStream(request.Channel);
#pragma warning restore CA2000 // Dispose objects before losing scope

		StreamOpened?.Invoke(this, stream);
		return Task.CompletedTask;
	}
}
