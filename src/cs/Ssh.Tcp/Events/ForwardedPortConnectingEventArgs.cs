// Copyright (c) Microsoft. All rights reserved.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Tcp.Events;

/// <summary>
/// Event raised when an incoming or outgoing connection to a forwarded port is
/// about to be established.
/// </summary>
public class ForwardedPortConnectingEventArgs : EventArgs
{
	/// <summary>
	/// Creates a new instance of <see cref="ForwardedPortConnectingEventArgs"/> class.
	/// </summary>
	public ForwardedPortConnectingEventArgs(
		int port,
		bool isIncoming,
		SshStream stream,
		CancellationToken cancellation)
	{
		Port = port;
		IsIncoming = isIncoming;
		Stream = stream;
		Cancellation = cancellation;
	}

	/// <summary>
	/// Gets the remote forwarded port number.
	/// </summary>
	/// <remarks>
	/// This may be different from the local port number, if the local TCP listener chose a
	/// different port.
	/// </remarks>
	public int Port { get; }

	/// <summary>
	/// Gets or sets a value that indicates whether this connection is incoming (remote connection
	/// to a local port) or outgoing (local connection to a remote port).
	/// </summary>
	public bool IsIncoming { get; set; }

	/// <summary>
	/// Gets a stream for the forwarded connection.
	/// </summary>
	public SshStream Stream { get; }

	/// <summary>
	/// Gets or sets an optional task that transforms the stream.
	/// </summary>
	/// <remarks>
	/// An event-handler may apply a transformation to the stream before the stream is connected
	/// to the local port or returned to the application. If the task result is null, the
	/// connection is rejected.
	/// </remarks>
	public Task<Stream?>? TransformTask { get; set; }

	/// <summary>
	/// Gets a cancellation token that is cancelled when the session is closed.
	/// </summary>
	public CancellationToken Cancellation { get; }
}
