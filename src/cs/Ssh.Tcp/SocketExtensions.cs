// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Net.Sockets;

namespace Microsoft.DevTunnels.Ssh.Tcp;

internal static class SocketExtensions
{
	/// <summary>
	/// Closes the socket in a way that simulates an aborted connection, causing the other end
	/// to receive a "connection reset" error.
	/// </summary>
	public static void Abort(this Socket socket)
	{
		if (socket == null) throw new ArgumentNullException(nameof(socket));

		socket.Close(timeout: 0);
	}
}
