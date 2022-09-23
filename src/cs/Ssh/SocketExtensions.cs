// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Net.Sockets;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Extensions for running SSH over TCP sockets.
/// </summary>
/// <remarks>
/// This class is not in the `Ssh.Tcp` assembly because some applications
/// use this library with TCP sockets without referencing that other assembly.
/// </remarks>
public static class SocketExtensions
{
	/// <summary>
	/// Sets TCP socket options for optimal performance. Not required, because
	/// the library can work with any kind of stream, not only a TCP socket.
	/// </summary>
	public static void ConfigureSocketOptionsForSsh(this Socket socket)
	{
		if (socket == null) throw new ArgumentNullException(nameof(socket));

		const int SocketBufferSize = (int)(2 * SshChannel.DefaultMaxPacketSize);
		socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
		socket.SetSocketOption(
			SocketOptionLevel.Socket, SocketOptionName.SendBuffer, SocketBufferSize);
		socket.SetSocketOption(
			SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, SocketBufferSize);
	}
}
