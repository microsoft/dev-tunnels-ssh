// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Default implementation of a TCP listener factory.
/// </summary>
internal class DefaultTcpListenerFactory : ITcpListenerFactory
{
	/// <inheritdoc />
	public Task<TcpListener> CreateTcpListenerAsync(
		IPAddress localIPAddress,
		int localPort,
		TraceSource trace,
		CancellationToken cancellation)
	{
		if (localIPAddress == null) throw new ArgumentNullException(nameof(localIPAddress));

		var listener = new TcpListener(localIPAddress, localPort);
		listener.Start();
		return Task.FromResult(listener);
	}
}
