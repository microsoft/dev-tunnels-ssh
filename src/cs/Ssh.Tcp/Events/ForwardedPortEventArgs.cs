// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;

namespace Microsoft.DevTunnels.Ssh.Tcp.Events;

[DebuggerDisplay("{ToString(),nq}")]
public class ForwardedPortEventArgs : EventArgs
{
	public ForwardedPortEventArgs(ForwardedPort port)
	{
		Port = port;
	}

	public ForwardedPort Port { get; }

	public override string ToString()
	{
		return Port.ToString();
	}
}
