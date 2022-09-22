// Copyright (c) Microsoft. All rights reserved.

using System.Diagnostics;

namespace Microsoft.DevTunnels.Ssh.Tcp.Events;

[DebuggerDisplay("{ToString(),nq}")]
public class ForwardedPortChannelEventArgs : ForwardedPortEventArgs
{
	public ForwardedPortChannelEventArgs(ForwardedPort port, SshChannel channel)
		: base(port)
	{
		Channel = channel;
	}

	public SshChannel Channel { get; }

	public override string ToString()
	{
		return $"{Port} {Channel}";
	}
}
