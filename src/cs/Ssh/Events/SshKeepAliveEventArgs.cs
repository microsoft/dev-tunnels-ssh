// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;

namespace Microsoft.DevTunnels.Ssh.Events;

/// <summary>
/// Event raised when a keep-alive message respose is not received.
/// </summary>
[DebuggerStepThrough]
public class SshKeepAliveEventArgs : EventArgs
{
	public SshKeepAliveEventArgs(int count)
	{
		Count = count;
	}

	/// <summary>
	/// The number of keep-alive messages that have been sent without a response.
	/// </summary>
	public int Count { get; }
}
