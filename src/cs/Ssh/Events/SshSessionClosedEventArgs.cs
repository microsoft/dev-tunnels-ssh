// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;

namespace Microsoft.DevTunnels.Ssh.Events;

[DebuggerStepThrough]
public class SshSessionClosedEventArgs : EventArgs
{
	public SshSessionClosedEventArgs(SshDisconnectReason reason, string message, Exception? ex)
	{
		Reason = reason;
		Message = message;
		Exception = ex;
	}

	public SshDisconnectReason Reason { get; }

	public string Message { get; }

	public Exception? Exception { get; }
}
