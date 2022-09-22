// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;

namespace Microsoft.DevTunnels.Ssh.Events;

[DebuggerStepThrough]
public class SshChannelClosedEventArgs : EventArgs
{
	internal static new SshChannelClosedEventArgs Empty { get; } = new SshChannelClosedEventArgs();

	public SshChannelClosedEventArgs()
	{
	}

	public SshChannelClosedEventArgs(uint exitStatus)
	{
		ExitStatus = exitStatus;
	}

	public SshChannelClosedEventArgs(string exitSignal, string? errorMessage = null)
	{
		ExitSignal = exitSignal;
		ErrorMessage = errorMessage;
	}

	public SshChannelClosedEventArgs(Exception ex)
	{
		Exception = ex;
	}

	/// <summary>
	/// Gets the exit status of the command that the channel was connected to, if supplied.
	/// </summary>
	public uint? ExitStatus { get; }

	/// <summary>
	/// Gets the abnormal-exit signal of the command that the channel was connected to, if supplied.
	/// </summary>
	public string? ExitSignal { get; }

	/// <summary>
	/// Gets the optional error message associated with the exit signal.
	/// </summary>
	public string? ErrorMessage { get; }

	/// <summary>
	/// Gets the exception, if any, that caused the channel to close unexpectedly.
	/// </summary>
	/// <remarks>
	/// If the channel closed due to a connectivity issue, this will be a
	/// <see cref="SshConnectionException" />.
	/// </remarks>
	public Exception? Exception { get; }
}
