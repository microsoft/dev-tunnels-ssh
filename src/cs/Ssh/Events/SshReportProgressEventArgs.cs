// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;

namespace Microsoft.DevTunnels.Ssh.Events;

/// <summary>
/// Event raised to report connection progress.
/// </summary>
[DebuggerStepThrough]
public class SshReportProgressEventArgs : EventArgs
{
	public SshReportProgressEventArgs(Progress progress, int? sessionNumber = null)
	{
		Progress = progress.ToString();
		SessionNumber = sessionNumber;
	}

	/// <summary>
	/// Specifies the progress event that is being reported. See <see cref="Progress"/>
	/// for a description of the different progress events that can be reported.
	/// </summary>
	public string Progress { get; }

	/// <summary>
	/// The session number associated with an SSH session progress event.
	/// </summary>
	public int? SessionNumber { get; }
}
