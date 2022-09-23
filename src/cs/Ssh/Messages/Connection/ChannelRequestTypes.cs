// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Messages;

public static class ChannelRequestTypes
{
	public const string Command = "exec";
	public const string Shell = "shell";
	public const string Terminal = "pty-req";
	public const string Signal = "signal";
	public const string ExitSignal = "exit-signal";
	public const string ExitStatus = "exit-status";
}
