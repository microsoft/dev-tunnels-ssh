// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh;

public class SshChannelException : Exception
{
	public SshChannelException()
	{
	}

	public SshChannelException(string message) : base(message)
	{
	}

	public SshChannelException(string message, Exception innerException) : base(message, innerException)
	{
	}

	public SshChannelException(
		string message,
		SshChannelOpenFailureReason openFailureReason)
		: base(FormatMessage(message, openFailureReason))
	{
		OpenFailureReason = openFailureReason;
	}

	public SshChannelOpenFailureReason OpenFailureReason { get; private set; }

	private static string FormatMessage(string message, SshChannelOpenFailureReason reason)
		=> reason == default ? message : $"{message}\nReason: {reason}";
}
