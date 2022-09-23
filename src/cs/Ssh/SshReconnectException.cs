// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh;

public class SshReconnectException : Exception
{
	public SshReconnectException()
	{
	}

	public SshReconnectException(string message) : base(message)
	{
	}

	public SshReconnectException(string message, Exception? innerException)
		: base(message, innerException)
	{
	}

	public SshReconnectException(string message, SshReconnectFailureReason failureReason)
		: base(FormatMessage(message, failureReason))
	{
		FailureReason = failureReason;
	}

	public SshReconnectException(
		string message, SshReconnectFailureReason failureReason, Exception? innerException)
		: base(FormatMessage(message, failureReason), innerException)
	{
		FailureReason = failureReason;
	}

	public SshReconnectFailureReason FailureReason { get; private set; }

	private static string FormatMessage(string message, SshReconnectFailureReason reason)
		=> reason == default ? message : $"{message}\nReason: {reason}";
}
