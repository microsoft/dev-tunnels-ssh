// Copyright (c) Microsoft. All rights reserved.

using System;

namespace Microsoft.DevTunnels.Ssh;

public class SshConnectionException : Exception
{
	public SshConnectionException()
	{
	}

	public SshConnectionException(string message) : base(message)
	{
	}

	public SshConnectionException(string message, Exception? innerException)
		: base(message, innerException)
	{
	}

	public SshConnectionException(string message, SshDisconnectReason disconnectReason)
		: base(FormatMessage(message, disconnectReason))
	{
		DisconnectReason = disconnectReason;
	}

	public SshConnectionException(
		string message, SshDisconnectReason disconnectReason, Exception? innerException)
		: base(FormatMessage(message, disconnectReason), innerException)
	{
		DisconnectReason = disconnectReason;
	}

	public SshDisconnectReason DisconnectReason { get; private set; }

	private static string FormatMessage(string message, SshDisconnectReason reason)
		=> reason == default ? message : $"{message}\nReason: {reason}";
}
