// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

public class CommandRequestMessage : ChannelRequestMessage
{
	public string? Command { get; set; }

	public CommandRequestMessage()
	{
		RequestType = ChannelRequestTypes.Command;
	}

	public CommandRequestMessage(string command) : this()
	{
		Command = command;
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		Command = reader.ReadString(Encoding.UTF8);
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (Command == null)
		{
			throw new InvalidOperationException("Command not set.");
		}

		base.OnWrite(ref writer);

		writer.Write(Command, Encoding.UTF8);
	}
}
