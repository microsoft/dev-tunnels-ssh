// Copyright (c) Microsoft. All rights reserved.

using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_DEBUG", MessageNumber)]
public class DebugMessage : SshMessage
{
	internal const byte MessageNumber = 4;

	public override byte MessageType => MessageNumber;

	public bool AlwaysDisplay { get; set; }

	public string? Message { get; set; }

	public string? Language { get; set; }

	public DebugMessage()
	{
	}

	public DebugMessage(string message)
	{
		Message = message;
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		AlwaysDisplay = reader.ReadBoolean();
		Message = reader.ReadString(Encoding.UTF8);
		Language = reader.ReadString(Encoding.ASCII);
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.Write(AlwaysDisplay);
		writer.Write(Message ?? string.Empty, Encoding.UTF8);
		writer.Write(Language ?? string.Empty, Encoding.ASCII);
	}

	public override string ToString()
	{
		return $"{base.ToString()}: {Message}";
	}
}
