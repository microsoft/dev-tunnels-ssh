// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_DISCONNECT", MessageNumber)]
public class DisconnectMessage : SshMessage
{
	internal const byte MessageNumber = 1;

	public DisconnectMessage()
	{
	}

	public DisconnectMessage(
		SshDisconnectReason reasonCode, string description, string? language = null)
	{
		if (description == null) throw new ArgumentNullException(nameof(description));

		ReasonCode = reasonCode;
		Description = description;
		Language = language;
	}

	public override byte MessageType => MessageNumber;

	public SshDisconnectReason ReasonCode { get; private set; }
	public string? Description { get; private set; }
	public string? Language { get; private set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		ReasonCode = (SshDisconnectReason)reader.ReadUInt32();
		Description = reader.ReadString(Encoding.UTF8);
		if (reader.Available >= 4)
		{
			Language = reader.ReadString(Encoding.ASCII);
		}
		else
		{
			Language = null;
		}
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.Write((uint)ReasonCode);
		writer.Write(Description ?? string.Empty, Encoding.UTF8);
		if (Language != null)
		{
			writer.Write(Language, Encoding.ASCII);
		}
	}
}
