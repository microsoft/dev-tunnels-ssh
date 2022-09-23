// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_GLOBAL_REQUEST", MessageNumber)]
public class SessionRequestMessage : SshMessage
{
	internal const byte MessageNumber = 80;

	public string? RequestType { get; set; }

	public bool WantReply { get; set; }

	public override byte MessageType => MessageNumber;

	protected override void OnRead(ref SshDataReader reader)
	{
		RequestType = reader.ReadString(Encoding.ASCII);
		WantReply = reader.ReadBoolean();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (RequestType == null)
		{
			throw new InvalidOperationException("Request type not set.");
		}

		writer.Write(RequestType, Encoding.ASCII);
		writer.Write(WantReply);
	}

	public override string ToString()
	{
		return base.ToString() + $"(RequestType: {RequestType})";
	}
}
