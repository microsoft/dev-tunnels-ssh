// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_USERAUTH_INFO_RESPONSE", MessageNumber)]
public class AuthenticationInfoResponseMessage : AuthenticationMessage
{
	internal const byte MessageNumber = 61;

	public IList<string> Responses { get; private set; }

	public override byte MessageType => MessageNumber;

	public AuthenticationInfoResponseMessage()
	{
		Responses = new List<string>();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.Write((uint)Responses.Count);
		foreach (string response in Responses)
		{
			writer.Write(response ?? string.Empty, Encoding.UTF8);
		}
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		Responses.Clear();
		int responseCount = (int)reader.ReadUInt32();
		for (int i = 0; i < responseCount; i++)
		{
			Responses.Add(reader.ReadString(Encoding.UTF8));
		}
	}
}
