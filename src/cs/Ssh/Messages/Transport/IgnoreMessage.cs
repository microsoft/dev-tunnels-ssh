// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_IGNORE", MessageNumber)]
public class IgnoreMessage : SshMessage
{
	internal const byte MessageNumber = 2;

	public override byte MessageType => MessageNumber;

	protected override void OnRead(ref SshDataReader reader)
	{
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
	}
}
