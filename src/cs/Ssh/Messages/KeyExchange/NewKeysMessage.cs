// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_NEWKEYS", MessageNumber)]
internal class NewKeysMessage : KeyExchangeMessage
{
	internal const byte MessageNumber = 21;

	public override byte MessageType => MessageNumber;

	protected override void OnRead(ref SshDataReader reader)
	{
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
	}
}
