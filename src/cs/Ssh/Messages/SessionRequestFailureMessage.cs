// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_REQUEST_FAILURE", MessageNumber)]
public class SessionRequestFailureMessage : SshMessage
{
	internal const byte MessageNumber = 82;

	public override byte MessageType => MessageNumber;

	protected override void OnRead(ref SshDataReader reader)
	{
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
	}
}
