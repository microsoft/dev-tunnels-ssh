// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_CHANNEL_EOF", MessageNumber)]
public class ChannelEofMessage : ChannelMessage
{
	internal const byte MessageNumber = 96;

	public override byte MessageType => MessageNumber;
}
