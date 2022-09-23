// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_CHANNEL_CLOSE", MessageNumber)]
public class ChannelCloseMessage : ChannelMessage
{
	internal const byte MessageNumber = 97;

	public override byte MessageType => MessageNumber;
}
