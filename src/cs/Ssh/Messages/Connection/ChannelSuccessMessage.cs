// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_CHANNEL_SUCCESS", MessageNumber)]
public class ChannelSuccessMessage : ChannelMessage
{
	internal const byte MessageNumber = 99;

	public override byte MessageType => MessageNumber;
}
