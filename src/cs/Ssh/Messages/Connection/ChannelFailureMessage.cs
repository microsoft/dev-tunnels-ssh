// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_CHANNEL_FAILURE", MessageNumber)]
public class ChannelFailureMessage : ChannelMessage
{
	internal const byte MessageNumber = 100;

	public override byte MessageType => MessageNumber;
}
