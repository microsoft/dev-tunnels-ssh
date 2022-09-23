// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_CHANNEL_WINDOW_ADJUST", MessageNumber)]
public class ChannelWindowAdjustMessage : ChannelMessage
{
	internal const byte MessageNumber = 93;

	public uint BytesToAdd { get; set; }

	public override byte MessageType => MessageNumber;

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		BytesToAdd = reader.ReadUInt32();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);

		writer.Write(BytesToAdd);
	}

	public override string ToString()
	{
		return base.ToString() + $"(BytesToAdd: {BytesToAdd})";
	}
}
