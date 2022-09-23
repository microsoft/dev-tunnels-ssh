// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_CHANNEL_OPEN_CONFIRMATION", MessageNumber)]
public class ChannelOpenConfirmationMessage : ChannelMessage
{
	internal const byte MessageNumber = 91;

	public uint SenderChannel { get; set; }
	public uint MaxWindowSize { get; set; }
	public uint MaxPacketSize { get; set; }

	public override byte MessageType => MessageNumber;

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		SenderChannel = reader.ReadUInt32();
		MaxWindowSize = reader.ReadUInt32();
		MaxPacketSize = reader.ReadUInt32();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);

		writer.Write(SenderChannel);
		writer.Write(MaxWindowSize);
		writer.Write(MaxPacketSize);
	}

	public override string ToString()
	{
		return base.ToString() + $"(SenderChannel: {SenderChannel})";
	}
}
