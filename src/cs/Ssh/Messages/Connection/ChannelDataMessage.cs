// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_CHANNEL_DATA", MessageNumber)]
public class ChannelDataMessage : ChannelMessage
{
	internal const byte MessageNumber = 94;

#pragma warning disable CA2227 // Collection properties should be read only
	public Buffer Data { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only

	public override byte MessageType => MessageNumber;

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		Data = reader.ReadBinary();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);

		writer.WriteBinary(Data);
	}

	public override string ToString()
	{
		return Data.ToString(nameof(ChannelDataMessage));
	}
}
