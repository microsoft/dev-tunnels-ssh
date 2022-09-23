// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

public abstract class ChannelMessage : ConnectionMessage
{
	private uint recipientChannel;

	public uint RecipientChannel
	{
		get
		{
			return this.recipientChannel;
		}
		set
		{
			if (value != this.recipientChannel)
			{
				this.recipientChannel = value;

				if (RawBytes.Count > 0)
				{
					// The RecipientChannel can be updated without re-serializing the message.
					// This supports piping channel messages with re-mapped channel IDs.
					// The RecipientChannel field follows the 1-byte message type.
					SshDataWriter.Write(RawBytes, 1, value);
				}
			}
		}
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		this.recipientChannel = reader.ReadUInt32();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.Write(this.recipientChannel);
	}

	public override string ToString()
	{
		return base.ToString() + $"(RecipientChannel: {RecipientChannel})";
	}
}
