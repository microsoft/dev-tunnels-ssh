// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_CHANNEL_OPEN", MessageNumber)]
public class ChannelOpenMessage : ConnectionMessage
{
	internal const byte MessageNumber = 90;

	private uint senderChannel;

	public string? ChannelType { get; set; }

	public uint SenderChannel
	{
		get
		{
			return this.senderChannel;
		}
		set
		{
			if (value != this.senderChannel)
			{
				this.senderChannel = value;

				if (RawBytes.Count > 0 && ChannelType != null)
				{
					// The SenderChannel can be updated without re-serializing the message.
					// This supports piping channel messages with re-mapped channel IDs.
					// The SenderChannel field follows the 1-byte message type and
					// length-prefixed ChannelType string.
					SshDataWriter.Write(RawBytes, sizeof(byte) + sizeof(uint) + ChannelType.Length, value);
				}
			}
		}
	}

	public uint MaxWindowSize { get; set; }
	public uint MaxPacketSize { get; set; }

	public override byte MessageType => MessageNumber;

	public ChannelOpenMessage()
	{
		MaxWindowSize = SshChannel.DefaultMaxWindowSize;
		MaxPacketSize = SshChannel.DefaultMaxPacketSize;
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		ChannelType = reader.ReadString(Encoding.ASCII);
		this.senderChannel = reader.ReadUInt32();
		MaxWindowSize = reader.ReadUInt32();
		MaxPacketSize = reader.ReadUInt32();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (ChannelType == null)
		{
			throw new InvalidOperationException("Channel type not set.");
		}

		writer.Write(ChannelType, Encoding.ASCII);
		writer.Write(this.senderChannel);
		writer.Write(MaxWindowSize);
		writer.Write(MaxPacketSize);
	}

	public override string ToString()
	{
		return base.ToString() +
			$"(ChannelType: {ChannelType}, SenderChannel: {SenderChannel})";
	}
}
