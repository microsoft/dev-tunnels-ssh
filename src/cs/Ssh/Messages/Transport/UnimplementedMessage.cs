// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_UNIMPLEMENTED", MessageNumber)]
public class UnimplementedMessage : SshMessage
{
	internal const byte MessageNumber = 3;

	public override byte MessageType => MessageNumber;

	public uint SequenceNumber { get; set; }

	public byte? UnimplementedMessageType { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		SequenceNumber = reader.ReadUInt32();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.Write(SequenceNumber);
	}

	public override string ToString()
	{
		return UnimplementedMessageType != null ?
			$"{base.ToString()}(MessageType: {UnimplementedMessageType})" :
			$"{base.ToString()}(SequenceNumber: {SequenceNumber})";
	}
}
