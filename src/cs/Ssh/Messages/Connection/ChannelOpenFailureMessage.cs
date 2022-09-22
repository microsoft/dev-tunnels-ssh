// Copyright (c) Microsoft. All rights reserved.

using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_CHANNEL_OPEN_FAILURE", MessageNumber)]
public class ChannelOpenFailureMessage : ChannelMessage
{
	internal const byte MessageNumber = 92;

	public SshChannelOpenFailureReason ReasonCode { get; set; }
	public string? Description { get; set; }
	public string? Language { get; set; }

	public override byte MessageType => MessageNumber;

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		ReasonCode = (SshChannelOpenFailureReason)reader.ReadUInt32();
		Description = reader.ReadString(Encoding.UTF8);
		Language = reader.ReadString(Encoding.ASCII);
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);

		writer.Write((uint)ReasonCode);
		writer.Write(Description ?? string.Empty, Encoding.UTF8);
		writer.Write(Language ?? "en", Encoding.ASCII);
	}

	public override string ToString()
	{
		return $"{base.ToString()}(ReasonCode: {ReasonCode}, Description: {Description})";
	}
}
