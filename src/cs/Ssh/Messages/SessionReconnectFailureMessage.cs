// Copyright (c) Microsoft. All rights reserved.

using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

internal class SessionReconnectFailureMessage : SessionRequestFailureMessage
{
	public SshReconnectFailureReason ReasonCode { get; set; }
	public string? Description { get; set; }
	public string? Language { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		if (reader.Available > 0)
		{
			ReasonCode = (SshReconnectFailureReason)reader.ReadUInt32();
			Description = reader.ReadString(Encoding.UTF8);
			Language = reader.ReadString(Encoding.ASCII);
		}
		else
		{
			ReasonCode = SshReconnectFailureReason.UnknownClientFailure;
		}
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
