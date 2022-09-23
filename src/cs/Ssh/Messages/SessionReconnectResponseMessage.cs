// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

internal class SessionReconnectResponseMessage : SessionRequestSuccessMessage
{
#pragma warning disable CA2227 // Collection properties should be read only
	public Buffer ServerReconnectToken { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only

	public ulong LastReceivedSequenceNumber { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);
		ServerReconnectToken = reader.ReadBinary();
		LastReceivedSequenceNumber = reader.ReadUInt64();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);
		writer.WriteBinary(ServerReconnectToken);
		writer.Write(LastReceivedSequenceNumber);
	}

	public override string ToString()
	{
		return base.ToString() + $"(LastReceivedSequenceNumber: {LastReceivedSequenceNumber})";
	}
}
