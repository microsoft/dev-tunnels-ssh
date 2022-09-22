// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

internal class SessionReconnectRequestMessage : SessionRequestMessage
{
#pragma warning disable CA2227 // Collection properties should be read only
	public Buffer ClientReconnectToken { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only

	public ulong LastReceivedSequenceNumber { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);
		ClientReconnectToken = reader.ReadBinary();
		LastReceivedSequenceNumber = reader.ReadUInt64();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);
		writer.WriteBinary(ClientReconnectToken);
		writer.Write(LastReceivedSequenceNumber);
	}

	public override string ToString()
	{
		return $"{GetType().Name}(LastReceivedSequenceNumber: {LastReceivedSequenceNumber})";
	}
}
