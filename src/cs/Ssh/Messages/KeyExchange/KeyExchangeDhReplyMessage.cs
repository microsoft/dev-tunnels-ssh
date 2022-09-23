// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_KEXDH_REPLY", MessageNumber)]
internal class KeyExchangeDhReplyMessage : KeyExchangeMessage
{
	internal const byte MessageNumber = 31;

	public override byte MessageType => MessageNumber;

#pragma warning disable CA2227 // Collection properties should be read only
	public Buffer HostKey { get; set; }

	public Buffer F { get; set; }

	public Buffer Signature { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only

	protected override void OnRead(ref SshDataReader reader)
	{
		HostKey = reader.ReadBinary();
		F = reader.ReadBinary();
		Signature = reader.ReadBinary();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.WriteBinary(HostKey);
		writer.WriteBinary(F);
		writer.WriteBinary(Signature);
	}
}
