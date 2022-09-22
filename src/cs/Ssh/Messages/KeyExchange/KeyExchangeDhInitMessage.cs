// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_KEXDH_INIT", MessageNumber)]
internal class KeyExchangeDhInitMessage : KeyExchangeMessage
{
	internal const byte MessageNumber = 30;

	public override byte MessageType => MessageNumber;

#pragma warning disable CA2227 // Collection properties should be read only
	public Buffer E { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only

	protected override void OnRead(ref SshDataReader reader)
	{
		E = reader.ReadBinary();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.WriteBinary(E);
	}
}
