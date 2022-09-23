// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_USERAUTH_PK_OK", MessageNumber)]
public class PublicKeyOkMessage : AuthenticationMessage
{
	internal const byte MessageNumber = 60;

	public override byte MessageType => MessageNumber;

	public string? KeyAlgorithmName { get; set; }

#pragma warning disable CA2227 // Collection properties should be read only
	public Buffer PublicKey { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only

	protected override void OnRead(ref SshDataReader reader)
	{
		KeyAlgorithmName = reader.ReadString(Encoding.ASCII);
		PublicKey = reader.ReadBinary();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (KeyAlgorithmName == null)
		{
			throw new InvalidOperationException("Key algorithm name not set.");
		}

		writer.Write(KeyAlgorithmName, Encoding.ASCII);
		writer.WriteBinary(PublicKey);
	}
}
