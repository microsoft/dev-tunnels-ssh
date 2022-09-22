// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_USERAUTH_FAILURE", MessageNumber)]
public class AuthenticationFailureMessage : AuthenticationMessage
{
	internal const byte MessageNumber = 51;

	public override byte MessageType => MessageNumber;

#pragma warning disable CA1819 // Properties should not return arrays
	public string[]? MethodNames { get; set; }
#pragma warning restore CA1819 // Properties should not return arrays

	public bool PartialSuccess { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		MethodNames = reader.ReadList(Encoding.ASCII);
		PartialSuccess = reader.ReadBoolean();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.Write(MethodNames ?? Array.Empty<string>(), Encoding.ASCII);
		writer.Write(PartialSuccess);
	}
}
