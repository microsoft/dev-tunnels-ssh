// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_SERVICE_REQUEST", MessageNumber)]
public class ServiceRequestMessage : SshMessage
{
	internal const byte MessageNumber = 5;

	public override byte MessageType => MessageNumber;

	public string? ServiceName { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		ServiceName = reader.ReadString(Encoding.ASCII);
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (ServiceName == null)
		{
			throw new InvalidOperationException("Service name not set.");
		}

		writer.Write(ServiceName, Encoding.ASCII);
	}

	public override string ToString()
	{
		return $"{base.ToString()}(Service: {ServiceName})";
	}
}
