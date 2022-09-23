// Copyright (c) Microsoft. All rights reserved.

using System.Text;
using Microsoft.DevTunnels.Ssh.IO;
using Microsoft.DevTunnels.Ssh.Tcp;

namespace Microsoft.DevTunnels.Ssh.Messages;

public class PortForwardRequestMessage : SessionRequestMessage
{
	public string? AddressToBind { get; set; }

	public uint Port { get; set; }

	public PortForwardRequestMessage()
	{
		RequestType = PortForwardingService.PortForwardRequestType;
		WantReply = true;
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);
		AddressToBind = reader.ReadString(Encoding.ASCII);
		Port = reader.ReadUInt32();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);
		writer.Write(AddressToBind ?? string.Empty, Encoding.ASCII);
		writer.Write(Port);
	}

	public override string ToString()
	{
		return base.ToString() + $"(AddressToBind: {AddressToBind}, Port: {Port})";
	}
}
