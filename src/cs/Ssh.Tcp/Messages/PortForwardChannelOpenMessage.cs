// Copyright (c) Microsoft. All rights reserved.

using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

public class PortForwardChannelOpenMessage : ChannelOpenMessage
{
	public string Host { get; set; } = string.Empty;
	public uint Port { get; set; }
	public string OriginatorIPAddress { get; set; } = string.Empty;
	public uint OriginatorPort { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		Host = reader.ReadString(Encoding.ASCII);
		Port = reader.ReadUInt32();
		OriginatorIPAddress = reader.ReadString(Encoding.ASCII);
		OriginatorPort = reader.ReadUInt32();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);

		writer.Write(Host ?? string.Empty, Encoding.ASCII);
		writer.Write(Port);
		writer.Write(OriginatorIPAddress ?? string.Empty, Encoding.ASCII);
		writer.Write(OriginatorPort);
	}

	public override string ToString() =>
		$"{GetType().Name} ChannelType: {ChannelType}, SenderChannel: {SenderChannel}, " +
		$"Host: {Host}, Port: {Port}, OriginatorIPAddress: {OriginatorIPAddress}, OriginatorPort: {OriginatorPort}";
}
