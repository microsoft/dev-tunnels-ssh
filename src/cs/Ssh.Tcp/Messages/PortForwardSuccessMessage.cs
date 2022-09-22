// Copyright (c) Microsoft. All rights reserved.

using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

public class PortForwardSuccessMessage : SessionRequestSuccessMessage
{
	public uint Port { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		// The port may be omitted from the response if it is the same as the requested port.
		if (reader.Available >= 4)
		{
			Port = reader.ReadUInt32();
		}
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);
		writer.Write(Port);
	}

	public override string ToString()
	{
		return base.ToString() + $"(Port: {Port})";
	}
}
