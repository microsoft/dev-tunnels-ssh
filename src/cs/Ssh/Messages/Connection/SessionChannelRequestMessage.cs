// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

/// <summary>
/// Extension request used with <see cref="SshProtocolExtensionNames.OpenChannelRequest" />
/// that enables sending a channel request (as a session request) before the recipient
/// channel ID is known.
/// </summary>
public class SessionChannelRequestMessage : SessionRequestMessage
{
	public uint SenderChannelId { get; set; }
	public ChannelRequestMessage? Request { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);
		SenderChannelId = reader.ReadUInt32();

		var request = new ChannelRequestMessage();
		request.Read(ref reader);
		Request = request;
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (Request == null)
		{
			throw new InvalidOperationException("Request message not set.");
		}

		base.OnWrite(ref writer);
		writer.Write(SenderChannelId);
		Request!.Write(ref writer);
	}

	public override string ToString()
	{
		return Request?.ToString() ?? base.ToString();
	}
}
