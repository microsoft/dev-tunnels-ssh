// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_EXT_INFO", MessageNumber)]
public class ExtensionInfoMessage : SshMessage
{
	// https://tools.ietf.org/html/draft-ietf-curdle-ssh-ext-info-15

	public const string ServerIndicator = "ext-info-c";
	public const string ClientIndicator = "ext-info-c";

	internal const byte MessageNumber = 7;

	public override byte MessageType => MessageNumber;

#pragma warning disable CA2227 // Collection properties should be read only
	public IDictionary<string, string>? ExtensionInfo { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only

	protected override void OnRead(ref SshDataReader reader)
	{
		uint count = reader.ReadUInt32();
		ExtensionInfo = new Dictionary<string, string>();

		for (uint i = 0; i < count; i++)
		{
			string key = reader.ReadString(Encoding.ASCII);
			string value = reader.ReadString(Encoding.UTF8);
			ExtensionInfo[key] = value;
		}
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (ExtensionInfo == null)
		{
			throw new InvalidOperationException("Extension info not set.");
		}

		writer.Write((uint)ExtensionInfo.Count);
		foreach (var item in ExtensionInfo)
		{
			writer.Write(item.Key, Encoding.ASCII);
			writer.Write(item.Value, Encoding.UTF8);
		}
	}

	public override string ToString()
	{
		if (ExtensionInfo == null)
		{
			return base.ToString();
		}

		return base.ToString() + '(' +
			string.Join("; ", ExtensionInfo.Select(
				e => e.Key + (e.Value.Length > 0 ? '=' + e.Value : string.Empty))) + ')';
	}
}
