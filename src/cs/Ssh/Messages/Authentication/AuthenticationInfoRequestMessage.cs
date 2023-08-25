// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_USERAUTH_INFO_REQUEST", MessageNumber)]
public class AuthenticationInfoRequestMessage : AuthenticationMessage
{
	public const byte MessageNumber = 60;

	public override byte MessageType => MessageNumber;

	public string Name { get; private set; }
	public string? Instruction { get; set; }
	public string? Language { get; set; }
	public IList<(string Prompt, bool Echo)> Prompts { get; private set; }

	public AuthenticationInfoRequestMessage() : this(string.Empty)
	{
	}

	public AuthenticationInfoRequestMessage(string name)
	{
		Name = name;
		Prompts = new List<(string, bool)>();
	}

	public void AddPrompt(string prompt, bool echo)
	{
		Prompts.Add((prompt, echo));
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.Write(Name ?? string.Empty, Encoding.UTF8);
		writer.Write(Instruction ?? string.Empty, Encoding.UTF8);
		writer.Write(Language ?? string.Empty, Encoding.ASCII);
		writer.Write((uint)Prompts.Count);

		foreach (var (prompt, _) in Prompts)
		{
			writer.Write(prompt ?? string.Empty, Encoding.UTF8);
		}

		foreach (var (_, echo) in Prompts)
		{
			writer.Write(echo);
		}
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		Name = reader.ReadString(Encoding.UTF8);
		Instruction = reader.ReadString(Encoding.UTF8);
		Language = reader.ReadString(Encoding.ASCII);

		Prompts.Clear();
		int promptsCount = (int)reader.ReadUInt32();

		string[] promptStrings = new string[promptsCount];
		for (int i = 0; i < promptsCount; i++)
		{
			promptStrings[i] = reader.ReadString(Encoding.UTF8);
		}

		for (int i = 0; i < promptsCount; i++)
		{
			bool echo = reader.ReadBoolean();
			Prompts.Add((promptStrings[i], echo));
		}
	}

	public override string ToString()
	{
		return $"{base.ToString()} \"{Name}\"";
	}
}
