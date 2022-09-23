// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

public class PasswordRequestMessage : AuthenticationRequestMessage
{
	public string? Password { get; private set; }

	public PasswordRequestMessage()
	{
	}

	public PasswordRequestMessage(
		string serviceName,
		string username,
		string? password)
		: base(serviceName, AuthenticationMethods.Password, username)
	{
		Password = password;
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);

		writer.Write(false);
		writer.Write(Password ?? string.Empty, Encoding.UTF8);
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		if (MethodName != AuthenticationMethods.Password)
		{
			throw new ArgumentException($"Method name {MethodName} is not valid.");
		}

		reader.ReadBoolean();
		Password = reader.ReadString(Encoding.UTF8);
	}
}
