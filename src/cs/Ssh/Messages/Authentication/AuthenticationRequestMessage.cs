// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_USERAUTH_REQUEST", MessageNumber)]
public class AuthenticationRequestMessage : AuthenticationMessage
{
	public const byte MessageNumber = 50;

	public override byte MessageType => MessageNumber;

	public string? Username { get; private set; }
	public string? ServiceName { get; private set; }
	public string? MethodName { get; private set; }

	public AuthenticationRequestMessage()
	{
	}

	public AuthenticationRequestMessage(
		string serviceName,
		string methodName,
		string username)
	{
		ServiceName = serviceName;
		MethodName = methodName;
		Username = username;
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (string.IsNullOrEmpty(MethodName))
		{
			throw new InvalidOperationException("Method name must be set.");
		}

		writer.Write(Username ?? string.Empty, Encoding.UTF8);
		writer.Write(ServiceName ?? string.Empty, Encoding.ASCII);
		writer.Write(MethodName!, Encoding.ASCII);
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		Username = reader.ReadString(Encoding.UTF8);
		ServiceName = reader.ReadString(Encoding.ASCII);
		MethodName = reader.ReadString(Encoding.ASCII);
	}

	public override string ToString()
	{
		return $"{base.ToString()}(Method: {MethodName}, Username: {Username})";
	}
}
