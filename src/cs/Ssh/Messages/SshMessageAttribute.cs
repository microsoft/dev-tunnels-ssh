// Copyright (c) Microsoft. All rights reserved.

using System;

namespace Microsoft.DevTunnels.Ssh.Messages;

[AttributeUsage(AttributeTargets.Class, Inherited = true, AllowMultiple = false)]
public sealed class SshMessageAttribute : Attribute
{
	public SshMessageAttribute(string name, byte number)
	{
		if (string.IsNullOrEmpty(name)) throw new ArgumentNullException(nameof(name));

		Name = name;
		Number = number;
	}

	public string Name { get; private set; }
	public byte Number { get; private set; }
}
