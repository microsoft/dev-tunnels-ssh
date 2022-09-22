// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.IO;

/// <summary>
/// Defines data types supported by <see cref="DerReader" /> and <see cref="DerWriter" />.
/// </summary>
public enum DerType
{
	None = 0,
#pragma warning disable CA1720 // Identifier contains type name
	Integer = 0x02,
#pragma warning restore CA1720 // Identifier contains type name
	BitString = 0x03,
	OctetString = 0x04,
	Null = 0x05,
	ObjectIdentifier = 0x06,
	Sequence = 0x10,
	Set = 0x11,
	Constructed = 0x20,
	Tagged = 0xA0,
}
