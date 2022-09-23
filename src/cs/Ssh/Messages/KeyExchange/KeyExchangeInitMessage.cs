// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_KEXINIT", MessageNumber)]
internal class KeyExchangeInitMessage : KeyExchangeMessage
{
	internal const byte MessageNumber = 20;

	public KeyExchangeInitMessage()
	{
		Cookie = new Buffer(16);
		SshAlgorithms.Random.GetBytes(Cookie);
	}

	public override byte MessageType => MessageNumber;

	public Buffer Cookie { get; private set; }

#pragma warning disable CA1819 // Properties should not return arrays
	public string[]? KeyExchangeAlgorithms { get; set; }

	public string[]? ServerHostKeyAlgorithms { get; set; }

	public string[]? EncryptionAlgorithmsClientToServer { get; set; }

	public string[]? EncryptionAlgorithmsServerToClient { get; set; }

	public string[]? MacAlgorithmsClientToServer { get; set; }

	public string[]? MacAlgorithmsServerToClient { get; set; }

	public string[]? CompressionAlgorithmsClientToServer { get; set; }

	public string[]? CompressionAlgorithmsServerToClient { get; set; }

	public string[]? LanguagesClientToServer { get; set; }

	public string[]? LanguagesServerToClient { get; set; }
#pragma warning restore CA1819 // Properties should not return arrays

	public bool FirstKexPacketFollows { get; set; }

	public uint Reserved { get; set; }

	protected override void OnRead(ref SshDataReader reader)
	{
		Cookie = reader.ReadBinary(16);
		KeyExchangeAlgorithms = reader.ReadList(Encoding.ASCII);
		ServerHostKeyAlgorithms = reader.ReadList(Encoding.ASCII);
		EncryptionAlgorithmsClientToServer = reader.ReadList(Encoding.ASCII);
		EncryptionAlgorithmsServerToClient = reader.ReadList(Encoding.ASCII);
		MacAlgorithmsClientToServer = reader.ReadList(Encoding.ASCII);
		MacAlgorithmsServerToClient = reader.ReadList(Encoding.ASCII);
		CompressionAlgorithmsClientToServer = reader.ReadList(Encoding.ASCII);
		CompressionAlgorithmsServerToClient = reader.ReadList(Encoding.ASCII);
		LanguagesClientToServer = reader.ReadList(Encoding.ASCII);
		LanguagesServerToClient = reader.ReadList(Encoding.ASCII);
		FirstKexPacketFollows = reader.ReadBoolean();
		Reserved = reader.ReadUInt32();
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		writer.Write(Cookie);
		writer.Write(KeyExchangeAlgorithms, Encoding.ASCII);
		writer.Write(ServerHostKeyAlgorithms, Encoding.ASCII);
		writer.Write(EncryptionAlgorithmsClientToServer, Encoding.ASCII);
		writer.Write(EncryptionAlgorithmsServerToClient, Encoding.ASCII);
		writer.Write(MacAlgorithmsClientToServer, Encoding.ASCII);
		writer.Write(MacAlgorithmsServerToClient, Encoding.ASCII);
		writer.Write(CompressionAlgorithmsClientToServer, Encoding.ASCII);
		writer.Write(CompressionAlgorithmsServerToClient, Encoding.ASCII);
		writer.Write(LanguagesClientToServer, Encoding.ASCII);
		writer.Write(LanguagesServerToClient, Encoding.ASCII);
		writer.Write(FirstKexPacketFollows);
		writer.Write(Reserved);
	}
}
