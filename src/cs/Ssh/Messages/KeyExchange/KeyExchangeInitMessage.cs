// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Linq;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[SshMessage("SSH_MSG_KEXINIT", MessageNumber)]
internal class KeyExchangeInitMessage : KeyExchangeMessage
{
	internal const byte MessageNumber = 20;

	public KeyExchangeInitMessage()
	{
	}

	public override byte MessageType => MessageNumber;

	private const int CookieLength = 16;

	/// <summary>
	/// Random bytes that ensure the complete message cannot be guessed,
	/// because it is an input to deriving the session key.
	/// </summary>
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
		Cookie = reader.ReadBinary(CookieLength);
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
		if (Cookie.Count != CookieLength)
		{
			Cookie = new Buffer(CookieLength);
			SshAlgorithms.Random.GetBytes(Cookie);
		}

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

	/// <summary>
	/// Gets a key-exchange init message that specifies "none" for all algorithms.
	/// </summary>
	public static KeyExchangeInitMessage None { get; } = CreateNone();

	private static KeyExchangeInitMessage CreateNone()
	{
		var noneArray = new[] { "none" };
		var emptyArray = new[] { string.Empty };

		var message = new KeyExchangeInitMessage
		{
			Cookie = new Buffer(CookieLength),
			KeyExchangeAlgorithms = noneArray,
			ServerHostKeyAlgorithms = noneArray,
			EncryptionAlgorithmsClientToServer = noneArray,
			EncryptionAlgorithmsServerToClient = noneArray,
			MacAlgorithmsClientToServer = noneArray,
			MacAlgorithmsServerToClient = noneArray,
			CompressionAlgorithmsClientToServer = noneArray,
			CompressionAlgorithmsServerToClient = noneArray,
			LanguagesClientToServer = emptyArray,
			LanguagesServerToClient = emptyArray,
		};

		// Save the serialized bytes so that the message doesn't have to be re-serialized every time
		// it is sent.
		message.RawBytes = message.ToBuffer();

		return message;
	}

	public bool AllowsNone
	{
		get
		{
			bool IncludesNone(string[]? algorithms) => algorithms?.Contains("none") == true;
			return IncludesNone(KeyExchangeAlgorithms) &&
				IncludesNone(ServerHostKeyAlgorithms) &&
				IncludesNone(EncryptionAlgorithmsClientToServer) &&
				IncludesNone(EncryptionAlgorithmsServerToClient) &&
				IncludesNone(MacAlgorithmsClientToServer) &&
				IncludesNone(MacAlgorithmsServerToClient) &&
				IncludesNone(CompressionAlgorithmsClientToServer) &&
				IncludesNone(CompressionAlgorithmsServerToClient) &&
				!FirstKexPacketFollows;
		}
	}
}
