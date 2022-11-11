// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

[DebuggerDisplay("{ToString(),nq}")]
public abstract class SshMessage
{
	/// <summary>
	/// Tries to create a message with the given message type code.
	/// </summary>
	/// <returns>The constructed message object, or null if not a known message type.</returns>
	public static SshMessage? TryCreate(SshSessionConfiguration config, byte messageType)
	{
		if (config == null) throw new ArgumentNullException(nameof(config));

		if (config.Messages.TryGetValue(messageType, out var type))
		{
			return (SshMessage)Activator.CreateInstance(type)!;
		}

		return null;
	}

	public abstract byte MessageType { get; }

	protected Buffer RawBytes { get; set; }

	public void Read(ref SshDataReader reader)
	{
		RawBytes = reader.Buffer;

		var number = reader.ReadByte();
		if (number != MessageType)
		{
			throw new ArgumentException($"Message type {number} is not valid.");
		}

		OnRead(ref reader);
	}

	public void Write(ref SshDataWriter writer)
	{
		if (this.RawBytes.Count > 0)
		{
			// Piped messages are rewritten without re-serialization. This preserves any
			// unparsed extended message data. It assumes no properties of the message
			// have been modified without also updating the serialized bytes.
			writer.WriteRaw(this.RawBytes);
		}
		else
		{
			writer.Write(MessageType);

			OnWrite(ref writer);
		}
	}

	public Buffer ToBuffer()
	{
		var writer = new SshDataWriter();
		Write(ref writer);
		return writer.ToBuffer();
	}

	public T ConvertTo<T>(bool copy = false) where T : SshMessage, new()
	{
		var reader = new SshDataReader(copy ? RawBytes.Copy() : RawBytes);
		var message = new T();
		message.Read(ref reader);
		return message;
	}

	protected virtual void OnRead(ref SshDataReader reader)
	{
		throw new NotSupportedException();
	}

	protected virtual void OnWrite(ref SshDataWriter writer)
	{
		throw new NotSupportedException();
	}

	public override string ToString()
	{
		return GetType().Name;
	}
}
