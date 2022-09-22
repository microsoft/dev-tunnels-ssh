// Copyright (c) Microsoft. All rights reserved.

using System;
using System.IO;
using System.Text;

namespace Microsoft.DevTunnels.Ssh.IO;

/// <summary>
/// Reads SSH-formatted data (bytes, integers, and strings) from a Buffer.
/// </summary>
public struct SshDataReader : IEquatable<SshDataReader>
{
	private readonly Buffer buffer;

	public SshDataReader(Buffer buffer)
	{
		this.buffer = buffer;
		Position = 0;
	}

	public Buffer Buffer => this.buffer;

	public int Position { get; set; }

	public long Available => this.buffer.Count - Position;

	public bool ReadBoolean()
	{
		return ReadByte() != 0;
	}

	public byte ReadByte()
	{
		if (Available == 0)
		{
			throw new EndOfStreamException();
		}

		byte value = this.buffer[Position];
		Position++;
		return value;
	}

	public uint ReadUInt32()
	{
		if (Available < 4)
		{
			throw new EndOfStreamException();
		}

		var value0 = this.buffer[Position + 0];
		var value1 = this.buffer[Position + 1];
		var value2 = this.buffer[Position + 2];
		var value3 = this.buffer[Position + 3];
		Position += 4;

		var value = ((uint)value0 << 24 | (uint)value1 << 16 | (uint)value2 << 8 | (uint)value3);
		return value;
	}

	public ulong ReadUInt64()
	{
		if (Available < 8)
		{
			throw new EndOfStreamException();
		}

		var value0 = this.buffer[Position + 0];
		var value1 = this.buffer[Position + 1];
		var value2 = this.buffer[Position + 2];
		var value3 = this.buffer[Position + 3];
		var value4 = this.buffer[Position + 4];
		var value5 = this.buffer[Position + 5];
		var value6 = this.buffer[Position + 6];
		var value7 = this.buffer[Position + 7];
		Position += 8;

		var value = (ulong)value0 << 56 | (ulong)value1 << 48 | (ulong)value2 << 40 | (ulong)value3 << 32 |
			(ulong)value4 << 24 | (ulong)value5 << 16 | (ulong)value6 << 8 | (ulong)value7;
		return value;
	}

	public string ReadString(Encoding encoding)
	{
		if (encoding == null) throw new ArgumentNullException(nameof(encoding));

		var bytes = ReadBinary();
		return encoding.GetString(bytes.Array, bytes.Offset, bytes.Count);
	}

	public string[] ReadList(Encoding encoding)
	{
		string stringList = ReadString(encoding);
		return stringList.Length == 0 ? Array.Empty<string>() : stringList.Split(',');
	}

	public BigInt ReadBigInt(bool lengthInBits = false)
	{
		uint length = ReadUInt32();
		if (lengthInBits)
		{
			length = (length + 7) / 8;
		}

		var data = ReadBinary(length);

		if (data.Count == 0)
		{
			return BigInt.Zero;
		}
		else if (lengthInBits)
		{
			return BigInt.FromByteArray(data.ToArray(), unsigned: true);
		}
		else
		{
			return new BigInt(data);
		}
	}

	public Buffer ReadBinary()
	{
		uint length = ReadUInt32();
		if (Available < length)
		{
			throw new EndOfStreamException();
		}

		return ReadBinary(length);
	}

	public Buffer ReadBinary(uint length)
	{
		var data = this.buffer.Slice(Position, (int)length);
		Position += (int)length;
		return data;
	}

	public bool Equals(SshDataReader other) => this.buffer.Equals(other.Buffer);

	public override bool Equals(object? obj) => obj is SshDataReader other && Equals(other);

	public override int GetHashCode() => this.buffer.GetHashCode();

	public static bool operator ==(SshDataReader left, SshDataReader right) => left.Equals(right);

	public static bool operator !=(SshDataReader left, SshDataReader right) => !(left == right);
}
