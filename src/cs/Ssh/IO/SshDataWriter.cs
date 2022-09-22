// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.DevTunnels.Ssh.IO;

/// <summary>
/// Writes SSH-formatted data (bytes, integers, and strings) to a Buffer.
/// </summary>
public struct SshDataWriter : IEquatable<SshDataWriter>
{
	private Buffer buffer;

	public SshDataWriter(Buffer buffer)
	{
		this.buffer = buffer;
		Position = 0;
	}

	public Buffer Buffer => this.buffer;

	public int Position { get; set; }

	public void Write(bool value)
	{
		Write(value ? (byte)1 : (byte)0);
	}

	public void Write(byte value)
	{
		Buffer.Expand(ref this.buffer, Position + 1);
		this.buffer[Position] = value;
		Position++;
	}

	public void Write(uint value)
	{
		Buffer.Expand(ref this.buffer, Position + 4);

		this.buffer[Position + 0] = (byte)(value >> 24);
		this.buffer[Position + 1] = (byte)(value >> 16);
		this.buffer[Position + 2] = (byte)(value >> 8);
		this.buffer[Position + 3] = (byte)(value >> 0);
		Position += 4;
	}

	internal static void Write(Buffer buffer, int offset, uint value)
	{
		buffer[offset + 0] = (byte)(value >> 24);
		buffer[offset + 1] = (byte)(value >> 16);
		buffer[offset + 2] = (byte)(value >> 8);
		buffer[offset + 3] = (byte)(value >> 0);
	}

	public void Write(ulong value)
	{
		Buffer.Expand(ref this.buffer, Position + 8);

		this.buffer[Position + 0] = (byte)(value >> 56);
		this.buffer[Position + 1] = (byte)(value >> 48);
		this.buffer[Position + 2] = (byte)(value >> 40);
		this.buffer[Position + 3] = (byte)(value >> 32);
		this.buffer[Position + 4] = (byte)(value >> 24);
		this.buffer[Position + 5] = (byte)(value >> 16);
		this.buffer[Position + 6] = (byte)(value >> 8);
		this.buffer[Position + 7] = (byte)(value >> 0);
		Position += 8;
	}

	public void Write(string str, Encoding encoding)
	{
		if (str == null) throw new ArgumentNullException(nameof(str));
		if (encoding == null) throw new ArgumentNullException(nameof(encoding));

		var bytes = encoding.GetBytes(str);
		WriteBinary(bytes);
	}

	public void Write(string[]? list, Encoding encoding)
	{
		Write(list != null ? string.Join(",", list) : string.Empty, encoding);
	}

	public void Write(BigInt value, bool lengthInBits = false)
	{
		var data = value.ToBuffer();
		if (data.Count == 1 && data[0] == 0)
		{
			Write(0U);
		}
		else if (lengthInBits)
		{
			// When length is in bits, the bigint is written as unsigned (so no extra leading zero).
			if (data[0] == 0)
			{
				data = data.Slice(1, data.Count - 1);
			}

			uint length = (uint)(data.Count - 1) * 8;
			var b = data[0];
			while (b > 0)
			{
				length++;
				b >>= 1;
			}

			Write(length);
			Write(data);
		}
		else
		{
			WriteBinary(data);
		}
	}

	public void Write(Buffer data)
	{
		Buffer.Expand(ref this.buffer, Position + data.Count);
		data.CopyTo(this.buffer, Position);
		Position += data.Count;
	}

	public void WriteBinary(Buffer data)
	{
		Buffer.Expand(ref this.buffer, Position + 4 + data.Count);
		Write((uint)data.Count);
		data.CopyTo(this.buffer, Position);
		Position += data.Count;
	}

	public void WriteRandom(int count)
	{
		Buffer.Expand(ref this.buffer, Position + count);
		SshAlgorithms.Random.GetBytes(this.buffer.Slice(Position, count));
		Position += count;
	}

	internal void WriteRaw(Buffer data)
	{
		Buffer.Expand(ref this.buffer, Position + data.Count);
		data.CopyTo(this.buffer, Position);
		Position += data.Count;
	}

	public Buffer ToBuffer()
	{
		return this.buffer.Slice(0, Position);
	}

	public bool Equals(SshDataWriter other) => this.buffer.Equals(other.Buffer);

	public override bool Equals(object? obj) => obj is SshDataWriter other && Equals(other);

	public override int GetHashCode() => this.buffer.GetHashCode();

	public static bool operator ==(SshDataWriter left, SshDataWriter right) => left.Equals(right);

	public static bool operator !=(SshDataWriter left, SshDataWriter right) => !(left == right);
}
