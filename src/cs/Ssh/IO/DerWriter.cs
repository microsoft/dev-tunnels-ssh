// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;

namespace Microsoft.DevTunnels.Ssh.IO;

/// <summary>
/// Writes data in DER (Distinguished Encoding Rules) format.
/// </summary>
/// <remarks>
/// Reference: https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
/// Reference: http://luca.ntop.org/Teaching/Appunti/asn1.html
/// </remarks>
public struct DerWriter : IEquatable<DerWriter>
{
	private Buffer buffer;
	private int position;
	private readonly DerType dataType;

	public DerWriter(Buffer buffer) : this(buffer, DerType.Constructed | DerType.Sequence)
	{
	}

	public DerWriter(Buffer buffer, DerType dataType)
	{
		this.buffer = buffer;
		this.position = 0;
		this.dataType = dataType;
	}

	public Buffer ToBuffer()
	{
		// Move the data over to make space for the type + length prefix.
		var length = this.position;
		var lengthSize = GetLengthSize(length);
		Buffer.Expand(ref this.buffer, 1 + lengthSize + length);
		Array.Copy(
			this.buffer.Array,
			this.buffer.Offset,
			this.buffer.Array,
			this.buffer.Offset + 1 + lengthSize,
			length);

		// Write the type + length prefix.
		this.position = 0;
		Write((byte)(this.dataType == default
			? DerType.Constructed | DerType.Sequence : this.dataType));
		WriteLength(length);
		var result = this.buffer.Slice(0, this.position + length);

		// Restore the writer buffer to its previous state (without the type + length prefix).
		this.buffer = this.buffer.Slice(1 + lengthSize, length);
		this.position = length;
		return result;
	}

	public byte[] ToArray()
	{
		return ToBuffer().ToArray();
	}

	public void WriteSequence(DerWriter data)
	{
		Write(data.ToBuffer());
	}

	public void WriteTagged(int tagId, DerWriter data)
	{
		if (tagId > 0xF) throw new ArgumentOutOfRangeException(nameof(tagId));
		Write((byte)(DerType.Tagged | (DerType)tagId));
		WriteLength(data.position);
		Write(data.buffer.Slice(0, data.position));
	}

	public void WriteNull()
	{
		Write((byte)DerType.Null);
		Write((byte)0);
	}

	public void WriteInteger(BigInt value)
	{
		Write((byte)DerType.Integer);
		var data = value.ToBuffer();
		WriteLength(data.Count);
		Write(data);
	}

	public void WriteOctetString(Buffer data)
	{
		Write((byte)DerType.OctetString);
		WriteLength(data.Count);
		Write(data);
	}

	public void WriteBitString(Buffer data)
	{
		Write((byte)DerType.BitString);
		WriteLength(1 + data.Count);
		Write((byte)0);
		Write(data);
	}

	public void WriteObjectIdentifier(Oid oidValue)
	{
		if (oidValue == null || oidValue.Value == null)
		{
			throw new ArgumentNullException(nameof(oidValue));
		}

		var values = oidValue.Value.Split('.')
			.Select((v) => int.Parse(v, CultureInfo.InvariantCulture))
			.ToArray();
		if (values.Length < 2 || values[0] >= 3 || values[1] >= 40)
		{
			throw new ArgumentException("Invalid object identifier", nameof(oidValue));
		}

		Write((byte)DerType.ObjectIdentifier);

		var length = values.Length - 1;
		for (int i = 2; i < values.Length; i++)
		{
			var value = values[i];
			while (value > 128)
			{
				length++;
				value /= 128;
			}
		}

		WriteLength(length);
		Write((byte)((values[0] * 40) + values[1]));

		for (int i = 2; i < values.Length; i++)
		{
			var value = values[i];
			if (value >= 128)
			{
				var bytes = new Stack<byte>();
				bytes.Push((byte)(value & 0x7F));

				while (value >= 128)
				{
					value /= 128;
					bytes.Push((byte)(0x80 | (value & 0x7F)));
				}

				while (bytes.Count > 0)
				{
					Write(bytes.Pop());
				}
			}
			else
			{
				Write((byte)value);
			}
		}
	}

	private void Write(byte value)
	{
		Buffer.Expand(ref this.buffer, this.position + 1);
		this.buffer[this.position] = value;
		this.position++;
	}

	private void Write(Buffer data)
	{
		Buffer.Expand(ref this.buffer, this.position + data.Count);
		data.CopyTo(this.buffer, this.position);
		this.position += data.Count;
	}

	private static int GetLengthSize(int length)
	{
		if (length > 127)
		{
			var size = 2;
			var val = length;

			while ((val >>= 8) != 0)
			{
				size++;
			}

			return size;
		}
		else
		{
			return 1;
		}
	}

	private void WriteLength(int length)
	{
		int size = GetLengthSize(length);
		if (size > 1)
		{
			Write((byte)((size - 1) | 0x80));
			for (int i = (size - 2) * 8, j = 1; i >= 0; i -= 8, j++)
			{
				Write((byte)(length >> i));
			}
		}
		else
		{
			Write((byte)length);
		}
	}

	public bool Equals(DerWriter other) =>
		this.dataType == other.dataType && this.buffer.Equals(other.buffer);

	public override bool Equals(object? obj) => obj is DerWriter other && Equals(other);

	public override int GetHashCode() => this.buffer.GetHashCode();

	public static bool operator ==(DerWriter left, DerWriter right) => left.Equals(right);

	public static bool operator !=(DerWriter left, DerWriter right) => !(left == right);
}
