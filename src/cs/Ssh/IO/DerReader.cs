// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Microsoft.DevTunnels.Ssh.IO;

/// <summary>
/// Reads data in DER (Distinguished Encoding Rules) format.
/// </summary>
/// <remarks>
/// Reference: https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
/// Reference: http://luca.ntop.org/Teaching/Appunti/asn1.html
/// </remarks>
public struct DerReader : IEquatable<DerReader>
{
	private readonly Buffer buffer;
	private int position;

	public DerReader(Buffer buffer) : this(buffer, DerType.Constructed | DerType.Sequence)
	{
	}

	public DerReader(Buffer buffer, DerType dataType)
	{
		this.buffer = buffer;
		this.position = 0;

		ReadType(dataType);

		var length = ReadLength();
		if (length > this.buffer.Count - this.position)
		{
			throw new InvalidOperationException("Read out of bounds.");
		}

		this.buffer = this.buffer.Slice(0, this.position + length);
	}

	public int Available
	{
		get
		{
			return this.buffer.Count - this.position;
		}
	}

	public void ReadNull()
	{
		ReadType(DerType.Null);
		if (ReadByte() != 0)
		{
			throw new InvalidOperationException($"Expected 0 after Null type.");
		}
	}

	public BigInt ReadInteger()
	{
		ReadType(DerType.Integer);
		var length = ReadLength();
		var resultBytes = ReadBytes(length);
		var result = new BigInt(resultBytes);
		return result;
	}

	public Buffer ReadOctetString()
	{
		ReadType(DerType.OctetString);
		var length = ReadLength();
		var result = ReadBytes(length);
		return result;
	}

	public Buffer ReadBitString()
	{
		ReadType(DerType.BitString);
		var length = ReadLength();

		var padding = ReadByte();
		if (padding != 0)
		{
			throw new NotSupportedException("Padded bit strings are not supported.");
		}

		var result = ReadBytes(length - 1);
		return result;
	}

	public Oid ReadObjectIdentifier(Oid? expected = null)
	{
		ReadType(DerType.ObjectIdentifier);

		var length = ReadLength();
		var end = this.position + length;

		var values = new List<int>(length + 1);

		var first = ReadByte();
		values.Add(first / 40);
		values.Add(first % 40);

		int next = 0;
		while (this.position < end)
		{
			var b = ReadByte();
			if ((b & 0x80) != 0)
			{
				next = (next * 128) + (b & 0x7F);
			}
			else
			{
				next = (next * 128) + b;
				values.Add(next);
				next = 0;
			}
		}

		if (next != 0)
		{
			throw new InvalidOperationException("Invalid OID format.");
		}

		var value = string.Join(".", values);
		if (expected != null && value != expected.Value)
		{
			throw new InvalidOperationException(
				$"Expected OID {expected.Value}, found: {value}");
		}

		var result = new Oid(value);
		return result;
	}

	public DerReader ReadSequence()
	{
		var start = this.position;
		ReadType(DerType.Constructed | DerType.Sequence);

		var length = ReadLength();
		this.position += length;
		return new DerReader(this.buffer.Slice(start, this.position - start));
	}

	public bool TryReadTagged(int tagId, out DerReader taggedData)
	{
		if (this.position >= this.buffer.Count)
		{
			taggedData = default;
			return false;
		}

		var type = (DerType)this.buffer[this.position];
		if (!type.HasFlag(DerType.Tagged) ||
			(int)(type & ~DerType.Tagged) != tagId)
		{
			taggedData = default;
			return false;
		}

		var start = this.position;
		this.position++;
		var length = ReadLength();
		this.position += length;
		taggedData = new DerReader(this.buffer.Slice(start, this.position - start), type);
		return true;
	}

	/// <summary>
	/// Reads the type of the next value in the sequence WITHOUT advancing the reader position.
	/// </summary>
	public DerType Peek()
	{
		if (this.position >= this.buffer.Count)
		{
			throw new InvalidOperationException("Read out of bounds.");
		}

		return (DerType)this.buffer[this.position];
	}

	private byte ReadByte()
	{
		if (this.position >= this.buffer.Count)
		{
			throw new InvalidOperationException("Read out of bounds.");
		}

		return this.buffer[this.position++];
	}

	private Buffer ReadBytes(int length)
	{
		if (this.position + length > this.buffer.Count)
		{
			throw new InvalidOperationException("Read out of bounds.");
		}

		var result = this.buffer.Slice(this.position, length);
		this.position += length;
		return result;
	}

	private int ReadLength()
	{
		int length = ReadByte();

		if (length == 0x80)
		{
			throw new NotSupportedException("Indefinite-length encoding is not supported.");
		}

		if (length > 127)
		{
			var size = length & 0x7f;

			// Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
			if (size > 4)
			{
				throw new InvalidOperationException(
					$"DER length is {size} and cannot be more than 4 bytes.");
			}

			length = 0;
			for (var i = 0; i < size; i++)
			{
				int next = ReadByte();
				length = (length << 8) + next;
			}

			if (length < 0)
			{
				throw new InvalidOperationException("Corrupted data - negative length found");
			}
		}

		return length;
	}

	private void ReadType(DerType expectedType)
	{
		var type = (DerType)ReadByte();
		if (type != expectedType)
		{
			throw new InvalidOperationException($"Expected {expectedType} data type, found: {type}");
		}
	}

	public bool Equals(DerReader other) => this.buffer.Equals(other.buffer);

	public override bool Equals(object? obj) => obj is DerReader other && Equals(other);

	public override int GetHashCode() => this.buffer.GetHashCode();

	public static bool operator ==(DerReader left, DerReader right) => left.Equals(right);

	public static bool operator !=(DerReader left, DerReader right) => !(left == right);
}
