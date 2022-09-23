// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;

#pragma warning disable CA1720 // Identifier contains type name "unsigned"

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Represents a large signed integer as a byte array.
/// </summary>
/// <remarks>
/// This has two significant advantages for SSH compared to System.Numerics.BigInteger:
///   - The byte order is big-endian (whereas S.N.BI is little-endian), avoiding lots of
///     unnecessary byte-swapping.
///   - The bytes are a slice of an array (a <see cref="Buffer" />), so less copying is required.
/// This class does not provide all the math operations that S.N.BI does. If necessary for math
/// or other purposes it can be converted to/from S.N.BI using the casting operators.
/// </remarks>
[DebuggerDisplay("{ToString(),nq}")]
public struct BigInt : IEquatable<BigInt>
{
	public static BigInt Zero { get; } = new BigInt(new Buffer(1));

	private readonly Buffer buffer;

	/// <summary>
	/// Creates a new BigInt instance from a buffer of signed bytes.
	/// </summary>
	/// <remarks>
	/// The first (high) bit of the first (high) byte is the sign bit. Therefore if the
	/// highest byte of an unsigned integer is greater than 127, the bytes must include
	/// a leading zero byte to prevent interpretation as a negative value.
	/// </remarks>
	public BigInt(Buffer buffer)
	{
		if (buffer.Count == 0)
		{
			throw new ArgumentException(
				"BigInt buffer length must be greater than zero.", nameof(buffer));
		}

		this.buffer = buffer;
	}

	/// <summary>
	/// Gets a value that indicates the sign of the big integer:
	/// 1 for positive, 0 for zero, -1 for negative.
	/// </summary>
	public int Sign
	{
		get
		{
			byte highByte = this.buffer[0];
			if (highByte == 0)
			{
				return this.buffer.Count > 1 ? 1 : 0;
			}
			else
			{
				return (highByte & 0x80) == 0 ? 1 : -1;
			}
		}
	}

	public static BigInt FromInt32(int value)
	{
		if (value == 0)
		{
			return BigInt.Zero;
		}

		bool isNegative = false;
		if (value < 0)
		{
			isNegative = true;
			value = -value;
		}

		var bytes = new List<byte>(4);

		for (var bit = 24; bit >= 0; bit -= 8)
		{
			if (value >= 1 << bit || bytes.Count > 0)
			{
				bytes.Add((byte)(value >> bit));
				value = value & ~(1 << bit);
			}
		}

		if (isNegative)
		{
			if ((bytes[0] & 0x80) == 0)
			{
				bytes[0] |= 0x80;
			}
			else
			{
				bytes.Insert(0, 0x80);
			}
		}

		return new BigInt(bytes.ToArray());
	}

	/// <summary>
	/// Converts a BigInt to a 32-bit signed integer.
	/// </summary>
	/// <exception cref="OverflowException">The value is out of range.</exception>
	public int ToInt32()
	{
		if (this.buffer.Count > 4)
		{
			throw new OverflowException(
				$"{nameof(BigInt)} value cannot be converted to a 32-bit signed integer.");
		}

		int value = this.buffer[0];
		if (Sign < 0)
		{
			value &= 0x7F;
		}

		for (int i = 1; i < this.buffer.Count; i++)
		{
			value = (value << 8) + this.buffer[i];
		}

		if (Sign < 0)
		{
			value = -value;
		}

		return value;
	}

	/// <summary>
	/// Creates a new BigInt instance from a byte array.
	/// </summary>
	/// <param name="bytes">Source byte array.</param>
	/// <param name="unsigned">True if the bytes should be interpreted as unsigned. If false,
	/// the high bit of the high byte is the sign bit.</param>
	/// <param name="littleEndian">True if the bytes are in little-endian order
	/// (and therefore need to be swapped).</param>
	public static BigInt FromByteArray(
		byte[] bytes,
		bool unsigned = false,
		bool littleEndian = false)
	{
		if (bytes == null)
		{
			throw new ArgumentNullException(nameof(bytes));
		}
		else if (bytes.Length == 0)
		{
			throw new ArgumentException(
				"BigInt byte array length must be greater than zero.", nameof(bytes));
		}

		byte highByte = bytes[littleEndian ? bytes.Length - 1 : 0];
		bool highBit = (highByte & 0x80) != 0;
		int prependZeroCount = unsigned && highBit ? 1 : 0;
		int skipZeroCount = 0;

		byte[] newBytes;
		if (littleEndian)
		{
			// Skip non-significant zeroes at the big end.
			for (int i = bytes.Length - 1; i > 0 && bytes[i] == 0; i--)
			{
				if ((bytes[i - 1] & 0x80) == 0)
				{
					skipZeroCount++;
				}
			}

			newBytes = new byte[bytes.Length + prependZeroCount - skipZeroCount];
			Array.Copy(bytes, 0, newBytes, prependZeroCount, bytes.Length - skipZeroCount);
			SwapByteOrder(newBytes, prependZeroCount, bytes.Length - skipZeroCount);
		}
		else
		{
			// Skip non-significant zeroes at the big end.
			for (int i = 0; i < bytes.Length - 1 && bytes[i] == 0; i++)
			{
				if ((bytes[i + 1] & 0x80) == 0)
				{
					skipZeroCount++;
				}
			}

			newBytes = new byte[bytes.Length + prependZeroCount - skipZeroCount];
			Array.Copy(
				bytes,
				littleEndian ? 0 : skipZeroCount,
				newBytes,
				littleEndian ? 0 : prependZeroCount,
				bytes.Length - skipZeroCount);
		}

#if DEBUG
		Buffer.TrackAllocation(newBytes.Length);
		Buffer.TrackCopy(bytes.Length - skipZeroCount);
#endif

		return new BigInt(newBytes);
	}

	/// <summary>
	/// Converts a BigInt instance to a byte buffer.
	/// </summary>
	/// <param name="unsigned">True if the returned bytes will be interprted as unsigned.
	/// If false, a positive integer may have a leading zero to prevent it from being
	/// interpreted as negative.</param>
	/// <param name="length">Desired length of the resulting buffer. The value will be zero-
	/// padded to fill the length. Only applies when unsigned is true.</param>
	/// <remarks>The returned buffer is a reference to the internal bytes, not a copy.</remarks>
	/// <exception cref="OverflowException">A length was specified that was too small to
	/// hold the value.</exception>
	public Buffer ToBuffer(bool unsigned = false, int length = -1)
	{
		if (length > 0 && !unsigned)
		{
			throw new ArgumentException("Length can only be specified with unsigned.");
		}

		if (!unsigned)
		{
			return this.buffer;
		}
		else if (Sign < 0)
		{
			throw new InvalidOperationException("Cannot format a negative BigInt as unsigned.");
		}
		else
		{
			var result = this.buffer;
			if (result[0] == 0 && result.Count > 1 && result.Count != length)
			{
				result = result.Slice(1, this.buffer.Count - 1);
			}

			if (length > 0)
			{
				if (result.Count > length)
				{
					throw new OverflowException(
						$"{nameof(BigInt)} ({result.Count} bytes) is too large for length {length}.");
				}
				else if (result.Count < length)
				{
					var padded = new Buffer(length);
					result.CopyTo(padded, length - result.Count);
					result = padded;
				}
			}

			return result;
		}
	}

	/// <summary>
	/// Converts a BigInt instance to an array of bytes.
	/// </summary>
	/// <param name="unsigned">True if the returned bytes will be interprted as unsigned.
	/// If false, a positive integer may have a leading zero to prevent it from being
	/// interpreted as negative.</param>
	/// <param name="length">Desired length of the resulting buffer. The value will be zero-
	/// padded to fill the length.</param>
	/// <param name="littleEndian">True if the returned bytes should be swapped to
	/// little-endian order.</param>
	/// <remarks>The returned array is a copy of the internal bytes, not a reference.</remarks>
	public byte[] ToByteArray(
		bool unsigned = false,
		int length = -1,
		bool littleEndian = false)
	{
		var bytes = this.ToBuffer(unsigned, length);
		byte[] newBytes = bytes.ToArray(); // This makes a copy of the bytes.

		if (littleEndian)
		{
			SwapByteOrder(newBytes);
		}

		return newBytes;
	}

	public override bool Equals(object? obj)
	{
		return obj is BigInt otherInt && Equals(otherInt);
	}

	/// <summary>
	/// Performs a comparison between two big integers in length-constant time.
	/// </summary>
	public bool Equals(BigInt other)
	{
		return this.buffer.Equals(other.buffer);
	}

	public static bool operator ==(BigInt left, BigInt right)
	{
		return left.Equals(right);
	}

	public static bool operator !=(BigInt left, BigInt right)
	{
		return !(left == right);
	}

	public override int GetHashCode()
	{
		return this.buffer.GetHashCode();
	}

	public override string ToString()
	{
		return this.buffer.ToString(nameof(BigInt));
	}

	public string ToString(string name)
	{
		return this.buffer.ToString(name);
	}

#pragma warning disable CA2225 // Operator overloads have named alternates
	public static explicit operator BigInteger(BigInt value)
	{
		var bytes = value.buffer.Copy().ToArray();
		SwapByteOrder(bytes);
		return new BigInteger(bytes);
	}

	public static explicit operator BigInt(BigInteger value)
	{
		var bytes = value.ToByteArray();
		SwapByteOrder(bytes);
		return new BigInt(bytes);
	}
#pragma warning restore CA2225 // Operator overloads have named alternates

	private static void SwapByteOrder(byte[] bytes, int offset = 0, int count = -1)
	{
		if (count < 0)
		{
			count = bytes.Length - offset;
		}

		int start = offset;
		int end = start + count - 1;
		while (start < end)
		{
			var temp = bytes[end];
			bytes[end] = bytes[start];
			bytes[start] = temp;
			start++;
			end--;
		}
	}
}
