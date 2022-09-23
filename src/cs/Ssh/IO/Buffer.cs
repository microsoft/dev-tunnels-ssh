// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;

#pragma warning disable CA1710 // Rename 'Buffer' to end in 'Collection'

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Represents a segment of a byte array.
/// </summary>
/// <remarks>
/// This structure is similar to ArraySegment&lt;byte&gt;, with several additional
/// conveniences.
/// </remarks>
[DebuggerDisplay("{ToString(),nq}")]
public struct Buffer : IEquatable<Buffer>, ICollection<byte>
{
	private static readonly byte[] EmptyArray = System.Array.Empty<byte>();
	public static readonly Buffer Empty = default;

	private readonly byte[] array;

	private Buffer(byte[] array, int offset, int count)
	{
		this.array = array;
		this.Offset = offset;
		this.Count = count;
	}

	public Buffer(int size) : this(new byte[size], 0, size)
	{
#if DEBUG
		TrackAllocation(size);
#endif
	}

	public static Buffer From(byte[] array) => From(array, 0, array?.Length ?? 0);

	public static Buffer From(byte[] array, int offset, int count)
	{
		if (array == null)
		{
			throw new ArgumentNullException(nameof(array));
		}

		if (offset < 0 || offset > array.Length)
		{
			throw new ArgumentOutOfRangeException(nameof(offset));
		}

		if (count < 0 || offset + count > array.Length)
		{
			throw new ArgumentOutOfRangeException(nameof(count));
		}

		return new Buffer(array, offset, count);
	}

	public static Buffer FromBase64(string base64)
	{
		var bytes = Convert.FromBase64String(base64);
		return new Buffer(bytes, 0, bytes.Length);
	}

#pragma warning disable CA1819 // Properties should not return arrays
	public byte[] Array => this.array ?? EmptyArray;
#pragma warning restore CA1819 // Properties should not return arrays

	public int Offset { get; }
	public int Count { get; }

	bool ICollection<byte>.IsReadOnly => false;

	public byte this[int index]
	{
		get => Array[Offset + index];
		set => Array[Offset + index] = value;
	}

	public Buffer Slice(int offset, int count)
	{
		if (offset + count > Count)
		{
			throw new ArgumentOutOfRangeException(
				nameof(count), "Slice is outside the bounds of the buffer.");
		}

		return new Buffer(Array, Offset + offset, count);
	}

	public void CopyTo(Buffer other, int otherOffset = 0)
	{
		if (other.Count - otherOffset < Count)
		{
			throw new ArgumentException("Destination buffer is too small.", nameof(other));
		}

		System.Array.Copy(Array, Offset, other.Array, other.Offset + otherOffset, Count);

#if DEBUG
		TrackCopy(Count);
#endif
	}

	public Buffer Copy()
	{
		var newBuffer = new Buffer(Count);
		CopyTo(newBuffer);
		return newBuffer;
	}

	/// <summary>
	/// Gets the buffer data as a byte array. If the buffer does not cover the whole array,
	/// this may be a copy of the buffer's array segment.
	/// </summary>
	public byte[] ToArray()
	{
		if (this.Offset == 0 && this.Count == this.Array.Length)
		{
			return Array;
		}

		return Copy().Array;
	}

#if SSH_ENABLE_SPAN
#pragma warning disable CA2225 // Operator overloads have named alternates

	public Span<byte> Span => new Span<byte>(Array, Offset, Count);

	public Memory<byte> Memory => new Memory<byte>(Array, Offset, Count);

	public static implicit operator Span<byte>(Buffer buffer) => buffer.Span;

	public static implicit operator Memory<byte>(Buffer buffer) => buffer.Memory;

#pragma warning restore CA2225 // Operator overloads have named alternates
#endif

	public static implicit operator Buffer(byte[] array)
	{
		return Buffer.From(array ?? System.Array.Empty<byte>());
	}

	public override bool Equals(object? obj)
	{
		return obj is Buffer otherBuffer && Equals(otherBuffer);
	}

	/// <summary>
	/// Performs a comparison between two buffers in length-constant time.
	/// </summary>
	/// <remarks>
	/// Prevents timing attacks by always comparing the whole sequence even when the answer
	/// could have been determined after only comparing a portion of the sequence.
	/// </remarks>
	public bool Equals(Buffer other)
	{
		if (Count != other.Count)
		{
			// Buffers are different sizes.
			return false;
		}

		if (Array == other.Array && Offset == other.Offset)
		{
			// A buffer instance is being compared to itself.
			return true;
		}

		bool equal = true;
		int end = Count + Offset;
		for (int i = Offset, j = other.Offset; i < end; i++, j++)
		{
			equal &= (Array[i] == other.Array[j]);
		}

		return equal;
	}

	public static bool operator ==(Buffer left, Buffer right)
	{
		return left.Equals(right);
	}

	public static bool operator !=(Buffer left, Buffer right)
	{
		return !(left == right);
	}

	public override int GetHashCode()
	{
		return new ArraySegment<byte>(Array, Offset, Count).GetHashCode();
	}

	void ICollection<byte>.Add(byte item) => throw new NotSupportedException();

	bool ICollection<byte>.Remove(byte item) => throw new NotSupportedException();

	void ICollection<byte>.Clear() => throw new NotSupportedException();

	bool ICollection<byte>.Contains(byte item)
	{
		return Array.Skip(Offset).Take(Count).Contains(item);
	}

	void ICollection<byte>.CopyTo(byte[] array, int arrayIndex)
	{
		System.Array.Copy(Array, Offset, array, arrayIndex, Count);

#if DEBUG
		TrackCopy(Count);
#endif
	}

	public IEnumerator<byte> GetEnumerator()
	{
		return Array.Skip(Offset).Take(Count).GetEnumerator();
	}

	IEnumerator IEnumerable.GetEnumerator()
	{
		return GetEnumerator();
	}

	public static void Expand(ref Buffer buffer, int minimumSize)
	{
		const int maxSize = 1 << 20; // 1 MB

		if (buffer.Count < minimumSize)
		{
			int newSize = Math.Max(512, buffer.Count * 2);
			while (newSize < minimumSize)
			{
				newSize *= 2;
			}

			if (newSize > maxSize)
			{
				throw new SshConnectionException(
					"Exceeded buffer size limit.", SshDisconnectReason.ProtocolError);
			}

			var newBuffer = new Buffer(newSize);
			buffer.CopyTo(newBuffer);
			buffer = newBuffer;
		}
	}

	public static Buffer Concat(Buffer left, Buffer right)
	{
		if (left.Count == 0) return right;
		if (right.Count == 0) return left;

		var result = new Buffer(left.Count + right.Count);
		left.CopyTo(result, 0);
		right.CopyTo(result, left.Count);
		return result;
	}

#pragma warning disable CA2225 // Operator overloads have named alternates ("Concat" instead of "Add")
	public static Buffer operator +(Buffer left, Buffer right) => Buffer.Concat(left, right);
#pragma warning restore CA2225 // Operator overloads have named alternates

	public void Clear()
	{
		System.Array.Clear(Array, Offset, Count);
	}

	public string ToBase64()
	{
		return Convert.ToBase64String(Array, Offset, Count);
	}

	/// <summary>
	/// Formats a byte buffer using the same format as OpenSSH,
	/// useful for debugging and comparison in logs.
	/// </summary>
	public override string ToString()
	{
		return ToString(nameof(Buffer));
	}

	private static uint[] MakeCrcTable()
	{
		uint c;
		var table = new uint[256];
		for (uint n = 0; n < 256; n++)
		{
			c = n;
			for (uint k = 0; k < 8; k++)
			{
				c = (uint)((c & 1) != 0 ? 0xedb88320 ^ (c >> 1) : c >> 1);
			}

			table[n] = c;
		}

		return table;
	}

	private static uint[]? crcTable;

	private static string Crc32(Buffer data)
	{
		if (crcTable == null)
		{
			crcTable = MakeCrcTable();
		}

		uint crc = uint.MaxValue;
		for (int i = 0; i < data.Count; i++)
		{
			crc = (crc >> 8) ^ crcTable[(crc ^ data[i]) & 0xff];
		}

		var result = (crc ^ -1) >> 0 & 0xFFFFFFFF;
		return result.ToString("X8", CultureInfo.InvariantCulture);
	}

	public string ToString(string name)
	{
		var s = new StringBuilder();
		s.AppendFormat(CultureInfo.InvariantCulture, "{0}[{1}] ({2})", name, Count, Crc32(this));
		s.AppendLine();

		int max = Math.Min(4096, Count);

		for (int lineOffset = 0; lineOffset < max; lineOffset += 16)
		{
			s.AppendFormat(CultureInfo.InvariantCulture, "{0:d4}:", lineOffset);

			for (int i = lineOffset; i < lineOffset + 16; i++)
			{
				if (i < max)
				{
					s.AppendFormat(CultureInfo.InvariantCulture, " {0:x2}", this[i]);
				}
				else
				{
					s.Append("   ");
				}
			}

			s.Append("  ");
			for (int i = lineOffset; i < lineOffset + 16; i++)
			{
				if (i < max)
				{
					char c = (char)this[i];
					s.Append(c > ' ' && c <= (char)127 ? c : '.');
				}
				else
				{
					s.Append(' ');
				}
			}

			s.AppendLine();
		}

		if (max < Count)
		{
			s.AppendLine("...");
		}

		return s.ToString();
	}

#if DEBUG
	/// <summary>
	/// Track byte buffer allocations in DEBUG mode.
	/// </summary>
	internal static void TrackAllocation(int size)
	{
		var location = GetStackTraceSummary(new StackTrace(2, true));
		lock (Allocations)
		{
			if (!Allocations.TryGetValue(location, out var allocationsList))
			{
				allocationsList = new List<int>();
				Allocations.Add(location, allocationsList);
			}

			allocationsList.Add(size);
		}
	}

	/// <summary>
	/// Track byte buffer copy operations in DEBUG mode.
	/// </summary>
	internal static void TrackCopy(int size)
	{
		if (size == 0)
		{
			return;
		}

		var location = GetStackTraceSummary(new StackTrace(2, true));
		lock (Copies)
		{
			if (!Copies.TryGetValue(location, out var copiesList))
			{
				copiesList = new List<int>();
				Copies.Add(location, copiesList);
			}

			copiesList.Add(size);
		}
	}

	private static string GetStackTraceSummary(StackTrace stackTrace)
	{
		var frameList = new List<string>();

		for (int i = 0; i < stackTrace.FrameCount && frameList.Count < 3; i++)
		{
			var stackFrame = stackTrace.GetFrame(i)!;
			var method = stackFrame.GetMethod();
			var declaringType = method?.DeclaringType;
			if (declaringType == null) continue;

			string? fileName = stackFrame.GetFileName();
			fileName = fileName != null ? System.IO.Path.GetFileName(fileName) : null;
			if (fileName != "Buffer.cs" && method!.Name != "MoveNext" &&
				!declaringType.Name.StartsWith("Async", StringComparison.Ordinal))
			{
				var methodName = declaringType.Name + '.' + method.Name + "()";
				frameList.Add(string.Format(
					CultureInfo.InvariantCulture,
					" {0}@{1}:{2}",
					methodName,
					fileName,
					stackFrame.GetFileLineNumber()));
			}
		}

		return string.Join(" ", frameList);
	}

	/// <summary>
	/// Tracks all allocations of byte buffers.
	/// </summary>
	/// <remarks>
	/// Each entry key is a summary of the stack trace where the allocation occurrred; the
	/// value is a list of allocation sizes that occurred there. To restart allocation tracking,
	/// clear the dictionary. Be sure to lock on it if it might be used concurrently.
	/// </remarks>
	public static System.Collections.Generic.Dictionary<string, List<int>> Allocations { get; }
		= new Dictionary<string, List<int>>();

	/// <summary>
	/// Tracks all copy operations of byte buffers.
	/// </summary>
	/// <remarks>
	/// Each entry key is a summary of the stack trace where the copy occurrred; the
	/// value is a list of copy sizes that occurred there. To restart copy tracking,
	/// clear the dictionary. Be sure to lock on it if it might be used concurrently.
	/// </remarks>
	public static System.Collections.Generic.Dictionary<string, List<int>> Copies { get; }
		= new Dictionary<string, List<int>>();
#endif
}
