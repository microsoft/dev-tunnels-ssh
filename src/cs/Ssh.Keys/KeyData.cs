// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Encapsulates formatted (serialized) key data and metadata.
/// </summary>
public class KeyData
{
	private int hyphenCount;
	private bool quoteHeaders;
	private int lineLength;

	internal KeyData(
		int hyphenCount = 5,
		bool quoteHeaders = false,
		int lineLength = 64)
	{
		this.hyphenCount = hyphenCount;
		this.quoteHeaders = quoteHeaders;
		this.lineLength = lineLength;
	}

	/// <summary>
	/// Gets or sets the key type; the use depends on the encoding.
	/// </summary>
	/// <remarks>
	/// In PEM encoding, the key type is part of the BEGIN and END markers. For example in
	/// "-----BEGIN RSA PUBLIC KEY-----" the key type is "RSA PUBLIC KEY".
	/// </remarks>
	public string KeyType { get; set; } = string.Empty;

#pragma warning disable CA2227 // Collection properties should be read only
	/// <summary>
	/// Gets or sets a dictionary of headers containing key metadata.
	/// </summary>
	/// <remarks>
	/// In PEM encoding, the headers appear in plaintext before the base64-encoded key.
	/// </remarks>
	public IDictionary<string, string> Headers { get; set; }
		= new Dictionary<string, string>();
#pragma warning restore CA2227 // Collection properties should be read only

#pragma warning disable CA1819 // Properties should not return arrays
	/// <summary>
	/// Gets or sets the formatted key bytes.
	/// </summary>
	public byte[] Data { get; set; } = Array.Empty<byte>();
#pragma warning restore CA1819 // Properties should not return arrays

	private static readonly Regex PemRegex = new Regex(
		@"^-+ *BEGIN (?<name>\w+( \w+)*) *-+\r?\n" +
		@"((?<header>[-_\w]+: [^\n]+(\\\r\n[^\n]+)*(\r?\n)*)*)?" +
		@"(?<data>([a-zA-Z0-9/+=]{1,80}\r?\n)+)-+ *END \k<name> *-+",
		RegexOptions.Multiline);

	public static bool TryDecodePem(string input, out KeyData result)
	{
		Match match = PemRegex.Match(input);
		if (!match.Success)
		{
			result = null!;
			return false;
		}

		string name = match.Groups["name"].Value;
		var headers = match.Groups["header"].Captures
			.Cast<Capture>()
			.Select((c) => ParsePemHeader(c.Value))
			.ToDictionary((kv) => kv.Key, (kv) => kv.Value, StringComparer.OrdinalIgnoreCase);
		string base64Data = match.Groups["data"].Value;

		byte[] data;
		try
		{
			data = Convert.FromBase64String(base64Data);
		}
		catch (FormatException)
		{
			result = null!;
			return false!;
		}

		result = new KeyData
		{
			KeyType = name,
			Headers = headers,
			Data = data,
		};
		return true;
	}

	internal static bool TryDecodePemBytes(byte[] input, out KeyData result)
	{
		if (input.Length < 3 || input[0] != '-' || input[1] != '-' || input[2] != '-')
		{
			result = null!;
			return false;
		}

		string inputString;
		try
		{
			inputString = Encoding.UTF8.GetString(input);
		}
		catch (ArgumentException)
		{
			result = null!;
			return false;
		}

		return TryDecodePem(inputString, out result);
	}

	public string EncodePem()
	{
		var hyphens = new string('-', this.hyphenCount);
		var separator = (this.hyphenCount < 5 ? " " : string.Empty);
		var quote = (this.quoteHeaders ? "\"" : string.Empty);

		var s = new StringBuilder();
#pragma warning disable SA1114 // Parameter list should follow declaration
		s.AppendLine(
#if NET6_0
			CultureInfo.InvariantCulture,
#endif
			$"{hyphens}{separator}BEGIN {KeyType}{separator}{hyphens}");

		foreach (var header in Headers)
		{
			// TODO: Wrap the value with \ if it's long.
			s.AppendLine(
#if NET6_0
				CultureInfo.InvariantCulture,
#endif

				$"{header.Key}: {quote}{header.Value}{quote}");
		}

		var dataBase64 = Convert.ToBase64String(Data);

		for (int offset = 0; offset < dataBase64.Length; offset += this.lineLength)
		{
			s.AppendLine(dataBase64.Substring(
				offset, Math.Min(this.lineLength, dataBase64.Length - offset)));
		}

		s.AppendLine(
#if NET6_0
			CultureInfo.InvariantCulture,
#endif
			$"{hyphens}{separator}END {KeyType}{separator}{hyphens}");
#pragma warning restore SA1114 // Parameter list should follow declaration

		return s.ToString();
	}

	internal byte[] EncodePemBytes()
	{
		return Encoding.UTF8.GetBytes(EncodePem());
	}

	internal string EncodeSshPublicKey()
	{
		return KeyType + " " + Convert.ToBase64String(Data) +
			(Headers.TryGetValue("Comment", out string? comment) ? " " + comment : string.Empty) +
			Environment.NewLine;
	}

	internal byte[] EncodeSshPublicKeyBytes()
	{
		return Encoding.UTF8.GetBytes(EncodeSshPublicKey());
	}

	private static KeyValuePair<string, string> ParsePemHeader(string header)
	{
#if NETSTANDARD2_0 || NET4
		header = header.Replace("\r", string.Empty).Replace("\\\n", string.Empty).TrimEnd('\n');
#else
		header = header.Replace("\r", string.Empty, StringComparison.Ordinal)
			.Replace("\\\n", string.Empty, StringComparison.Ordinal).TrimEnd('\n');
#endif

		string key = header;
		string value = string.Empty;

		var delimterIndex = header.IndexOf(": ", StringComparison.Ordinal);
		if (delimterIndex > 0)
		{
			key = header.Substring(0, delimterIndex);
			value = header.Substring(delimterIndex + 2);

			if (value.Length >= 2 && value[0] == '"' && value[value.Length - 1] == '"')
			{
				value = value.Substring(1, value.Length - 2);
			}
		}

		return new KeyValuePair<string, string>(key, value);
	}
}
