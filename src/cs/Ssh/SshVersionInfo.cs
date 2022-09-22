// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Linq;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Parses the SSH software name and version from the version string exchanged via the
/// initial packets sent between client and server.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
public class SshVersionInfo
{
	/// <summary>
	/// Attempts to parse an SSH version string into a version info object.
	/// </summary>
	public static bool TryParse(string versionString, out SshVersionInfo versionInfo)
	{
		if (versionString == null) throw new ArgumentNullException(nameof(versionString));

		var versionParts = versionString.Split(new[] { '-' }, 3);
		if (versionParts.Length != 3 || versionParts[0] != "SSH")
		{
			versionInfo = null!;
			return false;
		}

		if (!Version.TryParse(versionParts[1], out var protocolVersion))
		{
			versionInfo = null!;
			return false;
		}

		string name;
		Version? version;

		var nameAndVersion = versionParts[2];
#pragma warning disable CA1307 // Specify StringComparison
		var spaceIndex = nameAndVersion.IndexOf(' ');
#pragma warning restore CA1307 // Specify StringComparison
		var lastUnderscoreBeforeSpace = nameAndVersion.LastIndexOf(
			'_', spaceIndex >= 0 ? spaceIndex : nameAndVersion.Length - 1);

		if (lastUnderscoreBeforeSpace >= 0)
		{
			name = nameAndVersion.Substring(0, lastUnderscoreBeforeSpace).Replace('_', ' ');

			// Ignore any non-digit characters after the version.
			var versionNumbers = nameAndVersion.Substring(lastUnderscoreBeforeSpace + 1);
			for (int i = 0; i < versionNumbers.Length; i++)
			{
				if (!char.IsDigit(versionNumbers[i]) && versionNumbers[i] != '.')
				{
					versionNumbers = versionNumbers.Substring(0, i);
					break;
				}
			}

			if (!Version.TryParse(versionNumbers, out version))
			{
				version = null;
			}
		}
		else
		{
			name = nameAndVersion;
			version = null;
		}

		versionInfo = new SshVersionInfo(versionString, protocolVersion, name, version);
		return true;
	}

	/// <summary>
	/// Gets the version info for the current SSH library.
	/// </summary>
	public static SshVersionInfo GetLocalVersion()
	{
		var assembly = typeof(SshSession).Assembly;
		var assemblyName = assembly.GetName().Name!;
		var assemblyVersion = assembly.GetName().Version!;
		assemblyVersion = new Version(assemblyVersion.Major, assemblyVersion.Minor);

		var protocolVersion = new Version(2, 0);
		var versionString = $"SSH-{protocolVersion}-{assemblyName}_{assemblyVersion}";
		return new SshVersionInfo(versionString, protocolVersion, assemblyName, assemblyVersion);
	}

	private SshVersionInfo(
		string versionString,
		Version protocolVersion,
		string name,
		Version? version)
	{
		VersionString = versionString;
		ProtocolVersion = protocolVersion;
		Name = name;
		Version = version;
	}

	private string VersionString { get; }

	/// <summary>
	/// Gets the SSH protocol version, currently always "2.0".
	/// </summary>
	public Version ProtocolVersion { get; }

	/// <summary>
	/// Gets the name of the SSH application or library.
	/// </summary>
	public string Name { get; }

	/// <summary>
	/// Gets the version of the SSH application or library.
	/// </summary>
	public Version? Version { get; }

	/// <summary>
	/// Returns the original SSH version string that was parsed.
	/// </summary>
	public override string ToString() => VersionString;

	/// <summary>
	/// Gets a value indicating whether this version info represents some version of
	/// this library.
	/// </summary>
	public bool IsVsSsh => IsVsSshCS || IsVsSshTS;

	private bool IsVsSshCS => Name == "Microsoft.VisualStudio.Ssh" || Name == "Microsoft.DevTunnels.Ssh";

	private bool IsVsSshTS => Name == "vs-ssh" || Name == "dev-tunnels-ssh";
}
