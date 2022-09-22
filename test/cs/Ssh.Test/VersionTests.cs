using System;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class VersionTests
{
	[Fact]
	public void GetLocalVersion()
	{
		var localVersion = SshVersionInfo.GetLocalVersion();
		Assert.Equal("2.0", localVersion.ProtocolVersion.ToString());
		var name = typeof(SshSession).Assembly.GetName().Name;
		Assert.Equal(name, localVersion.Name);
		Assert.NotNull(localVersion.Version);
	}

	[Fact]
	public void ParseVsSshCSVersion()
	{
		var name = typeof(SshSession).Assembly.GetName().Name;
		var test = $"SSH-2.0-{name}_3.0.0";
		Assert.True(SshVersionInfo.TryParse(test, out var result));
		Assert.Equal("2.0", result.ProtocolVersion.ToString());
		Assert.Equal(name, result.Name);
		Assert.Equal("3.0.0", result.Version?.ToString());
		Assert.Equal(test, result.ToString());
	}

	[Fact]
	public void ParseVsSSHTSVersion()
	{
		var test = "SSH-2.0-dev-tunnels-ssh_3.0.0";
		Assert.True(SshVersionInfo.TryParse(test, out var result));
		Assert.Equal("2.0", result.ProtocolVersion.ToString());
		Assert.Equal("3.0.0", result.Version?.ToString());
		Assert.Equal(test, result.ToString());
	}

	[Fact]
	public void ParseOpenSshVersion()
	{
		var test = "SSH-2.0-OpenSSH_7.7.7";
		Assert.True(SshVersionInfo.TryParse(test, out var result));
		Assert.Equal("2.0", result.ProtocolVersion.ToString());
		Assert.Equal("OpenSSH", result.Name);
		Assert.Equal("7.7.7", result.Version?.ToString());
		Assert.Equal(test, result.ToString());
	}

	[Fact]
	public void ParseOpenSshForWindowsVersion()
	{
		var test = "SSH-2.0-OpenSSH_for_Windows_7.7.7";
		Assert.True(SshVersionInfo.TryParse(test, out var result));
		Assert.Equal("2.0", result.ProtocolVersion.ToString());
		Assert.Equal("OpenSSH for Windows", result.Name);
		Assert.Equal("7.7.7", result.Version?.ToString());
		Assert.Equal(test, result.ToString());
	}

	[Fact]
	public void ParseOpenSshVersionWithExtraInfo()
	{
		var test = "SSH-2.0-OpenSSH_7.7.7x1 extra";
		Assert.True(SshVersionInfo.TryParse(test, out var result));
		Assert.Equal("2.0", result.ProtocolVersion.ToString());
		Assert.Equal("OpenSSH", result.Name);
		Assert.Equal("7.7.7", result.Version?.ToString());
		Assert.Equal(test, result.ToString());
	}

	[Fact]
	public void ParseWithNoSoftwareVersion()
	{
		var test = "SSH-2.0-test_extra";
		Assert.True(SshVersionInfo.TryParse(test, out var result));
		Assert.Equal("2.0", result.ProtocolVersion.ToString());
		Assert.Equal("test", result.Name);
		Assert.Null(result.Version);
		Assert.Equal(test, result.ToString());
	}
}
