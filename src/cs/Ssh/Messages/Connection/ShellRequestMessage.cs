// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Messages;

public class ShellRequestMessage : ChannelRequestMessage
{
	public ShellRequestMessage()
	{
		RequestType = ChannelRequestTypes.Shell;
	}
}
