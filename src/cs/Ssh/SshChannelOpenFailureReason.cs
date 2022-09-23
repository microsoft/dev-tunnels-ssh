// Copyright (c) Microsoft. All rights reserved.

using System.ComponentModel;

namespace Microsoft.DevTunnels.Ssh.Messages;

public enum SshChannelOpenFailureReason
{
	[EditorBrowsable(EditorBrowsableState.Never)]
	None = 0, // Not used by protocol
	AdministrativelyProhibited = 1,
	ConnectFailed = 2,
	UnknownChannelType = 3,
	ResourceShortage = 4,
}
