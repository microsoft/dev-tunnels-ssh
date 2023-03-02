// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Defines the protocol extensions supported by this implementation.
/// </summary>
/// <remarks>
/// Strings with @ are not email addresses; they are namespaced private extensions.
/// Reference https://tools.ietf.org/html/rfc4250#section-4.6.1
/// </remarks>
public static class SshProtocolExtensionNames
{
	/// <summary>
	/// Lists host key signature algorithms enabled by the sender.
	/// </summary>
	/// <remarks>
	/// This is a "standard" protocol extension supported by most SSH implementations.
	/// </remarks>
	public const string ServerSignatureAlgorithms = "server-sig-algs";

	/// <summary>
	/// An optimization that enables sending an initial channel request without
	/// waiting for a channel open confirmation message.
	/// </summary>
	public const string OpenChannelRequest = "open-channel-request@microsoft.com";

	/// <summary>
	/// Enables reconnecting to a session that was recently disconnected.
	/// </summary>
	public const string SessionReconnect = "session-reconnect@microsoft.com";

	/// <summary>
	/// Enables continual latency measurements between client and server.
	/// </summary>
	/// <remarks>
	/// This extension requires that the reconnect extension is also enabled, because
	/// it leverages some of the session history info for reconnect to compute latency.
	/// </remarks>
	public const string SessionLatency = "session-latency@microsoft.com";
}
