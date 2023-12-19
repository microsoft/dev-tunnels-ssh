// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Defines the connection progress events that are reported.
/// </summary>
public enum Progress
{
	// Client connection to relay
	OpeningClientConnectionToRelay,
	OpenedClientConnectionToRelay,

	// Host connection to relay
	OpeningHostConnectionToRelay,
	OpenedHostConnectionToRelay,

	// SSH Session Connection
	OpeningSshSessionConnection,
	OpenedSshSessionConnection,
	StartingProtocolVersionExchange,
	CompletedProtocolVersionExchange,
	StartingKeyExchange,
	CompletedKeyExchange,
	StartingSessionAuthentication,
	CompletedSessionAuthentication,
}
