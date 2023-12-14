//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * Connection progress
 */
export enum Progress {
	// Client connection to relay
	OpeningClientConnectionToRelay = "OpeningClientConnectionToRelay",
	OpenedClientConnectionToRelay = "OpenedClientConnectionToRelay",

	// Host connection to relay
	OpeningHostConnectionToRelay = "OpeningHostConnectionToRelay",
	OpenedHostConnectionToRelay = "OpenedHostConnectionToRelay",

	// SSH Session Connection
	OpeningSshSessionConnection = "OpeningSshSessionConnection",
	OpenedSshSessionConnection = "OpenedSshSessionConnection",
	SendingProtocolVersionExchange = "SendingProtocolVersionExchange",
	ReceivingProtocolVersionExchange = "ReceivingProtocolVersionExchange",
	StartingKeyExchange = "StartingKeyExchange",
	CompletedKeyExchange = "CompletedKeyExchange",
	StartingSessionAuthentication = "StartingSessionAuthentication",
	CompletedSessionAuthentication = "CompletedSessionAuthentication",

	// Port forwarding messages
	StartingPortForwarding = "StartingPortForwarding",
	CompletedLocalPortForwarding = "CompletedLocalPortForwarding",
	CompletedRemotePortForwarding = "CompletedRemotePortForwarding",
	OpeningChannelPortForwarding = "OpeningChannelPortForwarding",
	OpenedChannelPortForwarding = "OpenedChannelPortForwarding",
	StartingWaitForForwardedPort = "StartingWaitForForwardedPort",
	CompletedWaitForForwardedPort = "CompletedWaitForForwardedPort",

	// Channel opening messages
	StartingOpenChannel = "StartingOpenChannel",
	CompletedOpenChannel = "CompletedOpenChannel",
}
