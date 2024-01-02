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

	// SSH session connection
	OpeningSshSessionConnection = "OpeningSshSessionConnection",
	OpenedSshSessionConnection = "OpenedSshSessionConnection",
	StartingProtocolVersionExchange = "StartingProtocolVersionExchange",
	CompletedProtocolVersionExchange = "CompletedProtocolVersionExchange",
	StartingKeyExchange = "StartingKeyExchange",
	CompletedKeyExchange = "CompletedKeyExchange",
	StartingSessionAuthentication = "StartingSessionAuthentication",
	CompletedSessionAuthentication = "CompletedSessionAuthentication",

	// Port forwarding
	StartingRefreshPorts = "StartingRefreshPorts",
	CompletedRefreshPorts = "CompletedRefreshPorts",

	// Tunnel service requests
	StartingRequestUri = "StartingRequestUri",
	StartingRequestConfig = "StartingRequestConfig",
	StartingSendTunnelRequest = "StartingSendTunnelRequest",
	CompletedSendTunnelRequest = "CompletedSendTunnelRequest",
	StartingCreateTunnelPort = "StartingCreateTunnelPort",
	CompletedCreateTunnelPort = "CompletedCreateTunnelPort",
	StartingGetTunnelPort = "StartingGetTunnelPort",
	CompletedGetTunnelPort = "CompletedGetTunnelPort",
}
