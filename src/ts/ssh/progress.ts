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
	StartingProtocolVersionExchange = "StartingProtocolVersionExchange",
	CompletedProtocolVersionExchange = "CompletedProtocolVersionExchange",
	StartingKeyExchange = "StartingKeyExchange",
	CompletedKeyExchange = "CompletedKeyExchange",
	StartingSessionAuthentication = "StartingSessionAuthentication",
	CompletedSessionAuthentication = "CompletedSessionAuthentication",
}
