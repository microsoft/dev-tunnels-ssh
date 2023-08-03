//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * SSH trace event level.
 */
export enum TraceLevel {
	Error = 'error',
	Warning = 'warning',
	Info = 'info',
	Verbose = 'verbose',
}

/**
 * Signature for a function that handles SSH trace events.
 *
 * @param level The level of message being traced: error, warning, info, or verbose.
 * @param eventId An integer that identifies the type of event. Normally this is one of
 * the values from `SshTraceEventIds`, but extensions may define additional event IDs.
 * @param msg A description of the event (non-localized).
 * @param err Optional `Error` object associated with the event, often included with
 * warning or error events. While the `Error.message` property is typically included as
 * (part of) the `msg` parameter, the error object may contain additional useful context
 * such as the stack trace.
 */
export type Trace = (level: TraceLevel, eventId: number, msg: string, err?: Error) => void;

// Events defined below should stay in sync with those in C#.

const baseEventId = 9000;

export class SshTraceEventIds {
	// Error / Warning events

	public static readonly unknownError = baseEventId + 0;
	public static readonly streamReadError = baseEventId + 1;
	public static readonly streamWriteError = baseEventId + 2;
	public static readonly streamCloseError = baseEventId + 3;
	public static readonly sendMessageFailed = baseEventId + 4;
	public static readonly receiveMessageFailed = baseEventId + 5;
	public static readonly handleMessageFailed = baseEventId + 6;
	public static readonly serverAuthenticationFailed = baseEventId + 7;
	public static readonly clientAuthenticationFailed = baseEventId + 8;
	public static readonly authenticationError = baseEventId + 9;
	public static readonly channelWindowAdjustFailed = baseEventId + 10;
	public static readonly channelWaitForWindowAdjust = baseEventId + 11;
	public static readonly sessionReconnectInitFailed = baseEventId + 20;
	public static readonly serverSessionReconnectFailed = baseEventId + 21;
	public static readonly clientSessionReconnectFailed = baseEventId + 22;
	public static readonly sessionRequestFailed = baseEventId + 23;
	public static readonly channelRequestFailed = baseEventId + 24;
	public static readonly serverListenFailed = baseEventId + 50;
	public static readonly portForwardServerListenFailed = baseEventId + 51;
	public static readonly portForwardRequestInvalid = baseEventId + 52;
	public static readonly portForwardChannelInvalid = baseEventId + 53;
	public static readonly portForwardChannelOpenFailed = baseEventId + 54;
	public static readonly portForwardConnectionFailed = baseEventId + 55;
	public static readonly metricsError = baseEventId + 61;

	// Info / Verbose events

	public static readonly protocolVersion = baseEventId + 100;
	public static readonly sendingMessage = baseEventId + 101;
	public static readonly receivingMessage = baseEventId + 102;
	public static readonly sendingChannelData = baseEventId + 103;
	public static readonly receivingChannelData = baseEventId + 104;
	public static readonly sessionEncrypted = baseEventId + 110;
	public static readonly sessionAuthenticating = baseEventId + 111;
	public static readonly sessionAuthenticated = baseEventId + 112;
	public static readonly sessionClosing = baseEventId + 113;
	public static readonly sessionConnecting = baseEventId + 114;
	public static readonly channelOpened = baseEventId + 120;
	public static readonly channelOpenFailed = baseEventId + 121;
	public static readonly channelEofReceived = baseEventId + 122;
	public static readonly channelClosed = baseEventId + 123;
	public static readonly serverListening = baseEventId + 150;
	public static readonly serverClientConnected = baseEventId + 151;
	public static readonly portForwardServerListening = baseEventId + 152;
	public static readonly portForwardConnectionAccepted = baseEventId + 153;
	public static readonly portForwardChannelOpened = baseEventId + 154;
	public static readonly portForwardChannelClosed = baseEventId + 155;
	public static readonly portForwardConnectionOpened = baseEventId + 156;
	public static readonly portForwardConnectionClosed = baseEventId + 157;
	public static readonly sessionDisconnected = baseEventId + 160;
	public static readonly clientSessionReconnecting = baseEventId + 161;
	public static readonly serverSessionReconnecting = baseEventId + 162;
	public static readonly clientSessionStartReconnecting = baseEventId + 163;
	public static readonly algorithmNegotiation = baseEventId + 170;
	public static readonly debugMessage = baseEventId + 200;
}
