// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh;

public static class SshTraceEventIds
{
	private const int BaseEventId = 9000;

	#region Error / Warning events

	public const int UnknownError = BaseEventId + 0;
	public const int StreamReadError = BaseEventId + 1;
	public const int StreamWriteError = BaseEventId + 2;
	public const int StreamCloseError = BaseEventId + 3;
	public const int SendMessageFailed = BaseEventId + 4;
	public const int ReceiveMessageFailed = BaseEventId + 5;
	public const int HandleMessageFailed = BaseEventId + 6;
	public const int ServerAuthenticationFailed = BaseEventId + 7;
	public const int ClientAuthenticationFailed = BaseEventId + 8;
	public const int AuthenticationException = BaseEventId + 9;
	public const int ChannelWindowAdjustFailed = BaseEventId + 10;
	public const int ChannelWaitForWindowAdjust = BaseEventId + 11;
	public const int SessionReconnectInitFailed = BaseEventId + 20;
	public const int ServerSessionReconnectFailed = BaseEventId + 21;
	public const int ClientSessionReconnectFailed = BaseEventId + 22;
	public const int SessionRequestFailed = BaseEventId + 23;
	public const int ChannelRequestFailed = BaseEventId + 24;
	public const int ChannelCloseFailed = BaseEventId + 25;
	public const int ServerListenFailed = BaseEventId + 50;
	public const int PortForwardServerListenFailed = BaseEventId + 51;
	public const int PortForwardRequestInvalid = BaseEventId + 52;
	public const int PortForwardChannelInvalid = BaseEventId + 53;
	public const int PortForwardChannelOpenFailed = BaseEventId + 54;
	public const int PortForwardConnectionFailed = BaseEventId + 55;
	public const int TaskChainError = BaseEventId + 60;
	public const int MetricsError = BaseEventId + 61;

	#endregion

	#region Info / Verbose events

	public const int ProtocolVersion = BaseEventId + 100;
	public const int SendingMessage = BaseEventId + 101;
	public const int ReceivingMessage = BaseEventId + 102;
	public const int SendingChannelData = BaseEventId + 103;
	public const int ReceivingChannelData = BaseEventId + 104;
	public const int SessionEncrypted = BaseEventId + 110;
	public const int SessionAuthenticating = BaseEventId + 111;
	public const int SessionAuthenticated = BaseEventId + 112;
	public const int SessionClosing = BaseEventId + 113;
	public const int SessionConnecting = BaseEventId + 114;
	public const int ChannelOpened = BaseEventId + 120;
	public const int ChannelOpenFailed = BaseEventId + 121;
	public const int ChannelEofReceived = BaseEventId + 122;
	public const int ChannelClosed = BaseEventId + 123;
	public const int ServerListening = BaseEventId + 150;
	public const int ServerClientConnected = BaseEventId + 151;
	public const int PortForwardServerListening = BaseEventId + 152;
	public const int PortForwardConnectionAccepted = BaseEventId + 153;
	public const int PortForwardChannelOpened = BaseEventId + 154;
	public const int PortForwardChannelClosed = BaseEventId + 155;
	public const int PortForwardConnectionOpened = BaseEventId + 156;
	public const int PortForwardConnectionClosed = BaseEventId + 157;
	public const int SessionDisconnected = BaseEventId + 160;
	public const int ClientSessionReconnecting = BaseEventId + 161;
	public const int ServerSessionReconnecting = BaseEventId + 162;
	public const int ClientSessionStartReconnecting = BaseEventId + 163;
	public const int AlgorithmNegotiation = BaseEventId + 170;
	public const int DebugMessage = BaseEventId + 200;

	#endregion
}
