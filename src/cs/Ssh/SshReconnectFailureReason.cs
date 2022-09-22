// Copyright (c) Microsoft. All rights reserved.

using System.ComponentModel;

namespace Microsoft.DevTunnels.Ssh.Messages;

public enum SshReconnectFailureReason : int
{
	/// <summary>
	/// No reason was specified.
	/// </summary>
	[EditorBrowsable(EditorBrowsableState.Never)]
	None = 0,

	/// <summary>
	/// Reconnection failed due to an unknown server-side error.
	/// </summary>
	UnknownServerFailure = 1,

	/// <summary>
	/// The session ID requested by the client for reconnection was not found among
	/// the server's reconnectable sessions.
	/// </summary>
	SessionNotFound = 2,

	/// <summary>
	/// The reconnect token supplied by the client was invalid when checked by the server.
	/// The validation ensures that the client knows a secret key negotiated in the
	/// previously connected session.
	/// </summary>
	InvalidClientReconnectToken = 3,

	/// <summary>
	/// The server was unable to re-send dropped messages that were requested by the client.
	/// </summary>
	ServerDroppedMessages = 4,

	/// <summary>
	/// Reconnection failed due to an unknown client-side error.
	/// </summary>
	UnknownClientFailure = 101,

	/// <summary>
	/// The host key supplied by the reconnected server did not match the host key from the
	/// original session; the client refused to reconnect to a different host.
	/// </summary>
	DifferentServerHostKey = 102,

	/// <summary>
	/// The reconnect token supplied by the server was invalid when checked by the client.
	/// The validation ensures that the server knows a secret key negotiated in the
	/// previously connected session.
	/// </summary>
	InvalidServerReconnectToken = 103,

	/// <summary>
	/// The client was unable to re-send dropped messages that were requested by the server.
	/// </summary>
	ClientDroppedMessages = 104,
}
