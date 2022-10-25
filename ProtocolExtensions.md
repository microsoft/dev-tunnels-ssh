# SSH Protocol Extensions
This library implements some extensions to the SSH protocol. All protocol extensions are negotiated according to [RFC 8308 - SSH Extension Negotiation](https://tools.ietf.org/html/rfc8308) so they will not be enabled when communicating with other SSH implementations that don't support the extensions.

Supported protocol extensions are defined in `SshProtocolExtensionNames`. They may be selectively enabled/disabled for individual sessions by modifying the `ProtocolExtensions` list of the session configuration.

## Extension: Server key algorithm names
Extension ID: `server-sig-algs`

This is a standard extension defined in [RFC 8308](https://tools.ietf.org/html/rfc8308) that enables the server to enumerate all public key algorithms accepted for client authentication.

## Extension: Initial channel requests
Extension ID: `open-channel-request@microsoft.com`

This extension makes opening channels slightly faster. Typically after opening an SSH channel, the next step is to send a channel request that specifies exactly what the channel will be used for. With the standard protocol, the channel request cannot be sent until the channel ID is obtained from the channel open confirmation. This protocol extension avoids waiting for that round-trip by bundling the initial channel request with the channel open request.

## Extension: Session reconnection
Extension ID: `session-reconnect@microsoft.com`

This extension enables an SSH client and server to recover from a temporary disconnection without impacting higher layers that are sending data over the SSH channels. The cost of reconnection support is an additional 8 bytes per packet, along with some caching of a small number of messages in-memory while connected, or up to 1MB per channel while disconnected.

### Reconnection sequence

The following sequence describes the reconnection protocol:

  1. After the initial key-exchange, server and client sessions both send extension-info messages that indicate their support for the reconnection extension.
  1. Upon receiving the extension-info message, server and client both send a special _enable-session-reconnect_ session request that activates the protocol extension:
     - All messages include an additional field that is the sequence number of the last message received by the message sender.
     - All messages sent by each side are saved in a reconnect cache.
     - Messages are discarded from the reconnect cache after the other side confirms receipt of an equal or greater sequence number. 
  1. A session connection error causes a disconnect event to be raised on both server and client sides, instead of permanently closing the sessions.
  1. The server saves the disconnected server session in a list of sessions available for reconnection.
  1. Any messages sent by either side while the session is in a disconnected state get silently added to the reconnect cache. (Of course no messages will be received in this state.)
  1. The client may then reconnect the _same_ client session to the _same_ server.
  1. When a new connection is made on the server, initially a new server session gets created.
  1. The old client session and new server session perform the initial key exchange for the session, as normal.
  1. After the key-exchange, the client sends a special _session-reconnect_ session request that performs the reconnection:
     - The reconnect request includes a token that proves the client knows a secret from the previous session.
     - The reconnect request also includes the sequence number of the last message received by the client before the session was disconnected, in case the disconnect dropped some messages.
  1. The server receives the _session-reconnect_ request, enumerates the list of sessions available for reconnection, and tries to match and validate the reconnect request token.
  1. The server sends a reconnect response:
     - The reconnect response includes a token that proves the server knows a secret from the previous session.
     - The reconnect response also includes the sequence number of the last message received by the server before the session was disconnected, in case the disconnect dropped some messages.
  1. The client receives the reconnect response and validates the token provided by the server.
  1. The server moves the stream for the new connection from the new server session over to the old server session, and the new server session is disposed.
  1. The reconnected client and server sessions re-send any dropped messages, or messages sent while disconnected, based on the sequence numbers last seen by the other side.
     - Key-exchange related messages are never re-sent, since key exchange was re-initialized for the new connection.

### Message caching for reconnection

As described above, sent messages are temporarily saved in a cache until the other side confirms their receipt. This cache can grow only as large as **1 MB per channel** due to the channel flow-control built into the SSH protocol.

SSH channels have a "window size" of 1 MB -- that means a channel can only send up to 1 MB of data until it receives a _channel-window-adjust_ message that indicates the other side has processed (at least some of) the data and is ready to receive more. When a channel window fills up, further attempts to send data over the channel are asynchronously blocked. This will eventually happen when the session is in a disconnected state and the application atempts to continue sending data over the channel.

## Extension: Session latency measurement
Extension ID: `session-latency@microsoft.com`

This extension enables continuous latency measurements throughout the duration of a session. In addition to current latency, the minimum, maximum, and average latency for the session are tracked.

Rather than forcing additional periodic "ping" packets, this protocol extension appends an additional 4 bytes to each packet. That means latency measurements are only recorded when the application layer is sending or receiving data. (Of course, an application that is not otherwise sending any data could intentionally send small messages to force latency measurements.) Note due to flow-control built-in to the SSH protocol, even a one-way data stream will include periodic latency measurements. 

Latency measurements require that the **Session reconnection** protocol extension is also enabled, because the latency measurements depend on the same packet caching and protocol handshake that the reconnect extension uses. (Latency measurements do not span disconnections; that is, a 30-second disconnection does not cause the maximum reported latency to be 30+ seconds. Latency is only measured while connected.)

Round-trip connection latency between SSH client and server are measured as follows:
 1. Before sending each packet (but after encryption and MAC computation), record the send time (_`Ts`_) along with the sent message in the reconnect cache.
 1. After receiving the first part of each packet, record the receive time (_`Tr`_) (before any decryption, MAC validation, or other processing).
 1. Include in each sent packet an extra 32-bit value that is the time delta (_`Td`_) since the last-recorded receive time (_`Tr`_). This follows the 64-bit last-received packet sequence number appended for reconnection support.
 1. After receiving each packet, find the message in the reconnect cache that matches the last-received sequence number, and get its send time (_`Ts`_). Also read the remote delta (_`Td`_) time from the end of the packet.
 1. Then the round-trip latency can be computed as _`(Tr - Ts - Td)`_. In other words, it measures the time between sending one packet and receiving the next, not including the time between receiving and sending on the remote side (and avoiding overlaps).

## Extension: Forward non-requested port
Extension ID: `can-change-port`

The SSH protocol specifies that the port forwarded in response to a port forwarding request must match the requested port. This extension indicates that the SSH session supports forwarding a port that differs from the requested port. When the requested port is not available, this allows the recipient of the request to select an appropriate port and send a single response, instead of informing the sender that it needs to request a different port.
