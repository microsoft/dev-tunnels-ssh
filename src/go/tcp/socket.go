// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import (
	"net"
)

// defaultSocketBufferSize is 2 * DefaultMaxPacketSize (32KB) = 64KB.
// This matches the C# and TypeScript implementations.
const defaultSocketBufferSize = 2 * 0x8000

// configureSocketForSSH configures a TCP connection with options optimized for SSH:
// TCP_NODELAY enabled, and send/receive buffers set to 64KB.
func configureSocketForSSH(conn net.Conn) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tcpConn.SetNoDelay(true)
	// Go's net package doesn't expose direct buffer size setting through
	// the high-level API, but SetReadBuffer/SetWriteBuffer are available.
	tcpConn.SetReadBuffer(defaultSocketBufferSize)
	tcpConn.SetWriteBuffer(defaultSocketBufferSize)
}
