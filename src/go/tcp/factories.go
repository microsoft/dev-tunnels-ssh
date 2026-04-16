// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import (
	"net"
	"strconv"
)

// TCPListenerFactory creates TCP listeners for port forwarding.
// Custom implementations can override the default listening behavior,
// for example to handle port conflicts, custom network interfaces,
// or to inject test listeners.
type TCPListenerFactory interface {
	// CreateTCPListener creates a TCP listener on the specified local address and port.
	//
	// Parameters:
	//   - remotePort: The remote port this listener is forwarding to/from (informational).
	//   - localIPAddress: The local IP address to listen on.
	//   - localPort: The local port to listen on (0 for dynamic allocation).
	//   - canChangeLocalPort: Whether the factory may choose a different port if the
	//     requested one is unavailable.
	//
	// Returns a started net.Listener or an error.
	CreateTCPListener(
		remotePort int,
		localIPAddress string,
		localPort int,
		canChangeLocalPort bool,
	) (net.Listener, error)
}

// PortForwardMessageFactory creates port forwarding protocol messages.
// Custom implementations can create message subclasses with additional
// application-specific fields.
type PortForwardMessageFactory interface {
	// CreateRequestMessage creates a PortForwardRequestMessage for the given port.
	CreateRequestMessage(port int) *PortForwardRequestMessage

	// CreateSuccessMessage creates a PortForwardSuccessMessage for the given port.
	CreateSuccessMessage(port int) *PortForwardSuccessMessage

	// CreateChannelOpenMessage creates a PortForwardChannelOpenMessage for the given port.
	CreateChannelOpenMessage(port int) *PortForwardChannelOpenMessage
}

// defaultTCPListenerFactory is the default implementation that uses net.Listen.
type defaultTCPListenerFactory struct{}

func (f *defaultTCPListenerFactory) CreateTCPListener(
	remotePort int,
	localIPAddress string,
	localPort int,
	canChangeLocalPort bool,
) (net.Listener, error) {
	listenAddr := net.JoinHostPort(localIPAddress, strconv.Itoa(localPort))
	return net.Listen("tcp", listenAddr)
}

// defaultPortForwardMessageFactory is the default implementation that creates
// standard port forwarding messages.
type defaultPortForwardMessageFactory struct{}

func (f *defaultPortForwardMessageFactory) CreateRequestMessage(port int) *PortForwardRequestMessage {
	return &PortForwardRequestMessage{}
}

func (f *defaultPortForwardMessageFactory) CreateSuccessMessage(port int) *PortForwardSuccessMessage {
	return &PortForwardSuccessMessage{}
}

func (f *defaultPortForwardMessageFactory) CreateChannelOpenMessage(port int) *PortForwardChannelOpenMessage {
	return &PortForwardChannelOpenMessage{}
}
