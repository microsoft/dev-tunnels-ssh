// Copyright (c) Microsoft Corporation. All rights reserved.

package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh"
	"github.com/microsoft/dev-tunnels-ssh/src/go/ssh/messages"
)

// PortForwardingServiceName is the service registration name.
const PortForwardingServiceName = "port-forwarding"

// ForwardedPort describes a single forwarded port.
type ForwardedPort struct {
	LocalHost  string
	LocalPort  int
	RemoteHost string
	RemotePort int
}

// ForwardedPortConnectingEventArgs provides information about a port forwarding
// connection that is about to be established, and allows the application to reject it.
type ForwardedPortConnectingEventArgs struct {
	// Port is the forwarded port number.
	Port int

	// IsIncoming is true for incoming connections (remote → local).
	IsIncoming bool

	// Stream is the SSH stream for the forwarded connection.
	Stream *ssh.Stream

	// Reject can be set to true by the callback to refuse the connection.
	Reject bool
}

// PortForwardingService handles SSH port forwarding (RFC 4254 sections 6-7).
// It manages both local-to-remote and remote-to-local port forwarding, as well
// as stream-based forwarding that doesn't use local TCP listeners.
type PortForwardingService struct {
	session *ssh.Session

	// AcceptLocalConnectionsForForwardedPorts controls whether to listen on local
	// TCP sockets for remotely-forwarded ports. Default: true.
	AcceptLocalConnectionsForForwardedPorts bool

	// AcceptRemoteConnectionsForNonForwardedPorts controls whether to accept
	// direct-tcpip channels for non-forwarded ports. Default: true.
	AcceptRemoteConnectionsForNonForwardedPorts bool

	// ForwardConnectionsToLocalPorts controls whether the port-forwarding service
	// forwards connections to local TCP sockets. Default: true.
	// When false, incoming forwarded channels are accepted but not auto-connected
	// to local TCP.
	ForwardConnectionsToLocalPorts bool

	// ChannelOpeningHandler is called when a port-forwarding channel is opening.
	// The handler can set FailureReason on the event args to reject the channel.
	ChannelOpeningHandler func(*ssh.ChannelOpeningEventArgs)

	// OnStreamOpened is called when a remote stream is opened (for StreamFromRemotePort).
	OnStreamOpened func(stream *ssh.Stream, port int)

	// OnForwardedPortConnecting is called when a connection to a forwarded port is
	// about to be established. Set Reject on the args to refuse the connection.
	OnForwardedPortConnecting func(*ForwardedPortConnectingEventArgs)

	// ListenerFactory creates TCP listeners for port forwarding.
	// If nil, the default factory using net.Listen is used.
	ListenerFactory TCPListenerFactory

	// MessageFactory creates port forwarding protocol messages.
	// If nil, the default factory creating standard messages is used.
	MessageFactory PortForwardMessageFactory

	// LocalForwardedPorts tracks ports being forwarded from local to remote
	// (via ForwardToRemotePort). Keyed by local port number.
	LocalForwardedPorts *ForwardedPortsCollection

	// RemoteForwardedPorts tracks ports being forwarded from remote to local
	// (via ForwardFromRemotePort or StreamFromRemotePort). Keyed by remote port number.
	RemoteForwardedPorts *ForwardedPortsCollection

	mu               sync.Mutex
	remoteForwarders map[int]*remoteForwarder // keyed by remote port
	localForwarders  map[int]*localForwarder  // keyed by local port
	streamWaiters    map[int][]chan *ssh.Stream // keyed by port
	forwarderNotify  chan struct{}             // closed+replaced when a remote forwarder is registered
	disposed         bool
}

// remoteForwarder tracks a single remote port forwarding (tcpip-forward).
type remoteForwarder struct {
	remoteHost string
	remotePort int
	localHost  string
	localPort  int
	listener   net.Listener
	isStream   bool // true for StreamFromRemotePort (no local TCP listener)
}

// localForwarder tracks a single local-to-remote port forwarding.
type localForwarder struct {
	localHost  string
	localPort  int
	remoteHost string
	remotePort int
	listener   net.Listener
}

// LocalPortForwarder represents an active local-to-remote port forwarding.
// Closing it stops the TCP listener(s) and removes the port from the collection.
type LocalPortForwarder struct {
	ForwardedPort
	pfs       *PortForwardingService
	listener2 net.Listener // optional IPv6 dual-mode listener
	closed    bool
}

// Close stops the local TCP listener(s) and removes the port from the local
// forwarded ports collection.
func (f *LocalPortForwarder) Close() error {
	f.pfs.mu.Lock()
	if f.closed {
		f.pfs.mu.Unlock()
		return nil
	}
	f.closed = true
	lf, ok := f.pfs.localForwarders[f.LocalPort]
	if ok {
		delete(f.pfs.localForwarders, f.LocalPort)
	}
	f.pfs.mu.Unlock()

	if ok && lf.listener != nil {
		lf.listener.Close()
	}
	if f.listener2 != nil {
		f.listener2.Close()
	}
	f.pfs.LocalForwardedPorts.Remove(f.LocalPort)
	return nil
}

// RemotePortForwarder represents an active remote-to-local port forwarding.
// Closing it sends a cancel-tcpip-forward session request and removes the port
// from the collection.
type RemotePortForwarder struct {
	ForwardedPort
	pfs    *PortForwardingService
	closed bool
}

// Close sends a cancel-tcpip-forward request to the remote side and removes
// the port from the remote forwarded ports collection.
func (f *RemotePortForwarder) Close() error {
	f.pfs.mu.Lock()
	if f.closed {
		f.pfs.mu.Unlock()
		return nil
	}
	f.closed = true
	_, ok := f.pfs.remoteForwarders[f.RemotePort]
	if ok {
		delete(f.pfs.remoteForwarders, f.RemotePort)
	}
	f.pfs.mu.Unlock()

	f.pfs.RemoteForwardedPorts.Remove(f.RemotePort)

	// Send cancel-tcpip-forward to the remote side with a timeout to avoid
	// blocking indefinitely if the session is unresponsive.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-f.pfs.session.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	defer cancel()

	msg := f.pfs.messageFactory().CreateRequestMessage(f.RemotePort)
	msg.RequestType = CancelPortForwardRequestType
	msg.WantReply = true
	msg.AddressToBind = f.RemoteHost
	msg.Port = uint32(f.RemotePort)
	_, _, err := f.pfs.session.RequestWithPayload(ctx, msg, true)
	return err
}

// NewPortForwardingService creates a new port forwarding service for the given session.
func NewPortForwardingService(session *ssh.Session) *PortForwardingService {
	return &PortForwardingService{
		session:                                     session,
		AcceptLocalConnectionsForForwardedPorts:      true,
		AcceptRemoteConnectionsForNonForwardedPorts:  true,
		ForwardConnectionsToLocalPorts:               true,
		ListenerFactory:                              &defaultTCPListenerFactory{},
		MessageFactory:                               &defaultPortForwardMessageFactory{},
		LocalForwardedPorts:                          NewForwardedPortsCollection(),
		RemoteForwardedPorts:                         NewForwardedPortsCollection(),
		remoteForwarders:                             make(map[int]*remoteForwarder),
		localForwarders:                              make(map[int]*localForwarder),
		streamWaiters:                                make(map[int][]chan *ssh.Stream),
		forwarderNotify:                              make(chan struct{}),
	}
}

// listenerFactory returns the configured ListenerFactory or the default.
func (pfs *PortForwardingService) listenerFactory() TCPListenerFactory {
	if pfs.ListenerFactory != nil {
		return pfs.ListenerFactory
	}
	return &defaultTCPListenerFactory{}
}

// messageFactory returns the configured MessageFactory or the default.
func (pfs *PortForwardingService) messageFactory() PortForwardMessageFactory {
	if pfs.MessageFactory != nil {
		return pfs.MessageFactory
	}
	return &defaultPortForwardMessageFactory{}
}

// AddPortForwardingService registers the port forwarding service on a session configuration.
// This enables handling of tcpip-forward requests, direct-tcpip channels, and
// forwarded-tcpip channels.
func AddPortForwardingService(config *ssh.SessionConfig) {
	config.AddService(PortForwardingServiceName, ssh.ServiceActivation{
		SessionRequests: []string{PortForwardRequestType, CancelPortForwardRequestType},
		ChannelTypes:    []string{ForwardedTCPIPChannelType, DirectTCPIPChannelType},
	}, func(session *ssh.Session, cfg interface{}) ssh.Service {
		return NewPortForwardingService(session)
	}, nil)
}

// OnSessionRequest handles tcpip-forward and cancel-tcpip-forward session requests.
func (pfs *PortForwardingService) OnSessionRequest(args *ssh.RequestEventArgs) {
	switch args.RequestType {
	case PortForwardRequestType:
		pfs.handleForwardRequest(args)
	case CancelPortForwardRequestType:
		pfs.handleCancelForwardRequest(args)
	}
}

// OnChannelOpening handles forwarded-tcpip and direct-tcpip channel open requests.
func (pfs *PortForwardingService) OnChannelOpening(args *ssh.ChannelOpeningEventArgs) {
	if args.Payload == nil {
		args.FailureReason = messages.ChannelOpenFailureConnectFailed
		args.FailureDescription = "missing channel open data"
		return
	}

	pfMsg, err := ParsePortForwardChannelOpenMessage(args.Payload)
	if err != nil {
		args.FailureReason = messages.ChannelOpenFailureConnectFailed
		args.FailureDescription = "invalid channel open message"
		return
	}

	switch pfMsg.ChannelType {
	case ForwardedTCPIPChannelType:
		pfs.handleForwardedTCPIPChannel(args, pfMsg)
	case DirectTCPIPChannelType:
		pfs.handleDirectTCPIPChannel(args, pfMsg)
	default:
		args.FailureReason = messages.ChannelOpenFailureUnknownChannelType
		args.FailureDescription = fmt.Sprintf("unknown channel type: %s", pfMsg.ChannelType)
	}
}

// OnChannelRequest handles channel requests (not used for port forwarding).
func (pfs *PortForwardingService) OnChannelRequest(channel *ssh.Channel, args *ssh.RequestEventArgs) {
}

// Close cleans up all forwarders and listeners.
// Implements io.Closer.
func (pfs *PortForwardingService) Close() error {
	pfs.mu.Lock()
	if pfs.disposed {
		pfs.mu.Unlock()
		return nil
	}
	pfs.disposed = true

	// Close all remote forwarder listeners.
	for _, rf := range pfs.remoteForwarders {
		if rf.listener != nil {
			rf.listener.Close()
		}
	}
	pfs.remoteForwarders = make(map[int]*remoteForwarder)

	// Close all local forwarder listeners.
	for _, lf := range pfs.localForwarders {
		if lf.listener != nil {
			lf.listener.Close()
		}
	}
	pfs.localForwarders = make(map[int]*localForwarder)

	// Close all stream waiters.
	for port, waiters := range pfs.streamWaiters {
		for _, ch := range waiters {
			close(ch)
		}
		delete(pfs.streamWaiters, port)
	}

	pfs.mu.Unlock()

	// Clear the port collections (fires OnPortRemoved callbacks).
	pfs.RemoteForwardedPorts.clear()
	pfs.LocalForwardedPorts.clear()
	return nil
}

// notifyForwarderAdded broadcasts to any goroutines waiting in WaitForForwardedPort.
// Must be called with pfs.mu held.
func (pfs *PortForwardingService) notifyForwarderAdded() {
	close(pfs.forwarderNotify)
	pfs.forwarderNotify = make(chan struct{})
}

// callForwardedPortConnecting invokes the OnForwardedPortConnecting callback.
// Returns true if the connection was rejected.
func (pfs *PortForwardingService) callForwardedPortConnecting(port int, isIncoming bool, stream *ssh.Stream) bool {
	handler := pfs.OnForwardedPortConnecting
	if handler == nil {
		return false
	}
	args := &ForwardedPortConnectingEventArgs{
		Port:       port,
		IsIncoming: isIncoming,
		Stream:     stream,
	}
	handler(args)
	return args.Reject
}

// handleForwardRequest processes a tcpip-forward request (server-side).
// The remote side is asking us to listen on a port and forward connections.
func (pfs *PortForwardingService) handleForwardRequest(args *ssh.RequestEventArgs) {
	pfMsg, err := ParsePortForwardRequestMessage(args.Payload)
	if err != nil {
		return // IsAuthorized stays false
	}

	// Check with the application callback for authorization.
	if pfs.ChannelOpeningHandler != nil {
		openArgs := &ssh.ChannelOpeningEventArgs{
			Request: &messages.ChannelOpenMessage{
				ChannelType: ForwardedTCPIPChannelType,
			},
			IsRemoteRequest: true,
		}
		pfs.ChannelOpeningHandler(openArgs)
		if openArgs.FailureReason != messages.ChannelOpenFailureNone {
			return
		}
	}

	port := int(pfMsg.Port)
	address := pfMsg.AddressToBind
	if address == "" {
		address = "127.0.0.1"
	}

	// Start listening on the requested port using the listener factory.
	ln, err := pfs.listenerFactory().CreateTCPListener(port, address, port, true)
	if err != nil {
		// Port in use or other error — return failure.
		return
	}

	// Get actual port (for dynamic allocation with port 0).
	actualPort := ln.Addr().(*net.TCPAddr).Port

	rf := &remoteForwarder{
		remoteHost: address,
		remotePort: actualPort,
		listener:   ln,
	}

	pfs.mu.Lock()
	pfs.remoteForwarders[actualPort] = rf
	pfs.notifyForwarderAdded()
	pfs.mu.Unlock()

	// Track this forwarding in the collection.
	pfs.RemoteForwardedPorts.Add(actualPort, &ForwardedPort{
		RemoteHost: address,
		RemotePort: actualPort,
	})

	// Start accepting connections on this listener.
	go pfs.acceptRemoteForwardConnections(rf)

	// Set success with the allocated port.
	args.IsAuthorized = true
	successMsg := pfs.messageFactory().CreateSuccessMessage(actualPort)
	successMsg.Port = uint32(actualPort)
	args.ResponseMessage = successMsg
}

// handleCancelForwardRequest processes a cancel-tcpip-forward request.
func (pfs *PortForwardingService) handleCancelForwardRequest(args *ssh.RequestEventArgs) {
	pfMsg, err := ParsePortForwardRequestMessage(args.Payload)
	if err != nil {
		return
	}

	port := int(pfMsg.Port)

	pfs.mu.Lock()
	rf, ok := pfs.remoteForwarders[port]
	if ok {
		delete(pfs.remoteForwarders, port)
	}
	pfs.mu.Unlock()

	if ok && rf.listener != nil {
		rf.listener.Close()
	}

	if ok {
		pfs.RemoteForwardedPorts.Remove(port)
	}

	args.IsAuthorized = ok
}

// acceptRemoteForwardConnections accepts TCP connections on a remote forwarder's
// listener and opens forwarded-tcpip channels back to the client.
func (pfs *PortForwardingService) acceptRemoteForwardConnections(rf *remoteForwarder) {
	for {
		conn, err := rf.listener.Accept()
		if err != nil {
			return // Listener closed
		}

		go pfs.handleRemoteForwardConnection(rf, conn)
	}
}

// handleRemoteForwardConnection handles a single incoming TCP connection for
// remote port forwarding by opening a forwarded-tcpip channel.
func (pfs *PortForwardingService) handleRemoteForwardConnection(rf *remoteForwarder, conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	// Derive a context from the session lifetime so the channel open is
	// cancelled when the session closes.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-pfs.session.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	defer cancel()

	// Open a forwarded-tcpip channel to the client.
	ch, err := pfs.session.OpenChannelWithMessage(
		ctx,
		ForwardedTCPIPChannelType,
		func(senderChannel, maxWindowSize, maxPacketSize uint32) messages.Message {
			openMsg := pfs.messageFactory().CreateChannelOpenMessage(rf.remotePort)
			openMsg.ChannelType = ForwardedTCPIPChannelType
			openMsg.SenderChannel = senderChannel
			openMsg.MaxWindowSize = maxWindowSize
			openMsg.MaxPacketSize = maxPacketSize
			openMsg.Host = rf.remoteHost
			openMsg.Port = uint32(rf.remotePort)
			openMsg.OriginatorIPAddress = remoteAddr.IP.String()
			openMsg.OriginatorPort = uint32(remoteAddr.Port)
			return openMsg
		},
	)
	if err != nil {
		return
	}

	// Relay data between the TCP connection and the SSH channel.
	stream := ssh.NewStream(ch)
	relayStreams(conn, stream)
}

// handleForwardedTCPIPChannel handles an incoming forwarded-tcpip channel (client-side).
// This is received when the server opens a channel for a port we previously forwarded.
func (pfs *PortForwardingService) handleForwardedTCPIPChannel(
	args *ssh.ChannelOpeningEventArgs,
	pfMsg *PortForwardChannelOpenMessage,
) {
	port := int(pfMsg.Port)

	pfs.mu.Lock()
	rf, hasForwarder := pfs.remoteForwarders[port]

	// Check for stream waiters.
	waiters := pfs.streamWaiters[port]
	pfs.mu.Unlock()

	// If this is a stream-based forwarder, deliver the stream.
	if hasForwarder && rf.isStream {
		// Let the channel open succeed — the stream will be delivered asynchronously.
		if pfs.OnStreamOpened != nil || len(waiters) > 0 {
			go func() {
				stream := ssh.NewStream(args.Channel)
				pfs.mu.Lock()
				if len(pfs.streamWaiters[port]) > 0 {
					ch := pfs.streamWaiters[port][0]
					pfs.streamWaiters[port] = pfs.streamWaiters[port][1:]
					pfs.mu.Unlock()
					ch <- stream
				} else {
					pfs.mu.Unlock()
					if pfs.OnStreamOpened != nil {
						pfs.OnStreamOpened(stream, port)
					}
				}
			}()
		}
		return
	}

	// If we have a forwarder with a local destination, connect to it.
	if hasForwarder && rf.localHost != "" {
		if !pfs.ForwardConnectionsToLocalPorts {
			// Channel accepted but not auto-connected to local TCP.
			return
		}
		localAddr := net.JoinHostPort(rf.localHost, strconv.Itoa(rf.localPort))
		go func() {
			stream := ssh.NewStream(args.Channel)
			if pfs.callForwardedPortConnecting(port, true, stream) {
				stream.Close()
				return
			}
			conn, err := net.Dial("tcp", localAddr)
			if err != nil {
				stream.Close()
				return
			}
			relayStreams(conn, stream)
		}()
		return
	}

	// Deliver to stream waiters if any.
	if len(waiters) > 0 {
		go func() {
			stream := ssh.NewStream(args.Channel)
			pfs.mu.Lock()
			if len(pfs.streamWaiters[port]) > 0 {
				ch := pfs.streamWaiters[port][0]
				pfs.streamWaiters[port] = pfs.streamWaiters[port][1:]
				pfs.mu.Unlock()
				ch <- stream
			} else {
				pfs.mu.Unlock()
			}
		}()
		return
	}

	// No forwarder and AcceptLocalConnectionsForForwardedPorts is set — accept
	// and let the application handle it (via accept queue).
	if pfs.AcceptLocalConnectionsForForwardedPorts {
		return
	}

	args.FailureReason = messages.ChannelOpenFailureConnectFailed
	args.FailureDescription = fmt.Sprintf("no forwarder for port %d", port)
}

// handleDirectTCPIPChannel handles an incoming direct-tcpip channel (server-side).
// The remote side wants to connect to a specific host:port through us.
func (pfs *PortForwardingService) handleDirectTCPIPChannel(
	args *ssh.ChannelOpeningEventArgs,
	pfMsg *PortForwardChannelOpenMessage,
) {
	if !pfs.AcceptRemoteConnectionsForNonForwardedPorts {
		args.FailureReason = messages.ChannelOpenFailureAdministrativelyProhibited
		args.FailureDescription = "direct-tcpip not allowed"
		return
	}

	// Allow the application to authorize or reject.
	if pfs.ChannelOpeningHandler != nil {
		pfs.ChannelOpeningHandler(args)
		if args.FailureReason != messages.ChannelOpenFailureNone {
			return
		}
	}

	if !pfs.ForwardConnectionsToLocalPorts {
		// Channel accepted but not auto-connected to local TCP.
		return
	}

	host := pfMsg.Host
	port := pfMsg.Port

	// Connect to the target destination.
	go func() {
		stream := ssh.NewStream(args.Channel)
		if pfs.callForwardedPortConnecting(int(port), true, stream) {
			stream.Close()
			return
		}
		targetAddr := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
		conn, err := net.Dial("tcp", targetAddr)
		if err != nil {
			stream.Close()
			return
		}
		relayStreams(conn, stream)
	}()
}

// ForwardFromRemotePort requests the remote side to listen on a port and forward
// connections back through the SSH session. Incoming connections are forwarded to
// localHost:localPort on the local side.
//
// If remotePort is 0, the remote side dynamically allocates a port.
// Returns the ForwardedPort with the actual remote port, or an error.
func (pfs *PortForwardingService) ForwardFromRemotePort(
	ctx context.Context,
	remoteIPAddress string,
	remotePort int,
	localHost string,
	localPort int,
) (*RemotePortForwarder, error) {
	if remoteIPAddress == "" {
		remoteIPAddress = "127.0.0.1"
	}

	// Check for duplicate forwarding of a specific (non-zero) remote port.
	if remotePort != 0 {
		pfs.mu.Lock()
		if _, exists := pfs.remoteForwarders[remotePort]; exists {
			pfs.mu.Unlock()
			return nil, fmt.Errorf("remote port %d is already being forwarded", remotePort)
		}
		pfs.mu.Unlock()
	}

	msg := pfs.messageFactory().CreateRequestMessage(remotePort)
	msg.RequestType = PortForwardRequestType
	msg.WantReply = true
	msg.AddressToBind = remoteIPAddress
	msg.Port = uint32(remotePort)

	success, respPayload, err := pfs.session.RequestWithPayload(ctx, msg, true)
	if err != nil {
		return nil, err
	}
	if !success {
		return nil, fmt.Errorf("remote port forwarding request rejected")
	}

	// Parse the allocated port from the response.
	actualPort := remotePort
	if len(respPayload) > 1 {
		respMsg := &PortForwardSuccessMessage{}
		if err := messages.ReadMessage(respMsg, respPayload); err == nil && respMsg.Port != 0 {
			actualPort = int(respMsg.Port)
		}
	}

	rf := &remoteForwarder{
		remoteHost: remoteIPAddress,
		remotePort: actualPort,
		localHost:  localHost,
		localPort:  localPort,
	}

	pfs.mu.Lock()
	pfs.remoteForwarders[actualPort] = rf
	pfs.notifyForwarderAdded()
	pfs.mu.Unlock()

	fp := &ForwardedPort{
		LocalHost:  localHost,
		LocalPort:  localPort,
		RemoteHost: remoteIPAddress,
		RemotePort: actualPort,
	}

	// Track this forwarding in the collection.
	pfs.RemoteForwardedPorts.Add(actualPort, fp)

	return &RemotePortForwarder{
		ForwardedPort: *fp,
		pfs:           pfs,
	}, nil
}

// ForwardToRemotePort listens on a local port and forwards connections to
// remoteHost:remotePort through the SSH session by opening direct-tcpip channels.
//
// If localPort is 0, a port is dynamically allocated.
// When localIPAddress is loopback (127.0.0.1) or any (0.0.0.0), the service also
// creates a second listener for the corresponding IPv6 address (::1 or ::) to
// support dual-mode IPv4/IPv6 listening.
// Returns the LocalPortForwarder with the actual local port, or an error.
func (pfs *PortForwardingService) ForwardToRemotePort(
	ctx context.Context,
	localIPAddress string,
	localPort int,
	remoteHost string,
	remotePort int,
) (*LocalPortForwarder, error) {
	if localIPAddress == "" {
		localIPAddress = "127.0.0.1"
	}

	// Check for duplicate forwarding of a specific (non-zero) local port.
	if localPort != 0 {
		pfs.mu.Lock()
		if _, exists := pfs.localForwarders[localPort]; exists {
			pfs.mu.Unlock()
			return nil, fmt.Errorf("local port %d is already being forwarded", localPort)
		}
		pfs.mu.Unlock()
	}

	factory := pfs.listenerFactory()

	ln, err := factory.CreateTCPListener(remotePort, localIPAddress, localPort, true)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s:%d: %w", localIPAddress, localPort, err)
	}

	actualPort := ln.Addr().(*net.TCPAddr).Port

	lf := &localForwarder{
		localHost:  localIPAddress,
		localPort:  actualPort,
		remoteHost: remoteHost,
		remotePort: remotePort,
		listener:   ln,
	}

	pfs.mu.Lock()
	pfs.localForwarders[actualPort] = lf
	pfs.mu.Unlock()

	go pfs.acceptLocalForwardConnections(lf)

	// IPv4/IPv6 dual-mode: if listening on loopback or any, also listen on the
	// corresponding IPv6 address to accept connections from both address families.
	var listener2 net.Listener
	if localIPAddress == "127.0.0.1" || localIPAddress == "0.0.0.0" {
		ipv6Addr := "::1"
		if localIPAddress == "0.0.0.0" {
			ipv6Addr = "::"
		}
		listener2, err = factory.CreateTCPListener(remotePort, ipv6Addr, actualPort, false)
		if err != nil {
			// IPv6 may not be available — silently skip.
			listener2 = nil
		}
		if listener2 != nil {
			lf2 := &localForwarder{
				localHost:  ipv6Addr,
				localPort:  actualPort,
				remoteHost: remoteHost,
				remotePort: remotePort,
				listener:   listener2,
			}
			go pfs.acceptLocalForwardConnections(lf2)
		}
	}

	fp := &ForwardedPort{
		LocalHost:  localIPAddress,
		LocalPort:  actualPort,
		RemoteHost: remoteHost,
		RemotePort: remotePort,
	}

	// Track this forwarding in the collection.
	pfs.LocalForwardedPorts.Add(actualPort, fp)

	return &LocalPortForwarder{
		ForwardedPort: *fp,
		pfs:           pfs,
		listener2:     listener2,
	}, nil
}

// acceptLocalForwardConnections accepts TCP connections on a local listener
// and opens direct-tcpip channels to the remote destination.
func (pfs *PortForwardingService) acceptLocalForwardConnections(lf *localForwarder) {
	for {
		conn, err := lf.listener.Accept()
		if err != nil {
			return // Listener closed
		}

		go pfs.handleLocalForwardConnection(lf, conn)
	}
}

// handleLocalForwardConnection handles a single incoming TCP connection for
// local-to-remote port forwarding by opening a direct-tcpip channel.
func (pfs *PortForwardingService) handleLocalForwardConnection(lf *localForwarder, conn net.Conn) {
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)

	// Derive a context from the session lifetime so the channel open is
	// cancelled when the session closes.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-pfs.session.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	defer cancel()

	ch, err := pfs.session.OpenChannelWithMessage(
		ctx,
		DirectTCPIPChannelType,
		func(senderChannel, maxWindowSize, maxPacketSize uint32) messages.Message {
			openMsg := pfs.messageFactory().CreateChannelOpenMessage(lf.remotePort)
			openMsg.ChannelType = DirectTCPIPChannelType
			openMsg.SenderChannel = senderChannel
			openMsg.MaxWindowSize = maxWindowSize
			openMsg.MaxPacketSize = maxPacketSize
			openMsg.Host = lf.remoteHost
			openMsg.Port = uint32(lf.remotePort)
			openMsg.OriginatorIPAddress = localAddr.IP.String()
			openMsg.OriginatorPort = uint32(localAddr.Port)
			return openMsg
		},
	)
	if err != nil {
		return
	}

	stream := ssh.NewStream(ch)
	relayStreams(conn, stream)
}

// StreamFromRemotePort requests the remote side to listen on a port and deliver
// incoming connections as SSH streams (without local TCP listeners).
//
// Incoming connections are delivered via the OnStreamOpened callback or via
// WaitForForwardedPort/ConnectToForwardedPort.
//
// If remotePort is 0, the remote side dynamically allocates a port.
// Returns the ForwardedPort with the actual remote port, or an error.
func (pfs *PortForwardingService) StreamFromRemotePort(
	ctx context.Context,
	remoteIPAddress string,
	remotePort int,
) (*ForwardedPort, error) {
	if remoteIPAddress == "" {
		remoteIPAddress = "127.0.0.1"
	}

	msg := pfs.messageFactory().CreateRequestMessage(remotePort)
	msg.RequestType = PortForwardRequestType
	msg.WantReply = true
	msg.AddressToBind = remoteIPAddress
	msg.Port = uint32(remotePort)

	success, respPayload, err := pfs.session.RequestWithPayload(ctx, msg, true)
	if err != nil {
		return nil, err
	}
	if !success {
		return nil, fmt.Errorf("remote port streaming request rejected")
	}

	actualPort := remotePort
	if len(respPayload) > 1 {
		respMsg := &PortForwardSuccessMessage{}
		if err := messages.ReadMessage(respMsg, respPayload); err == nil && respMsg.Port != 0 {
			actualPort = int(respMsg.Port)
		}
	}

	rf := &remoteForwarder{
		remoteHost: remoteIPAddress,
		remotePort: actualPort,
		isStream:   true,
	}

	pfs.mu.Lock()
	pfs.remoteForwarders[actualPort] = rf
	pfs.notifyForwarderAdded()
	pfs.mu.Unlock()

	fp := &ForwardedPort{
		RemoteHost: remoteIPAddress,
		RemotePort: actualPort,
	}

	// Track this forwarding in the collection.
	pfs.RemoteForwardedPorts.Add(actualPort, fp)

	return fp, nil
}

// StreamToRemotePort opens a direct-tcpip channel to the specified remote
// host and port and returns it as an io.ReadWriteCloser stream.
func (pfs *PortForwardingService) StreamToRemotePort(
	ctx context.Context,
	remoteHost string,
	remotePort int,
) (io.ReadWriteCloser, error) {
	ch, err := pfs.session.OpenChannelWithMessage(
		ctx,
		DirectTCPIPChannelType,
		func(senderChannel, maxWindowSize, maxPacketSize uint32) messages.Message {
			openMsg := pfs.messageFactory().CreateChannelOpenMessage(remotePort)
			openMsg.ChannelType = DirectTCPIPChannelType
			openMsg.SenderChannel = senderChannel
			openMsg.MaxWindowSize = maxWindowSize
			openMsg.MaxPacketSize = maxPacketSize
			openMsg.Host = remoteHost
			openMsg.Port = uint32(remotePort)
			openMsg.OriginatorIPAddress = "127.0.0.1"
			openMsg.OriginatorPort = 0
			return openMsg
		},
	)
	if err != nil {
		return nil, err
	}

	return ssh.NewStream(ch), nil
}

// ConnectToForwardedPort connects to a port that has been forwarded via
// StreamFromRemotePort by waiting for the next incoming forwarded-tcpip channel
// on that port and returning it as a stream.
//
// Note: this differs from the C# ConnectToForwardedPortAsync, which actively opens
// an SSH channel to the forwarded port (client-initiated). The Go implementation
// passively waits for an incoming forwarded-tcpip channel from the remote side.
// Use this on the side that called StreamFromRemotePort to receive connections
// that arrive on the remote-forwarded port.
func (pfs *PortForwardingService) ConnectToForwardedPort(
	ctx context.Context,
	forwardedPort int,
) (io.ReadWriteCloser, error) {
	ch := make(chan *ssh.Stream, 1)

	pfs.mu.Lock()
	pfs.streamWaiters[forwardedPort] = append(pfs.streamWaiters[forwardedPort], ch)
	pfs.mu.Unlock()

	select {
	case stream := <-ch:
		if stream == nil {
			return nil, fmt.Errorf("port forwarding service closed")
		}
		return stream, nil
	case <-ctx.Done():
		// Remove the waiter.
		pfs.mu.Lock()
		waiters := pfs.streamWaiters[forwardedPort]
		for i, w := range waiters {
			if w == ch {
				pfs.streamWaiters[forwardedPort] = append(waiters[:i], waiters[i+1:]...)
				break
			}
		}
		pfs.mu.Unlock()
		return nil, ctx.Err()
	}
}

// WaitForForwardedPort waits until a forwarded port is available for connection.
// This is useful when using StreamFromRemotePort with dynamic port allocation,
// since the port may not be ready immediately.
func (pfs *PortForwardingService) WaitForForwardedPort(
	ctx context.Context,
	forwardedPort int,
) error {
	for {
		pfs.mu.Lock()
		_, ok := pfs.remoteForwarders[forwardedPort]
		notify := pfs.forwarderNotify
		pfs.mu.Unlock()

		if ok {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-notify:
			// A forwarder was registered — loop to check if it's ours.
		}
	}
}

// relayStreams copies data bidirectionally between two streams until one is closed.
// When either direction's Read/Write fails, both conn and stream are closed
// immediately so the other goroutine's blocking Read is unblocked.
func relayStreams(conn net.Conn, stream *ssh.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)

	// closeOnce ensures both sides are closed exactly once when either direction fails.
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			conn.Close()
			stream.Close()
		})
	}

	// conn → stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := stream.Write(buf[:n]); werr != nil {
					closeBoth()
					return
				}
			}
			if err != nil {
				closeBoth()
				return
			}
		}
	}()

	// stream → conn
	go func() {
		defer wg.Done()
		buf := make([]byte, 8192)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					closeBoth()
					return
				}
			}
			if err != nil {
				closeBoth()
				return
			}
		}
	}()

	wg.Wait()
	// Final close in case neither goroutine triggered closeBoth (shouldn't happen,
	// but defensive).
	closeBoth()
}

// GetPortForwardingService retrieves the port forwarding service from a session,
// activating it if necessary.
func GetPortForwardingService(session *ssh.Session) *PortForwardingService {
	svc := session.GetService(PortForwardingServiceName)
	if svc != nil {
		if pfs, ok := svc.(*PortForwardingService); ok {
			return pfs
		}
	}

	// Activate the service.
	svc = session.ActivateService(PortForwardingServiceName)
	if svc != nil {
		if pfs, ok := svc.(*PortForwardingService); ok {
			return pfs
		}
	}

	return nil
}
