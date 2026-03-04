// Copyright (c) Microsoft Corporation. All rights reserved.

// Package tcp provides TCP client/server wrappers and port forwarding for
// Dev Tunnels SSH.
//
// This package builds on the core ssh package to provide:
//   - [Client]: TCP SSH client that connects to a host:port and establishes an SSH session
//   - [Server]: TCP SSH server that listens on a port and accepts SSH connections
//   - [PortForwardingService]: local and remote port forwarding over SSH channels
//
// Port forwarding supports both local-to-remote and remote-to-local directions.
// The [PortForwardingService] is activated as an SSH service and manages the
// lifecycle of forwarded ports, including automatic channel creation for each
// incoming connection.
//
// Note: [PortForwardingService.ConnectToForwardedPort] differs from the C#
// implementation. In Go, it returns a connected [net.Conn] directly, while
// in C# it returns a [Stream] that may require additional setup. See the
// method documentation for details.
package tcp
