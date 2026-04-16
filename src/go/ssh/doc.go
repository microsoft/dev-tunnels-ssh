// Copyright (c) Microsoft Corporation. All rights reserved.

// Package ssh provides the core SSH2 protocol implementation for Microsoft Dev Tunnels.
//
// This package implements the SSH2 protocol over any bidirectional stream (not just TCP),
// supporting session management, channel multiplexing, key exchange, authentication,
// and session reconnection.
//
// # Architecture
//
// The central type is [Session], which manages the connection lifecycle and message
// dispatch. Sessions are created via [ClientSession] (for initiating connections) or
// [ServerSession] (for accepting connections). Both embed Session and add role-specific
// behavior.
//
// Sessions operate over any [io.ReadWriteCloser], enabling SSH over TCP, named pipes,
// WebSockets, or in-memory pipes for testing.
//
// # Key Exchange and Encryption
//
// Algorithm negotiation follows RFC 4253. Supported algorithms are configured via
// [SessionConfig] and negotiated during the initial key exchange. The library supports
// ECDH (P-256, P-384, P-521), DH (group14, group16), AES-GCM, AES-CTR, AES-CBC,
// and HMAC-SHA2 variants.
//
// A nil entry in an algorithm list means "none" (no security), useful for testing
// or trusted network scenarios.
//
// # Channel Multiplexing
//
// Multiple logical channels can be multiplexed over a single session. Channels
// support bidirectional data transfer with flow control (window management).
// Use [Session.OpenChannel] to create channels and [Session.AcceptChannel] to
// accept incoming channel requests.
//
// # Authentication
//
// Authentication is event-driven via the [Session.OnAuthenticating] callback.
// Supported methods include password, public key, and keyboard-interactive.
//
// # Reconnection
//
// Sessions support transparent reconnection over a new stream without losing
// channel state. This is negotiated via protocol extensions and enabled
// automatically when both sides support it.
//
// # Services
//
// Services extend session functionality. They are activated on-demand when a
// matching service request, channel type, or session request is received.
// The [Service] interface defines the contract for pluggable services.
package ssh
