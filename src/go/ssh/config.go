// Copyright (c) Microsoft Corporation. All rights reserved.

package ssh

import "fmt"

// Protocol extension name constants.
//
// The @microsoft.com domain is used for all Dev Tunnels SSH custom extensions.
// This matches the C# and TypeScript implementations exactly, and is the domain
// expected by the Dev Tunnels relay service. Extensions are negotiated
// via RFC 8308 ext-info messages during key exchange.
const (
	ExtensionServerSignatureAlgorithms = "server-sig-algs"
	ExtensionOpenChannelRequest        = "open-channel-request@microsoft.com"
	ExtensionSessionReconnect          = "session-reconnect@microsoft.com"
	ExtensionSessionLatency            = "session-latency@microsoft.com"
)

// Extension request type constants.
//
// Uses the same @microsoft.com domain as the extension names above.
// The keepalive extension uses @openssh.com for OpenSSH compatibility.
const (
	ExtensionRequestInitialChannelRequest  = "initial-channel-request@microsoft.com"
	ExtensionRequestKeepAlive              = "keepalive@openssh.com"
	ExtensionRequestEnableSessionReconnect = "enable-session-reconnect@microsoft.com"
)

// Well-known algorithm names used in configuration.
const (
	AlgoKexEcdhNistp521  = "ecdh-sha2-nistp521"
	AlgoKexEcdhNistp384  = "ecdh-sha2-nistp384"
	AlgoKexEcdhNistp256  = "ecdh-sha2-nistp256"
	AlgoKexDHGroup16     = "diffie-hellman-group16-sha512"
	AlgoKexDHGroup14     = "diffie-hellman-group14-sha256"
	AlgoKexNone          = "none"

	AlgoPKRsaSha512       = "rsa-sha2-512"
	AlgoPKRsaSha256       = "rsa-sha2-256"
	AlgoPKEcdsaSha2P384   = "ecdsa-sha2-nistp384"
	AlgoPKEcdsaSha2P256   = "ecdsa-sha2-nistp256"
	AlgoPKEcdsaSha2P521   = "ecdsa-sha2-nistp521"
	AlgoPKNone            = "none"

	AlgoEncAes256Gcm = "aes256-gcm@openssh.com"
	AlgoEncAes256Cbc = "aes256-cbc"
	AlgoEncAes256Ctr = "aes256-ctr"
	AlgoEncNone      = "none"

	AlgoHmacSha512Etm = "hmac-sha2-512-etm@openssh.com"
	AlgoHmacSha256Etm = "hmac-sha2-256-etm@openssh.com"
	AlgoHmacSha512    = "hmac-sha2-512"
	AlgoHmacSha256    = "hmac-sha2-256"
	AlgoHmacNone      = "none"

	AlgoCompNone = "none"
)

// Well-known authentication method names.
const (
	AuthMethodNone                = "none"
	AuthMethodPassword            = "password"
	AuthMethodPublicKey           = "publickey"
	AuthMethodKeyboardInteractive = "keyboard-interactive"
	AuthMethodHostBased           = "hostbased"
)

// MessageHandler is a callback that handles a custom SSH message type.
// The payload parameter contains the full raw message including the type byte.
type MessageHandler func(payload []byte) error

// SessionConfig specifies the sets of algorithms and other configuration
// for an SSH session. Each collection of algorithms is in order of preference.
// Server and client negotiate the most-preferred algorithm supported by both.
type SessionConfig struct {
	// ProtocolExtensions lists protocol extensions enabled for the session.
	ProtocolExtensions []string

	// AuthenticationMethods lists enabled authentication methods.
	AuthenticationMethods []string

	// KeyExchangeAlgorithms lists enabled KEX algorithms in preference order.
	// A "none" entry means no key exchange (no security).
	KeyExchangeAlgorithms []string

	// PublicKeyAlgorithms lists enabled public key algorithms in preference order.
	PublicKeyAlgorithms []string

	// EncryptionAlgorithms lists enabled encryption algorithms in preference order.
	EncryptionAlgorithms []string

	// HmacAlgorithms lists enabled HMAC algorithms in preference order.
	HmacAlgorithms []string

	// CompressionAlgorithms lists enabled compression algorithms in preference order.
	CompressionAlgorithms []string

	// TraceChannelData enables tracing of all channel data messages.
	TraceChannelData bool

	// MaxClientAuthenticationAttempts is the max number of client auth attempts
	// allowed by the server. Default is 5.
	MaxClientAuthenticationAttempts int

	// EnableKeyExchangeGuess controls whether the client sends a KEX guess
	// before receiving server preferences. Disabled by default.
	EnableKeyExchangeGuess bool

	// KeepAliveIntervalSeconds is the keep-alive interval in seconds (0 = disabled).
	KeepAliveIntervalSeconds int

	// KeyRotationThreshold is the number of bytes after which key rotation is triggered.
	// Default is 512MB. This should only be changed for testing.
	KeyRotationThreshold int

	// MaxReconnectMessageCacheSize is the maximum number of sent messages to cache
	// for reconnection retransmission. When the cache exceeds this limit, the oldest
	// messages are evicted. Default is 1024.
	MaxReconnectMessageCacheSize int

	// MaxChannelWindowSize overrides the default channel window size.
	// Zero means use DefaultMaxWindowSize (1 MB).
	MaxChannelWindowSize uint32

	// MessageHandlers maps SSH message type numbers to custom handler functions.
	// When a message is received with a type that has a registered handler,
	// the handler is called instead of sending an UnimplementedMessage response.
	// This allows extending the SSH protocol without modifying the library.
	MessageHandlers map[byte]MessageHandler

	// ServiceRegistrations maps service names to their activation rules and factories.
	// Use AddService() to register services.
	ServiceRegistrations map[string]*ServiceRegistration
}

// registerDefaultServices registers built-in services on a config.
func registerDefaultServices(config *SessionConfig) {
	config.AddService(AuthServiceName, ServiceActivation{
		ServiceRequest: AuthServiceName,
	}, newAuthenticationService, nil)

	config.AddService(ConnectionServiceName, ServiceActivation{
		ServiceRequest: ConnectionServiceName,
	}, newConnectionService, nil)
}

// NewDefaultConfig creates a new SessionConfig with default secure algorithms.
// The algorithm preference order matches the C# and TypeScript implementations.
func NewDefaultConfig() *SessionConfig {
	config := &SessionConfig{
		ProtocolExtensions: []string{
			ExtensionServerSignatureAlgorithms,
			ExtensionOpenChannelRequest,
		},
		AuthenticationMethods: []string{
			AuthMethodNone,
			AuthMethodPassword,
			AuthMethodPublicKey,
			AuthMethodKeyboardInteractive,
		},
		KeyExchangeAlgorithms: []string{
			AlgoKexEcdhNistp384,
			AlgoKexEcdhNistp256,
			AlgoKexDHGroup16,
			AlgoKexDHGroup14,
		},
		PublicKeyAlgorithms: []string{
			AlgoPKRsaSha512,
			AlgoPKRsaSha256,
			AlgoPKEcdsaSha2P384,
			AlgoPKEcdsaSha2P256,
		},
		EncryptionAlgorithms: []string{
			AlgoEncAes256Gcm,
			AlgoEncAes256Cbc,
			AlgoEncAes256Ctr,
		},
		HmacAlgorithms: []string{
			AlgoHmacSha512Etm,
			AlgoHmacSha256Etm,
			AlgoHmacSha512,
			AlgoHmacSha256,
		},
		CompressionAlgorithms: []string{
			AlgoCompNone,
		},
		MaxClientAuthenticationAttempts:  5,
		KeyRotationThreshold:            512 * 1024 * 1024, // 512 MiB
		MaxReconnectMessageCacheSize:    1024,
	}
	registerDefaultServices(config)
	return config
}

// NewDefaultConfigWithReconnect creates a new SessionConfig with default secure
// algorithms and reconnection extensions enabled.
func NewDefaultConfigWithReconnect() *SessionConfig {
	config := NewDefaultConfig()
	config.ProtocolExtensions = append(config.ProtocolExtensions,
		ExtensionSessionReconnect,
		ExtensionSessionLatency,
	)
	return config
}

// NewNoSecurityConfig creates a new SessionConfig with no-security algorithms.
// All algorithm lists contain only "none", meaning no encryption, no HMAC, no key exchange.
func NewNoSecurityConfig() *SessionConfig {
	config := &SessionConfig{
		ProtocolExtensions: []string{
			ExtensionServerSignatureAlgorithms,
			ExtensionOpenChannelRequest,
		},
		AuthenticationMethods: []string{
			AuthMethodNone,
			AuthMethodPassword,
			AuthMethodPublicKey,
			AuthMethodKeyboardInteractive,
		},
		KeyExchangeAlgorithms: []string{
			AlgoKexNone,
		},
		PublicKeyAlgorithms: []string{
			AlgoPKNone,
		},
		EncryptionAlgorithms: []string{
			AlgoEncNone,
		},
		HmacAlgorithms: []string{
			AlgoHmacNone,
		},
		CompressionAlgorithms: []string{
			AlgoCompNone,
		},
		MaxClientAuthenticationAttempts:  5,
		KeyRotationThreshold:            512 * 1024 * 1024,
		MaxReconnectMessageCacheSize:    1024,
	}
	registerDefaultServices(config)
	return config
}

// hasNonNone returns true if the slice contains any entry other than "none".
func hasNonNone(algos []string) bool {
	for _, a := range algos {
		if a != "none" {
			return true
		}
	}
	return false
}

// Validate checks the session configuration for internal consistency.
// It returns an error if algorithm combinations are invalid, such as
// encryption algorithms specified without any key exchange algorithm.
func (c *SessionConfig) Validate() error {
	hasEncryption := hasNonNone(c.EncryptionAlgorithms)
	hasHmac := hasNonNone(c.HmacAlgorithms)
	hasKex := hasNonNone(c.KeyExchangeAlgorithms)

	if hasEncryption && !hasKex {
		return fmt.Errorf("invalid config: encryption algorithms require at least one non-\"none\" key exchange algorithm")
	}
	if hasHmac && !hasKex {
		return fmt.Errorf("invalid config: HMAC algorithms require at least one non-\"none\" key exchange algorithm")
	}
	return nil
}
