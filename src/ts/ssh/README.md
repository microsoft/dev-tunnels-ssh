# Dev Tunnels SSH Library
A Secure Shell (SSH2) client and server protocol implementation for Node.js
and browser environments.

## Feature Highlights
 - SSH over any JavaScript stream (including but not limited to Node.js
 TCP sockets and browser websockets)
 - Configurable, extensible, negotiated algorithms for key-exchange, encryption,
   integrity (HMAC), and public-key authentication
 - Channel multiplexing, with ability to stream data to/from channels
 - Piping between two sessions can relay all channels and port-forwarding
 - Extensible channel request handling (for "exec", "shell", or custom requests)
 - Supports reconnecting a disconnected session without disrupting channel streams.
 - Compatible with common SSH software. (Tested against OpenSSH.)

## Requirements
The TypeScript implementation supports either Node.js (>= 8.x) or a
browser environment. When running on Node.js, it uses the Node.js built-in
[crypto](https://nodejs.org/api/crypto.html) module. When running in a browser
it uses the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API),
which is supported by all modern browsers. However note that since script on
a web page cannot access native TCP sockets, the standard use of SSH over
TCP is not possible; some other stream transport like a websocket may be used.

## Packages
The optional `dev-tunnels-ssh-tcp` and `dev-tunnels-ssh-keys` depend on the core `dev-tunnels-ssh` package.
