# Dev Tunnels SSH TCP Library
Includes `SshClient` and `SshServer` convenience classes for establishing SSH
sessions over TCP, and the `PortForwardingService` class that enables forwarding
TCP ports between client and server.

## Examples

### Forward from a server port to a client port
```TypeScript
// Port-forwarding is not enabled by default. It must be added to the session configuration
// on both client and server sides.
const config = new SshSessionConfiguration();
config.addService(PortForwardingService);

const client = new SshClient(config);
const session: SshClientSession = await client.openSession(host, port);

// Handle server and client authentication.
session.onAuthenticating((e) => { ... });
if (!(await session.authenticate(credentials))) {
	throw new Error('Authentication failed.');
}

// Start port-forwarding.
const pfs = session.activateService(PortForwardingService);
const forwarder: RemotePortForwarder = await pfs.forwardFromRemotePort('::', remotePort);
// Connections to the port on the server will now be forwarded to
// the same port on the client.
forwarder.dispose();
// New connections to the server port are no longer forwarded.
// (Existing forwarded connections may remain alive until the session is closed.)
```

### Stream to a server port
```TypeScript
const session: SshClientSession = ...

const pfs = session.activateService(PortForwardingService);
const stream: SshStream = await pfs.streamToRemotePort('localhost', remotePort);
// The stream data is forwarded to/from the port on the server.
```

## Browser compatibility
This package has limited capabilities when running in a browser. Obviously a browser
cannot access local TCP ports. However, it is possible to _stream_ to/from
server ports. The `streamFromRemotePort()` and `streamToRemotePort()` methods are
validated working in a browser environment.
