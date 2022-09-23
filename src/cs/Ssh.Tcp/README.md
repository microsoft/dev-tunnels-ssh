# Dev Tunnels SSH TCP Library
Includes `SshClient` and `SshServer` convenience classes for establishing SSH sessions
over TCP, and also enables forwarding TCP ports between client and server. Reference this
package to get port-forwarding extension methods on the `SshClientSession` class.

## Examples

### Forward from a server port to a client port
```C#
// Port-forwarding is not enabled by default. It must be added to the session configuration
// on both client and server sides.
var config = new SshSessionConfiguration();
config.AddService<PortForwardingService>();

var client = new SshClient(config, new TraceSource(nameof(SshClient)));
SshClientSession session = await client.OpenSessionAsync(host, port);

// Handle server and client authentication.
session.Authenticating += ...
if (!(await session.AuthenticateAsync(credentials)))
{
	throw new Exception("Authentication failed.");
}

// Start port-forwarding.
using (RemotePortForwarder forwarder = await session.ForwardFromRemotePortAsync(
	IPAddress.Loopback, remotePort))
{
	// Connections to the port on the server will now be forwarded to
	// the same port on the client.
}
// New connections to the server port are no longer forwarded.
// (Existing forwarded connections may remain alive until the session is closed.)
```

### Stream to a server port
```C#
SshClientSession session = ...
SshStream stream = await session.StreamToRemotePortAsync("localhost", remotePort);
// The stream data is forwarded to/from the port on the server.
```
