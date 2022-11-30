# Dev Tunnels SSH Library
A Secure Shell (SSH2) client and server protocol implementation for .NET.

## Feature Highlights
 - SSH over any .NET Stream (including but not limited to a TCP socket stream)
 - Configurable, extensible, negotiated algorithms for key-exchange, encryption,
   integrity (HMAC), and public-key authentication
 - Channel multiplexing, with ability to stream data to/from channels
 - Extensibility for handling custom session requests and channel requests
 - Compatible with common SSH software. (Tested against OpenSSH.)

## Requirements
This library targets the following .NET versions:
 - .NET Framework 4.8
 - .NET Standard 2.1 (.NET Core 3.1, .NET 5)
 - .NET 6

The .NET Framework target runs only on Windows (of course); the other targets support
Windows, Mac, and Linux.

Some minor functionality is not available in the .NET Framework target:
 - **AES-GCM** - This cipher algorithm is available (and preferred) when using
   .NET Standard 2.1 or later. If using .NET Framework, or if the other
   side does not support it, then other cipher and MAC algorithms (AES-CTR,
   SHA2-ETM) are used instead.
 - **Use of `Span<T>`** - There is no functional difference, but this reduces
   the amount of memory allocations and copies, allowing for a slight
   performance improvement with .NET Standard 2.1 or later.

### OS Requirements
Crypto algorithms work across all .NET Core platforms: Windows, Mac, and Linux.
On Windows the .NET Core crypto implementations bind to
[CNG](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-features) via
`ncrypt.dll`. On Mac and Linux, .NET Core uses OpenSSL.

Use of ECDH on Windows requires a capability (`BCRYPT_KDF_RAW_SECRET`) that is
only available starting in Windows 10. The ECDH algorithm will be automatically
disabled on older Windows versions, so negotiation will fall back to regular
DH. _Note proper Windows version detection for ECDH may require an
[application manifest](..\..\..\bench\cs\SSH.Benchmark\app.manifest)._

## Basic Examples
Note these examples depend on the `SshClient` and `SshServer` classes
available in the separate [`Microsoft.DevTunnels.Ssh.Tcp` package](..\Ssh.Tcp\README.md).

### Client example
This example connects to an SSH server at a specified host and port,
authenticates using a username and password, and executes a command.

```C#
var client = new SshClient(
    SshSessionConfiguration.Default,
    new TraceSource(nameof(SshClient)));
SshClientSession session = await client.OpenSessionAsync(host, port);

// Handle server public key authentication.
session.Authenticating += (_, e) =>
{
    e.AuthenticationTask = Task.Run(() =>
    {
        // TODO: Validate the server's public key.
        // Return null if validation failed.
        IKeyPair hostKey = e.PublicKey;

        var serverIdentity = new ClaimsIdentity();
        return new ClaimsPrincipal(serverIdentity);
    });
};

SshClientCredentials credentials = (username, password);
if (!(await session.AuthenticateAsync(credentials)))
{
    throw new Exception("Authentication failed.");
}

// Open a channel, send a command, and read the command result.
SshChannel channel = await session.OpenChannelAsync();
bool commandAuthorized = await channel.RequestAsync(
    new CommandRequestMessage("example command"));
if (commandAuthorized)
{
    using (var channelStream = new SshStream(channel))
    {
        var result = await new StreamReader(channelStream).ReadToEndAsync();
        Console.WriteLine(result);
    }
}
await channel.CloseAsync();
```

### Server example
This example runs an SSH server listening on a specified port,
authenticates clients when they connect, and processes command requests.
```C#
var server = new SshServer(
    SshSessionConfiguration.Default,
    new TraceSource(nameof(SshServer)));

// Generate a host key and use it for server authentication.
var hostKey = SshAlgorithms.PublicKey.RsaWithSha512.Value.GenerateKeyPair();
server.Credentials = new[] { hostKey };

// Handle client authentication.
server.SessionAuthenticating += (_, e) =>
{
    var authenticationType = e.AuthenticationType;
    e.AuthenticationTask = Task.Run(() =>
    {
        // TODO: Depending on the authentication type, validate the client's public key
        // or password, available on the event object. Return null if validation failed.
        var userIdentity = new ClaimsIdentity(new Claim[]
        {
            new Claim(ClaimTypes.NameIdentifier, e.Username),
        });
        return new ClaimsPrincipal(userIdentity);
    });
};

// Handle channel command requests.
server.ChannelRequest += (_, e) =>
{
    if (e.RequestType == ChannelRequestTypes.Command)
    {
        var commandRequest = e.Request.ConvertTo<CommandRequestMessage>();
        string command = commandRequest.Command;

        // TODO: Check if command is authorized for the authenticated client
        // using identity/claims of the principal.
        e.IsAuthorized = (e.Principal != null);

        Task.Run(() =>
        {
            using (var channelStream = new SshStream(channel))
            {
                // TODO: Execute the command (asynchronously) and
                // send results back over the stream.
                var channelWriter = new StreamWriter(channelStream);
                channelWriter.WriteLine("example result");
            }
        });
    }
};

await server.AcceptSessionsAsync(port);
```

## Extensibility
This library prioritizes flexiblity over completeness; if something SSH-related
is not implemented directly in the library, there is generally a way to plug in
that support without changing the library itself.

### Algorithms
Algorithms for an SSH session can be configured using an instance of the
`SshSessionConfiguration` class. Additional built-in or external algorithms may
be added to the collections on the session configuration.

A set of common algorithms for key-exchange, encryption, HMAC, and public-key
auth are built-in, exposed via the `SshAlgorithms` class. A subset of those
(the most secure ones) are enabled in `SshSessionConfiguration.Default`.

### Authentication
Two-way authentication is supported. A server or client MUST handle the
`Session.Authenticating` event to confirm authentication, otherwise
authentication fails. For public keys, the library takes care of verifying
the signature (that proves the other side possesses the corresponding private
key). Then it's up to the event-handler to validate that the public key matches
an external list of known keys for the host or user. (Or in the case of
password authentication it must validate that the user's password is correct).

### Key management
The library does not implement any key-management scheme, though it can import
and export RSA and EC keys in many formats -- see the static methods on the
`KeyPair` class. It is up to the application to ensure exported keys are
protected with appropriate access controls (e.g. file permissions).

Note the key import/export functionality is published as a separate `SSH.Keys`
assembly and NuGet package.

### Messages
Most of the standard SSH messages have corresponding `Message` subclasses. It
is possible to define custom message subclasses and send them over a session
or channel. For example a custom channel request may extend the
`ChannelRequestMessage` with additional fields.

### Services
Custom services can be added to the server-side or client-side session
configuration, to be automatically activated for handling incoming session or
channel requests. See documentation on the `SshService` abstract base class
for details. Or see code in the port-forwarding package that is built on
this extensibility mechanism.

### Requests / Commands
A client or server can handle `Session.Request` or `Channel.Request` events to
process requests that are not otherwise handled by services. Depending on the
request type, the request object can be converted to a particular (custom)
subclass of `SessionRequestMessage` or `ChannelRequestMessage` to obtain
structured request details. Execution of the request may result in a brief
response followed by closing the channel (as with a `CommandRequestMessage`),
or a long-running two-way conversation (as with a `ShellRequestMessage`).

## Piping
An SSH server can create a "pipe" between two sessions connected to the same
server, to support a "relay" scenario. Once two sessions are connected by a
pipe, messages sent by one client will be forwarded by the server so that
they are received by the other client. This includes:
 - Session requests
 - Channel open requests
 - Channel requests
 - Channel data
 - Channel end
 - Session end

Note a pair of connected pipes is not _end-to-end_ encrypted: each session is
still independently authenticated and encrypted, so the server must decrypt
and re-encrypt messages when forwarding.

Use the `PipeExtensions.PipeAsync()` method to start piping.'

## Future work

### Compression
Currently only the "none" compression algorithm is implemented. It should be
straightforward to add support for the "zlib" compression algorithm, though
compression at the SSH protocol level is generally considered to have limited
value in most scenarios.

### Shell / terminal support
The library doesn't currently offer built-in support for executing commands
or starting a persistent shell in the host operating system on the server
side, or for integrating with a terminal on the client side.

## Acknowledgements
Significant portions of the code in this library were originally derived from
the [FxSsh project](https://github.com/Aimeast/FxSsh), though most of that
has been heavily modified, refactored, and expanded. Smaller snippets were
also borrowed from the [SSH.NET project](https://github.com/sshnet/SSH.NET).
