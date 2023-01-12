# Project

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.

# Dev Tunnels SSH Library
A Secure Shell (SSH2) client and server protocol library, implemented in both
C# and TypeScript.

## Feature Highlights
 - SSH over any .NET Stream or JavaScript stream (including but not limited to
   TCP socket streams)
 - Configurable, extensible, negotiated algorithms for key-exchange, encryption,
   integrity (HMAC), and public-key authentication
 - Channel multiplexing, with ability to stream data to/from channels
 - Port-forwarding, with ability to stream data to/from remote ports
 - Piping between two sessions can relay all channels and port-forwarding
 - Extensible channel request handling (for "exec", "shell", or custom requests)
 - Supports [reconnecting](./ProtocolExtensions.md) a disconnected session
   without disrupting channel streams.
 - Compatible with common SSH software. (Tested against OpenSSH.)
 - Supports importing and exporting several key formats, including
   password-protected keys.

### Limitations
The following features are not implemented in this library, though they could be built
on top of it:
 - Allowing a client to login to a user account on the server
 - Connecting to a shell on the server
 - Invoking shell commands on the server
 - Transferring files (SCP or SFTP)
 - Rendering a terminal on the client side

Future development may add support for some of these capabilities, likely in the
form of additional optional packages.

## C# (.NET Standard)
.NET Standard 2.0 & 2.1 support means it can be used with .NET Framework 4.7+ on
Windows or .NET Core 2.0+ on any platform. It's tested on Windows, Mac, & Ubuntu. For
details about the .NET library, see [src/cs/Ssh/README.md](./src/cs/Ssh/README.md).

## TypeScript (Node.js or Browser)
The TypeScript implementation supports either Node.js (>= 14.x) or a browser
environment. The Node.js version is tested on Windows, Mac & Unbuntu; the browser
version is tested on Chrome & Edge Chromium, though it should work in any modern
browser that supports the web crypto API. Note that since script on a web page
cannot access native TCP sockets, the standard use of SSH over TCP is not possible;
some other stream transport like a websocket may be used. For details about the
TypeScript library, see [src/ts/ssh/README.md](./src/ts/ssh/README.md).

## Packages

|                                          | C# NuGet package | TS npm package |
| ---------------------------------------- | ---------------- | -------------- |
| SSH core protocol and crypto             | [**`Microsoft.DevTunnels.Ssh`**](https://www.nuget.org/packages/Microsoft.DevTunnels.Ssh) | [**`@microsoft/dev-tunnels-ssh`**](https://www.npmjs.com/package/@microsoft/dev-tunnels-ssh)
| SSH public/private key import/export     | [**`Microsoft.DevTunnels.Ssh.Keys`**](https://www.nuget.org/packages/Microsoft.DevTunnels.Ssh.Keys/) | [**`@microsoft/dev-tunnels-ssh-keys`**](https://www.npmjs.com/package/@microsoft/dev-tunnels-ssh-keys)
| SSH TCP connections and port-forwarding  | [**`Microsoft.DevTunnels.Ssh.Tcp`**](https://www.nuget.org/packages/Microsoft.DevTunnels.Ssh.Tcp/) | [**`@microsoft/dev-tunnels-ssh-tcp`**](https://www.npmjs.com/package/@microsoft/dev-tunnels-ssh-tcp)

The optional "keys" and "TCP" packages depend on the core package. All SSH packages
in an app must be the same major and minor version; the patch version (3rd component)
may differ if necessary. In other words, any changes that impact cross-package
dependencies will increment at least the minor version.

## Development
See [README-dev.md](README-dev.md).

## SSH Algorithms Support
Crypto algorithms below rely on platform APIs in .NET ([System.Security.Cryptography](
https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography?view=netstandard-2.1
)), Node.js ([crypto module](https://nodejs.org/api/crypto.html)) or browsers ([web crypto](
https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)). There is _one_ use of
a 3rd-party library: the [diffie-hellman](https://github.com/crypto-browserify/diffie-hellman)
package is required in browsers because there is no corresponding web crypto API.

Legend:  
    ✔✔✔ - Enabled and preferred in default session configuration.  
    ✔✔ - Enabled (but not preferred) in default session configuration.  
    ✔ - Supported and can be enabled in custom session configuration.  
    ☑ - Coming soon (working in a branch or PR).  
    ?? - Under consideration for the future.

| Type         | Algorithm Name                  | Status   |
| -------------| ------------------------------- | -------- |
| | |
| key-exchange | `diffie-hellman-group16-sha512` | ✔✔
| key-exchange | `diffie-hellman-group14-sha256` | ✔✔
| key-exchange | `ecdh-sha2-nistp521`            | ✔
| key-exchange | `ecdh-sha2-nistp384`            | ✔✔✔
| key-exchange | `ecdh-sha2-nistp256`            | ✔✔
| key-exchange | `curve25519-sha256`             | ??   [1]
| | |
| public-key   | `rsa-sha2-512`                  | ✔✔✔
| public-key   | `rsa-sha2-256`                  | ✔✔
| public-key   | `ecdsa-sha2-nistp256`           | ✔✔
| public-key   | `ecdsa-sha2-nistp384`           | ✔✔
| public-key   | `ecdsa-sha2-nistp521`           | ✔
| public-key   | `ssh-ed25519`                   | ??   [1]
| public-key   | `*-cert-v01@openssh.com`        | ??   [2]
| | |
| cipher       | `aes256-cbc`                    | ✔✔  [3]
| cipher       | `aes256-ctr`                    | ✔✔
| cipher       | `aes192-cbc`                    | ✔
| cipher       | `aes192-ctr`                    | ✔
| cipher       | `aes128-cbc`                    | ✔
| cipher       | `aes128-ctr`                    | ✔
| cipher       | `aes256-gcm@openssh.com`        | ✔✔✔
| cipher       | `aes128-gcm@openssh.com`        | ✔
| cipher       | `chacha20-poly1305@openssh.com` | ??   [1]
| | |
| mac          | `hmac-sha2-512`                 | ✔✔
| mac          | `hmac-sha2-256`                 | ✔✔
| mac          | `hmac-sha2-512-etm@openssh.com` | ✔✔✔
| mac          | `hmac-sha2-256-etm@openssh.com` | ✔✔


[1] May require use of 3rd-party libs, though Curve25519 APIs are under
consideration for [.NET](https://github.com/dotnet/runtime/issues/14741) and
[web crypto](https://github.com/w3c/webcrypto/issues/233).  
[2] OpenSSH certificate support should be possible with some work.  
[3] AES-CBC is not supported in browsers due to a [limitation](
https://github.com/w3c/webcrypto/issues/73) of the web crypto API. AES-CTR or
AES-GCM works fine.

There is no plan to have built-in support for older algorithms known to be
insecure (for example SHA-1), though in some cases these can be easily added by
the application.

## Key Format Support
Support for importing and exporting keys in various formats is provided in
NuGet/npm packages separate from the core SSH functionality. Some key formats
are only implemented in _either_ the C# or TS libraries, not both.
See also [src/cs/SSH.Keys/README.md](src/cs/SSH.Keys/README.md)
or [src/ts/ssh-keys/README.md](src/ts/ssh-keys/README.md).

| Key Format           | Key Algorithm | Password Protection | Format Description |
| -------------------- | ------------- | ------------------- | ------------------ |
| SSH public key       | RSA<br>ECDSA  | N/A                 | Single line key algorithm name, base64-encoded key bytes, and optional comment. Files conventionally end with `.pub`.
| PKCS#1               | RSA           | _import&nbsp;only_  | Starts with one of:<br>`-----BEGIN RSA PUBLIC KEY-----`<br>`-----BEGIN RSA PRIVATE KEY-----`
| SEC1                 | ECDSA         | _import&nbsp;only_  | Starts with:<br>`-----BEGIN EC PRIVATE KEY-----`
| PKCS#8               | RSA<br>ECDSA  | ✔                  | Starts with one of:<br>`-----BEGIN PUBLIC KEY-----`<br>`-----BEGIN PRIVATE KEY-----`<br>`-----BEGIN ENCRYPTED PRIVATE KEY-----`
| SSH2<br>_C# only_    | RSA           | ✔                  | Starts with one of:<br>`---- BEGIN SSH2 PUBLIC KEY ----`<br>`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`
| OpenSSH<br>_C# only_ | RSA<br>ECDSA  | ✔                  | Starts with one of:<br>`-----BEGIN OPENSSH PUBLIC KEY-----`<br>`-----BEGIN OPENSSH PRIVATE KEY-----`
| JWK<br>_TS only_     | RSA<br>ECDSA  | N/A                 | JSON with key algorithm name and parameters

## References
The following RFCs define the SSH protocol:
 - [RFC 4250 - SSH Protocol Assigned Numbers](https://tools.ietf.org/html/rfc4250)
 - [RFC 4251 - SSH Protocol Architecture](https://tools.ietf.org/html/rfc4251)
 - [RFC 4252 - SSH Authentication Protocol](https://tools.ietf.org/html/rfc4252)
 - [RFC 4253 - SSH Transport Layer Protocol](https://tools.ietf.org/html/rfc4253)
 - [RFC 4254 - SSH Connection Protocol](https://tools.ietf.org/html/rfc4254)
 - [RFC 4716 - SSH Public Key File Format](https://tools.ietf.org/html/rfc4716)
 - [RFC 5647 - AES GCM for the SSH Protocol](https://tools.ietf.org/html/rfc5647)
 - [RFC 5656 - EC Algorithm Integration in SSH](https://tools.ietf.org/html/rfc5656)
 - [RFC 8308 - SSH Extension Negotiation](https://tools.ietf.org/html/rfc8308)
