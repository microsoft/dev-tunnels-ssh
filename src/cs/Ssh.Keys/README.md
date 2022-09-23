# Dev Tunnels SSH Keys Library
Enables importing and exporting SSH public and private keys in various formats.
Password-protection of private keys is also supported when importing and
exporting.

## Supported Key Algorithms
 - RSA (2048, 4096)
 - ECDSA (P-256, P-384, P-521)

## Supported Key Formats

 - **SSH public key** - Single line starting with a key algorithm name
   such as `ssh-rsa`, followed by base64-encoded key bytes, and an optional
   comment. Files in this format typically end with `.pub`.

 - **PKCS#1 public or private RSA key** - PEM-encoded keys in this format begin
   with one of the following:  
   `-----BEGIN RSA PUBLIC KEY-----`  
   `-----BEGIN RSA PRIVATE KEY-----`  

 - **SEC1 private EC key** - PEM-encoded keys in this format begin with:  
   `-----BEGIN EC PRIVATE KEY-----`  

 - **PKCS#8 public or private key** - PEM-encoded keys in this format begin
   with one of the following:  
   `-----BEGIN PUBLIC KEY-----`  
   `-----BEGIN PRIVATE KEY-----`  
   `-----BEGIN ENCRYPTED PRIVATE KEY-----`

 - **OpenSSH private key** - PEM-encoded keys in this format begin with one
   of the following:  
   `-----BEGIN OPENSSH PUBLIC KEY-----`  
   `-----BEGIN OPENSSH PRIVATE KEY-----`  

 - **SSH2 public or private key:** - These keys use a PEM-_like_ encoding
   that begins with one of the following:  
   `---- BEGIN SSH2 PUBLIC KEY ----`  
   `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`  

Private keys in any of the formats may be passphrase-protected, meaning the
private key is encrypted using an encryption key derived from a passphrase.
(The encryption used by the PKCS#1/SEC1 formats is weak and no longer
recommended.)

For the key formats that are typically PEM-encoded, the equivalent binary (DER)
format is also supported.

## Examples
Use static methods on the `KeyPair` class to import or export keys. When
importing, the key format can be auto-detected in most cases.

```C#
// Import my password-protected RSA private key from a file.
IKeyPair privateKey = KeyPair.ImportPrivateKeyFile(@".ssh\id_rsa", myPassword);

// Use the private key for client public key authentication.
SshClientSession session = ...
SshClientCredentials credentials = (username, privateKey);
bool result = await session.AuthenticateAsync(credentials);
```

When exporting, you can specify the format, and optionally supply a password
for encrypting the key. The default format is **PKCS#8** because it has broad
support and strong encryption when using password protection.
