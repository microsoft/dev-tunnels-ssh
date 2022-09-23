# Dev Tunnels SSH Keys Library
Enables importing and exporting SSH public and private keys in various formats.
Password-protection of private keys is also supported when importing and
exporting some formats.

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

 - **JSON Web Key (JWK)** - Key paramters are formatted as JSON.

Private keys in PKCS#1, SEC1, or PKCS#8 format may be passphrase-protected,
meaning the private key is encrypted using an encryption key derived from a
passphrase. (The encryption used by the PKCS#1/SEC1 formats is weak and no
longer recommended.)

For the key formats that are typically PEM-encoded, the equivalent binary (DER)
format is also supported.

## Example
Use `importKey*`, `exportPublicKey*`, and `exportPrivateKey*` functions provided
by the library to import or export keys. When importing, the key format can be
auto-detected in most cases.

```TypeScript
// Import my password-protected RSA private key from a file.
const privateKey: KeyPair = importPrivateKeyFile('.ssh/id_rsa', myPassword);

// Use the private key for client public key authentication.
const session: SshClientSession = ...
const credentials: SshClientCredentials = { username, publicKeys: [ privateKey ] };
const result: boolean = await session.authenticate(credentials);
```

When exporting, you can specify the format, and optionally supply a password
for encrypting the key. The default format is **PKCS#8** because it has broad
support and strong encryption when using password protection.
