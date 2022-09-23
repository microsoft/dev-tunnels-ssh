// Copyright (c) Microsoft. All rights reserved.

using System.Collections.Generic;
using Microsoft.DevTunnels.Ssh.Algorithms;
using RandomNumberGenerator = System.Security.Cryptography.RandomNumberGenerator;

#pragma warning disable CA1034 // Nested types should not be visible
#pragma warning disable CA1724 // Nested types do not conflict with namespace names
#pragma warning disable SA1402 // File may only contain a single type
#pragma warning disable SA1649 // File name should match first type name

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Defines algorithms that may be included in SSH session configuration for negotiation and
/// potential use in SSH sessions.
/// </summary>
/// <remarks>
/// Some algorithms may be unavailable at runtime; those are automatically excluded from
/// negotiation even if they are included in the session configuration.
///
/// Algorithm names reference:
/// http://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml
/// </remarks>
public static class SshAlgorithms
{
	public static class KeyExchange
	{
		public static KeyExchangeAlgorithm? None { get; } = null;

		public static KeyExchangeAlgorithm DHGroup14Sha256 { get; } = new DiffieHellman(DiffieHellman.DHGroup14Sha256, 2048, HmacAlgorithm.Sha256);
		public static KeyExchangeAlgorithm DHGroup16Sha512 { get; } = new DiffieHellman(DiffieHellman.DHGroup16Sha512, 4096, HmacAlgorithm.Sha512);

#if SSH_ENABLE_ECDH
		public static KeyExchangeAlgorithm EcdhNistp256 { get; } = new ECDiffieHellman(ECDiffieHellman.EcdhNistp256, 256, HmacAlgorithm.Sha256);
		public static KeyExchangeAlgorithm EcdhNistp384 { get; } = new ECDiffieHellman(ECDiffieHellman.EcdhNistp384, 384, HmacAlgorithm.Sha384);
		public static KeyExchangeAlgorithm EcdhNistp521 { get; } = new ECDiffieHellman(ECDiffieHellman.EcdhNistp521, 521, HmacAlgorithm.Sha512);
#endif
	}

	public static class PublicKey
	{
		public static PublicKeyAlgorithm? None { get; } = null;

		public static PublicKeyAlgorithm RsaWithSha256 { get; } = new Rsa(Rsa.RsaWithSha256, HmacAlgorithm.Sha256);
		public static PublicKeyAlgorithm RsaWithSha512 { get; } = new Rsa(Rsa.RsaWithSha512, HmacAlgorithm.Sha512);

		public static PublicKeyAlgorithm ECDsaSha2Nistp256 { get; } = new ECDsa(ECDsa.ECDsaSha2Nistp256, HmacAlgorithm.Sha256);
		public static PublicKeyAlgorithm ECDsaSha2Nistp384 { get; } = new ECDsa(ECDsa.ECDsaSha2Nistp384, HmacAlgorithm.Sha384);
		public static PublicKeyAlgorithm ECDsaSha2Nistp521 { get; } = new ECDsa(ECDsa.ECDsaSha2Nistp521, HmacAlgorithm.Sha512);
	}

	public static class Encryption
	{
		public static EncryptionAlgorithm? None { get; } = null;

		public static EncryptionAlgorithm Aes256Cbc { get; } = new EncryptionAlgorithm("aes256-cbc", "AES", CipherModeEx.CBC, 256);
		public static EncryptionAlgorithm Aes256Ctr { get; } = new EncryptionAlgorithm("aes256-ctr", "AES", CipherModeEx.CTR, 256);
#if SSH_ENABLE_AESGCM
		public static EncryptionAlgorithm Aes256Gcm { get; } = new AesGcm("aes256-gcm@openssh.com", 256);
#endif
	}

	public static class Hmac
	{
		public static HmacAlgorithm? None { get; } = null;

		public static HmacAlgorithm HmacSha256 { get; } = new HmacAlgorithm("hmac-sha2-256", HmacAlgorithm.Sha256);
		public static HmacAlgorithm HmacSha512 { get; } = new HmacAlgorithm("hmac-sha2-512", HmacAlgorithm.Sha512);

		public static HmacAlgorithm HmacSha256Etm { get; } = new HmacAlgorithm("hmac-sha2-256-etm@openssh.com", HmacAlgorithm.Sha256, encryptThenMac: true);
		public static HmacAlgorithm HmacSha512Etm { get; } = new HmacAlgorithm("hmac-sha2-512-etm@openssh.com", HmacAlgorithm.Sha512, encryptThenMac: true);
	}

	public static class Compression
	{
		public static CompressionAlgorithm? None { get; } = null;
	}

	/// <summary>
	/// Gets the default provider of cryptographically random bytes.
	/// </summary>
	public static IRandom Random { get; } = new RNG();

	private class RNG : IRandom
	{
		private readonly RandomNumberGenerator random = RandomNumberGenerator.Create();

		public void GetBytes(Buffer buffer)
		{
			this.random.GetBytes(buffer.Array, buffer.Offset, buffer.Count);
		}
	}
}
