using Microsoft.DevTunnels.Ssh.Algorithms;
using System;
using System.Linq;
using System.Reflection;
using System.Text;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class CryptoTests
{
	[Theory]
	[InlineData(DiffieHellman.DHGroup14Sha256)]
	[InlineData(DiffieHellman.DHGroup16Sha512)]
#if SSH_ENABLE_ECDH
	[InlineData(ECDiffieHellman.EcdhNistp256)]
	[InlineData(ECDiffieHellman.EcdhNistp384)]
	[InlineData(ECDiffieHellman.EcdhNistp521)]
#endif
	public void KeyExchange(string kexAlg)
	{
		var alg = GetAlgorithmByName<KeyExchangeAlgorithm>(
			typeof(SshAlgorithms.KeyExchange), kexAlg);
		Assert.True(alg.IsAvailable, $"Algorithm not available: {kexAlg}");

		using var kexA = alg.CreateKeyExchange();
		using var kexB = alg.CreateKeyExchange();

		var exchangeA = kexA.StartKeyExchange();
		var exchangeB = kexB.StartKeyExchange();

		var secretA = kexA.DecryptKeyExchange(exchangeB);
		var secretB = kexB.DecryptKeyExchange(exchangeA);

		Assert.True(secretB.Equals(secretA));
	}

	[Theory]
	[InlineData(Rsa.RsaWithSha256, 1024)]
	[InlineData(Rsa.RsaWithSha512, 2048)]
	[InlineData(Rsa.RsaWithSha512, 4096)]
	[InlineData(ECDsa.ECDsaSha2Nistp256, null)]
	[InlineData(ECDsa.ECDsaSha2Nistp384, null)]
	[InlineData(ECDsa.ECDsaSha2Nistp521, null)]
	public void SignVerify(string pkAlg, int? keySize)
	{
		var alg = GetAlgorithmByName<PublicKeyAlgorithm>(
			typeof(SshAlgorithms.PublicKey), pkAlg);
		Assert.True(alg.IsAvailable, $"Algorithm not available: {pkAlg}");

		var keyPair = alg.GenerateKeyPair(keySize);

		Buffer data = Encoding.UTF8.GetBytes("test");
		var signer = alg.CreateSigner(keyPair);

		var signature = new Buffer(signer.DigestLength);
		signer.Sign(data, signature);

		var verifier = alg.CreateVerifier(keyPair);
		var verified = verifier.Verify(data, signature);
		Assert.True(verified);
	}

	[Theory]
	[InlineData("aes256-cbc")]
	[InlineData("aes256-ctr")]
#if SSH_ENABLE_AESGCM
	[InlineData("aes256-gcm@openssh.com")]
#endif
	public void EncryptDecrypt(string encAlg)
	{
		var alg = GetAlgorithmByName<EncryptionAlgorithm>(
			typeof(SshAlgorithms.Encryption), encAlg);
		Assert.True(alg.IsAvailable, $"Algorithm not available: {encAlg}");

		var key = new Buffer(alg.KeyLength);
		var iv = new Buffer(alg.BlockLength);

		var random = SshAlgorithms.Random;
		random.GetBytes(key);
		random.GetBytes(iv);

		var cipher = alg.CreateCipher(true, key, iv);
		var decipher = alg.CreateCipher(false, key, iv);

		var plaintext = new Buffer(3 * alg.BlockLength);
		for (int i = 0; i < plaintext.Count; i++)
		{
			plaintext[i] = (byte)i;
		}

		var ciphertext = new Buffer(plaintext.Count);
		cipher.Transform(plaintext, ciphertext);
		Assert.False(ciphertext.SequenceEqual(plaintext));

		var signer = cipher as IMessageSigner;
		var verifier = decipher as IMessageVerifier;
		if (signer?.AuthenticatedEncryption == true)
		{
			var tag = new Buffer(signer.DigestLength);
			signer.Sign(plaintext, tag);
			verifier.Verify(ciphertext, tag);
		}

		var plaintext2 = new Buffer(ciphertext.Count);
		decipher.Transform(ciphertext, plaintext2);
		Assert.True(plaintext2.SequenceEqual(plaintext));
	}

	[Theory]
	[InlineData("hmac-sha2-256")]
	[InlineData("hmac-sha2-512")]
	[InlineData("hmac-sha2-256-etm@openssh.com")]
	[InlineData("hmac-sha2-512-etm@openssh.com")]
	public void Hmac(string hmacAlg)
	{
		var alg = GetAlgorithmByName<HmacAlgorithm>(
			typeof(SshAlgorithms.Hmac), hmacAlg);
		Assert.True(alg.IsAvailable, $"Algorithm not available: {hmacAlg}");

		var key = new Buffer(alg.KeyLength);

		var random = SshAlgorithms.Random;
		random.GetBytes(key);

		var signer = alg.CreateSigner(key);
		var verifier = alg.CreateVerifier(key);

		var data = new Buffer(16);
		for (int i = 0; i < data.Count; i++)
		{
			data[i] = (byte)i;
		}

		var signature = new Buffer(signer.DigestLength);
		signer.Sign(data, signature);

		var verified = verifier.Verify(data, signature);
		Assert.True(verified);

	}

	private static T GetAlgorithmByName<T>(Type algorithmClass, string name)
		where T : SshAlgorithm
	{
		return algorithmClass.GetProperties(BindingFlags.Public | BindingFlags.Static)
			.Select((p) => p.GetValue(null))
			.Cast<T>()
			.FirstOrDefault((a) => a?.Name == name) ??
			throw new ArgumentException($"Algorithm not found: {name}");
	}
}
