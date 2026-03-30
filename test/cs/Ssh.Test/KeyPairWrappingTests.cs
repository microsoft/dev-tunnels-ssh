using Microsoft.DevTunnels.Ssh.Algorithms;
using System;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using SshECDsa = Microsoft.DevTunnels.Ssh.Algorithms.ECDsa;
using SshRsa = Microsoft.DevTunnels.Ssh.Algorithms.Rsa;

namespace Microsoft.DevTunnels.Ssh.Test;

/// <summary>
/// Tests for wrapping existing RSA/ECDsa instances in KeyPair objects.
/// Validates the public constructors added for non-exportable CNG key support.
/// </summary>
public class KeyPairWrappingTests
{
	private static PublicKeyAlgorithm GetAlgorithmByName(string name)
	{
		return typeof(SshAlgorithms.PublicKey)
			.GetProperties(BindingFlags.Public | BindingFlags.Static)
			.Select(p => p.GetValue(null) as PublicKeyAlgorithm)
			.First(a => a?.Name == name)!;
	}

	[Fact]
	public void RsaKeyPair_WrapExistingInstance_SignAndVerify()
	{
		using var rsa = RSA.Create(2048);
		var keyPair = new SshRsa.KeyPair(rsa);

		Assert.True(keyPair.HasPrivateKey);
		Assert.Equal("ssh-rsa", keyPair.KeyAlgorithmName);

		var alg = GetAlgorithmByName(SshRsa.RsaWithSha256);
		var signer = alg.CreateSigner(keyPair);
		var verifier = alg.CreateVerifier(keyPair);

		Buffer data = Encoding.UTF8.GetBytes("test data for RSA signing");
		var signature = new Buffer(signer.DigestLength);
		signer.Sign(data, signature);

		Assert.True(verifier.Verify(data, signature));
	}

	[Fact]
	public void RsaKeyPair_WrapExistingInstance_GetPublicKeyBytes()
	{
		using var rsa = RSA.Create(2048);
		var keyPair = new SshRsa.KeyPair(rsa);

		var publicKeyBytes = keyPair.GetPublicKeyBytes();
		Assert.True(publicKeyBytes.Count > 0);

		// The public key blob should start with the "ssh-rsa" algorithm name
		var reader = new IO.SshDataReader(publicKeyBytes);
		var algorithmName = reader.ReadString(Encoding.ASCII);
		Assert.Equal("ssh-rsa", algorithmName);
	}

	[Fact]
	public void RsaKeyPair_WrapExistingInstance_NullThrows()
	{
		Assert.Throws<ArgumentNullException>(() => new SshRsa.KeyPair((RSA)null!));
	}

	[Fact]
	public void RsaKeyPair_WrapExistingInstance_MatchesImportedKeyPair()
	{
		using var rsa = RSA.Create(2048);
		var rsaParams = rsa.ExportParameters(true);

		// Path 1: ImportParameters (existing API)
		var keyPair1 = new SshRsa.KeyPair();
		keyPair1.ImportParameters(rsaParams);

		// Path 2: Wrap directly (new public constructor)
		var keyPair2 = new SshRsa.KeyPair(rsa);

		// Both should produce the same public key bytes
		var pub1 = keyPair1.GetPublicKeyBytes();
		var pub2 = keyPair2.GetPublicKeyBytes();
		Assert.Equal(pub1.ToArray(), pub2.ToArray());

		// Signature from wrapped key should verify with imported key's verifier
		var alg = GetAlgorithmByName(SshRsa.RsaWithSha512);
		var signer = alg.CreateSigner(keyPair2);
		var verifier = alg.CreateVerifier(keyPair1);

		Buffer data = Encoding.UTF8.GetBytes("cross-verify test");
		var signature = new Buffer(signer.DigestLength);
		signer.Sign(data, signature);

		Assert.True(verifier.Verify(data, signature));
	}

	[Theory]
	[InlineData(SshECDsa.ECDsaSha2Nistp256)]
	[InlineData(SshECDsa.ECDsaSha2Nistp384)]
	[InlineData(SshECDsa.ECDsaSha2Nistp521)]
	public void ECDsaKeyPair_WrapExistingInstance_SignAndVerify(string algorithmName)
	{
		var curve = algorithmName switch
		{
			SshECDsa.ECDsaSha2Nistp256 => ECCurve.NamedCurves.nistP256,
			SshECDsa.ECDsaSha2Nistp384 => ECCurve.NamedCurves.nistP384,
			SshECDsa.ECDsaSha2Nistp521 => ECCurve.NamedCurves.nistP521,
			_ => throw new ArgumentException(algorithmName),
		};

		using var ecdsa = System.Security.Cryptography.ECDsa.Create(curve);
		var keyPair = new SshECDsa.KeyPair(ecdsa);

		Assert.True(keyPair.HasPrivateKey);
		Assert.Equal(algorithmName, keyPair.KeyAlgorithmName);

		var alg = GetAlgorithmByName(algorithmName);
		var signer = alg.CreateSigner(keyPair);
		var verifier = alg.CreateVerifier(keyPair);

		Buffer data = Encoding.UTF8.GetBytes("test data for ECDSA signing");
		var signature = new Buffer(signer.DigestLength);
		signer.Sign(data, signature);

		// ECDSA uses variable-length signatures — trim to actual content
		signature = alg.CreateSignatureData(signature);
		var rawSig = alg.ReadSignatureData(signature);

		Assert.True(verifier.Verify(data, rawSig));
	}

	[Fact]
	public void ECDsaKeyPair_WrapExistingInstance_GetPublicKeyBytes()
	{
		using var ecdsa = System.Security.Cryptography.ECDsa.Create(ECCurve.NamedCurves.nistP256);
		var keyPair = new SshECDsa.KeyPair(ecdsa);

		var publicKeyBytes = keyPair.GetPublicKeyBytes();
		Assert.True(publicKeyBytes.Count > 0);

		var reader = new IO.SshDataReader(publicKeyBytes);
		var algName = reader.ReadString(Encoding.ASCII);
		Assert.Equal(SshECDsa.ECDsaSha2Nistp256, algName);
	}

	[Fact]
	public void ECDsaKeyPair_WrapExistingInstance_NullThrows()
	{
		Assert.Throws<ArgumentNullException>(
			() => new SshECDsa.KeyPair((System.Security.Cryptography.ECDsa)null!));
	}

	[Fact]
	public void ECDsaKeyPair_WrapExistingInstance_MatchesImportedKeyPair()
	{
		using var ecdsa = System.Security.Cryptography.ECDsa.Create(ECCurve.NamedCurves.nistP384);
		var ecParams = ecdsa.ExportParameters(true);

		// Path 1: ImportParameters
		var keyPair1 = new SshECDsa.KeyPair();
		keyPair1.ImportParameters(ecParams);

		// Path 2: Wrap directly
		var keyPair2 = new SshECDsa.KeyPair(ecdsa);

		var pub1 = keyPair1.GetPublicKeyBytes();
		var pub2 = keyPair2.GetPublicKeyBytes();
		Assert.Equal(pub1.ToArray(), pub2.ToArray());
	}
}
