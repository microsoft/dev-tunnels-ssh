using System;
using System.IO;
using Microsoft.DevTunnels.Ssh.Keys;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class KeyImportExportTests
{
	public KeyImportExportTests()
	{
		// Reduce the number of KDF rounds when testing so the tests run faster.
		var opensshFormatter = (OpenSshKeyFormatter)KeyPair.Formatters[KeyFormat.OpenSsh];
		opensshFormatter.KdfRounds = 2;

		var pkcs8Formatter = (Pkcs8KeyFormatter)KeyPair.Formatters[KeyFormat.Pkcs8];
		pkcs8Formatter.Pbkdf2Iterations = 2048;
	}

	private const string TestDataDir = "Data";
	private const string TestPassword = "password";

	private static string TestFile(string name)
	{
		var testFile = Path.Combine(TestDataDir, name + ".txt");
		if (!File.Exists(testFile))
		{
			throw new NotImplementedException($"Test file does not exist: {testFile}");
		}
		return testFile;
	}

	[SkippableTheory(typeof(NotImplementedException))]
	[InlineData("rsa2048", KeyFormat.Ssh)]
	[InlineData("rsa2048", KeyFormat.Ssh2)]
	[InlineData("rsa2048", KeyFormat.Pkcs1)]
	[InlineData("rsa2048", KeyFormat.Pkcs8)]
	[InlineData("rsa2048", KeyFormat.Jwk)]
	[InlineData("rsa4096", KeyFormat.Ssh)]
	[InlineData("rsa4096", KeyFormat.Ssh2)]
	[InlineData("rsa4096", KeyFormat.Pkcs1)]
	[InlineData("rsa4096", KeyFormat.Pkcs8)]
	[InlineData("ecdsa384", KeyFormat.Ssh)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8)]
	[InlineData("ecdsa384", KeyFormat.Jwk)]
	[InlineData("ecdsa521", KeyFormat.Ssh)]
	public void ImportPublicKey(string algorithm, KeyFormat keyFormat)
	{
		var suffix = keyFormat.ToString().ToLowerInvariant();
		var keyPair = KeyPair.ImportKeyFile(TestFile($"testkey-public-{algorithm}-{suffix}"));
		Assert.NotNull(keyPair);
		Assert.False(keyPair.HasPrivateKey);

		var expected = File.ReadAllText(TestFile($"testkey-public-{algorithm}-ssh"));
		if (keyFormat == KeyFormat.Pkcs1 ||
			keyFormat == KeyFormat.Sec1 ||
			keyFormat == KeyFormat.Pkcs8)
		{
			// Some formats don't support comments.
			var publicKey = KeyPair.ImportKey(expected);
			publicKey.Comment = null;
			expected = KeyPair.ExportPublicKey(publicKey);
		}

		Assert.Equal(expected, KeyPair.ExportPublicKey(keyPair));
	}

	[SkippableTheory(typeof(NotImplementedException))]
	[InlineData("rsa2048", KeyFormat.Pkcs1)]
	[InlineData("rsa2048", KeyFormat.Pkcs8)]
	[InlineData("rsa2048", KeyFormat.Ssh2)]
	[InlineData("rsa2048", KeyFormat.OpenSsh)]
	[InlineData("rsa2048", KeyFormat.Jwk)]
	[InlineData("rsa2048", KeyFormat.Pkcs1, TestPassword)]
	[InlineData("rsa2048", KeyFormat.Ssh2, TestPassword)]
	[InlineData("rsa2048", KeyFormat.OpenSsh, TestPassword)]
	[InlineData("rsa4096", KeyFormat.Pkcs1)]
	[InlineData("rsa4096", KeyFormat.Pkcs8)]
	[InlineData("rsa4096", KeyFormat.Ssh2)]
	[InlineData("rsa4096", KeyFormat.OpenSsh)]
	[InlineData("rsa4096", KeyFormat.Jwk)]
	[InlineData("ecdsa384", KeyFormat.Sec1)]
	[InlineData("ecdsa384", KeyFormat.Sec1, TestPassword)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8)]
	[InlineData("ecdsa384", KeyFormat.OpenSsh)]
	[InlineData("ecdsa384", KeyFormat.OpenSsh, TestPassword)]
	[InlineData("ecdsa384", KeyFormat.Jwk)]
	[InlineData("ecdsa521", KeyFormat.Sec1)]
	[InlineData("ecdsa521", KeyFormat.Pkcs8)]
#if SSH_ENABLE_PBKDF2
	[InlineData("rsa2048", KeyFormat.Pkcs8, TestPassword)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8, TestPassword)]
#endif
	public void ImportPrivateKey(string algorithm, KeyFormat keyFormat, string passphrase = null)
	{
		var suffix = keyFormat.ToString().ToLowerInvariant()
			+ (passphrase != null ? "-pw" : string.Empty);

		var keyPair = KeyPair.ImportKeyFile(
			TestFile($"testkey-private-{algorithm}-{suffix}"), passphrase);
		Assert.NotNull(keyPair);
		Assert.True(keyPair.HasPrivateKey);

		var expected = File.ReadAllText(TestFile($"testkey-public-{algorithm}-ssh"));
		if (keyFormat == KeyFormat.Pkcs1 ||
			keyFormat == KeyFormat.Sec1 ||
			keyFormat == KeyFormat.Pkcs8)
		{
			// Some formats don't support comments.
			var publicKey = KeyPair.ImportKey(expected);
			publicKey.Comment = null;
			expected = KeyPair.ExportPublicKey(publicKey);
		}

		Assert.Equal(expected, KeyPair.ExportPublicKey(keyPair));
	}

	[SkippableTheory(typeof(NotImplementedException))]
	[InlineData("rsa2048", KeyFormat.Pkcs1)]
	[InlineData("rsa2048", KeyFormat.Ssh2)]
	[InlineData("rsa2048", KeyFormat.OpenSsh)]
	[InlineData("ecdsa384", KeyFormat.OpenSsh)]
#if SSH_ENABLE_PBKDF2
	[InlineData("rsa2048", KeyFormat.Pkcs8)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8)]
#endif
	public void ImportPrivateKeyInvalidPassword(string algorithm, KeyFormat keyFormat)
	{
		var suffix = keyFormat.ToString().ToLowerInvariant() + "-pw";
		var privateKeyFile = TestFile($"testkey-private-{algorithm}-{suffix}");

		Assert.Throws<UnauthorizedAccessException>(() =>
		{
			KeyPair.ImportKeyFile(privateKeyFile, null);
		});
		Assert.Throws<UnauthorizedAccessException>(() =>
		{
			KeyPair.ImportKeyFile(privateKeyFile, "invalid");
		});
	}

	[SkippableTheory(typeof(NotImplementedException))]
	[InlineData("rsa2048", KeyFormat.Ssh)]
	[InlineData("rsa2048", KeyFormat.Ssh2)]
	[InlineData("rsa2048", KeyFormat.Pkcs1)]
	[InlineData("rsa2048", KeyFormat.Pkcs8)]
	[InlineData("rsa2048", KeyFormat.Jwk)]
	[InlineData("rsa4096", KeyFormat.Ssh)]
	[InlineData("rsa4096", KeyFormat.Ssh2)]
	[InlineData("rsa4096", KeyFormat.Pkcs1)]
	[InlineData("rsa4096", KeyFormat.Pkcs8)]
	[InlineData("rsa4096", KeyFormat.Jwk)]
	[InlineData("ecdsa384", KeyFormat.Ssh)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8)]
	[InlineData("ecdsa384", KeyFormat.Jwk)]
	[InlineData("ecdsa521", KeyFormat.Ssh)]
	[InlineData("ecdsa521", KeyFormat.Pkcs8)]
	public void ExportPublicKey(string algorithm, KeyFormat keyFormat)
	{
		var suffix = keyFormat.ToString().ToLowerInvariant();
		var publicKey = KeyPair.ImportKeyFile(TestFile($"testkey-public-{algorithm}-ssh"));

		var exportedPublicKey = KeyPair.ExportPublicKey(publicKey, keyFormat);
		var expected = File.ReadAllText(TestFile($"testkey-public-{algorithm}-{suffix}"));
		Assert.Equal(expected, exportedPublicKey);
	}

	[SkippableTheory(typeof(NotImplementedException))]
	[InlineData("ecdsa384", KeyFormat.Sec1)]
	public void ExportPublicKeyNotSupported(string algorithm, KeyFormat keyFormat)
	{
		var suffix = keyFormat.ToString().ToLowerInvariant();
		var publicKey = KeyPair.ImportKeyFile(TestFile($"testkey-public-{algorithm}-ssh"));
		Assert.Throws<NotSupportedException>(() => KeyPair.ExportPublicKey(publicKey, keyFormat));
	}

	[SkippableTheory(typeof(NotImplementedException))]
	[InlineData("rsa2048", KeyFormat.Pkcs1)]
	[InlineData("rsa2048", KeyFormat.Pkcs8)]
	[InlineData("rsa2048", KeyFormat.Ssh2)]
	[InlineData("rsa2048", KeyFormat.OpenSsh)]
	[InlineData("rsa2048", KeyFormat.Jwk)]
	[InlineData("rsa2048", KeyFormat.Pkcs1, TestPassword)]
	[InlineData("rsa2048", KeyFormat.Ssh2, TestPassword)]
	[InlineData("rsa2048", KeyFormat.OpenSsh, TestPassword)]
	[InlineData("rsa4096", KeyFormat.Pkcs1)]
	[InlineData("rsa4096", KeyFormat.Pkcs8)]
	[InlineData("rsa4096", KeyFormat.Ssh2)]
	[InlineData("rsa4096", KeyFormat.OpenSsh)]
	[InlineData("rsa4096", KeyFormat.Jwk)]
	[InlineData("ecdsa384", KeyFormat.Sec1)]
	[InlineData("ecdsa384", KeyFormat.Sec1, TestPassword)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8)]
	[InlineData("ecdsa384", KeyFormat.OpenSsh)]
	[InlineData("ecdsa384", KeyFormat.OpenSsh, TestPassword)]
	[InlineData("ecdsa521", KeyFormat.Sec1)]
	[InlineData("ecdsa521", KeyFormat.Pkcs8)]
#if SSH_ENABLE_PBKDF2
	[InlineData("rsa2048", KeyFormat.Pkcs8, TestPassword)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8, TestPassword)]
#endif
	public void ExportPrivateKey(string algorithm, KeyFormat keyFormat, string passphrase = null)
	{
		ProvideMockRandomBytes(keyFormat, passphrase != null);

		var suffix = keyFormat.ToString().ToLowerInvariant()
			+ (passphrase != null ? "-pw" : string.Empty);
		var formatSuffix = algorithm.StartsWith("rsa") ? "pkcs1" : "sec1";

		var keyPair = KeyPair.ImportKeyFile(
			TestFile($"testkey-private-{algorithm}-{formatSuffix}"));
		keyPair.Comment = "comment"; // PKCS#1/SEC1 format does not persist the comment.

		if (passphrase != null && keyFormat != KeyFormat.Pkcs8 && keyFormat != KeyFormat.OpenSsh)
		{
			// Export with passphrase is not supported due to weak encryption.
			Assert.Throws<NotSupportedException>(
				() => KeyPair.ExportPrivateKey(keyPair, passphrase, keyFormat));
		}
		else
		{
			var exportedPrivateKey = KeyPair.ExportPrivateKey(keyPair, passphrase, keyFormat);
			var expected = File.ReadAllText(TestFile($"testkey-private-{algorithm}-{suffix}"));
			Assert.Equal(expected, exportedPrivateKey);
		}
	}

	[SkippableTheory(typeof(NotImplementedException))]
	[InlineData("rsa2048", KeyFormat.Ssh)]
	[InlineData("rsa2048", KeyFormat.Ssh2)]
	[InlineData("rsa2048", KeyFormat.Pkcs1)]
	[InlineData("rsa2048", KeyFormat.Pkcs8)]
	[InlineData("ecdsa384", KeyFormat.Ssh)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8)]
	public void ExportImportPublicKeyBytes(string algorithm, KeyFormat keyFormat)
	{
		var publicKey = KeyPair.ImportKeyFile(TestFile($"testkey-public-{algorithm}-ssh"));
		var publicKeyBytes = KeyPair.ExportPublicKeyBytes(
			publicKey, keyFormat, KeyEncoding.Binary);
		var publicKey2 = KeyPair.ImportKeyBytes(publicKeyBytes, passphrase: null, keyFormat);
		publicKey2.Comment = "comment";

		var exportedPublicKey = KeyPair.ExportPublicKey(publicKey2, KeyFormat.Ssh);
		var expected = File.ReadAllText(TestFile($"testkey-public-{algorithm}-ssh"));
		Assert.Equal(expected, exportedPublicKey);
	}

	[SkippableTheory(typeof(NotImplementedException))]
	[InlineData("rsa2048", KeyFormat.Pkcs1)]
	[InlineData("rsa2048", KeyFormat.Pkcs8)]
	[InlineData("rsa2048", KeyFormat.Ssh2)]
	[InlineData("rsa2048", KeyFormat.OpenSsh)]
	[InlineData("rsa2048", KeyFormat.OpenSsh, TestPassword)]
	[InlineData("ecdsa384", KeyFormat.Sec1)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8)]
	[InlineData("ecdsa384", KeyFormat.OpenSsh)]
	[InlineData("ecdsa384", KeyFormat.OpenSsh, TestPassword)]
#if SSH_ENABLE_PBKDF2
	[InlineData("rsa2048", KeyFormat.Pkcs8, TestPassword)]
	[InlineData("ecdsa384", KeyFormat.Pkcs8, TestPassword)]
#endif
	public void ExportImportPrivateKeyBytes(
		string algorithm,
		KeyFormat keyFormat,
		string passphrase = null)
	{
		var formatSuffix = algorithm.StartsWith("rsa") ? "pkcs1" : "sec1";
		var privateKey = KeyPair.ImportKeyFile(TestFile(
			$"testkey-private-{algorithm}-{formatSuffix}"));

		ProvideMockRandomBytes(keyFormat, passphrase != null);
		var privateKeyBytes = KeyPair.ExportPrivateKeyBytes(
			privateKey, passphrase, keyFormat, KeyEncoding.Binary);

		var privateKey2 = KeyPair.ImportKeyBytes(privateKeyBytes, passphrase, keyFormat);

		var exportFormat = algorithm.StartsWith("rsa") ? KeyFormat.Pkcs1 : KeyFormat.Sec1;
		var exportedPrivateKey = KeyPair.ExportPrivateKey(
			privateKey2, passphrase: null, exportFormat);
		var expected = File.ReadAllText(TestFile($"testkey-private-{algorithm}-{formatSuffix}"));
		Assert.Equal(expected, exportedPrivateKey);
	}

	/// <summary>
	/// Provide mocked "random" bytes to exporters to ensure deterministic output.
	/// </summary>
	private static void ProvideMockRandomBytes(KeyFormat keyFormat, bool encrypting)
	{
		if (keyFormat == KeyFormat.OpenSsh)
		{
			var mockRandom = new MockRandom();
			var formatter = (OpenSshKeyFormatter)KeyPair.Formatters[KeyFormat.OpenSsh];
			formatter.Random = mockRandom;

			var checkBytes = new byte[] { 0xcc, 0xcc, 0xcc, 0xcc };
			mockRandom.Values.Add(checkBytes);

			if (encrypting)
			{
				var salt = new byte[]
				{
						0xc4, 0xdf, 0xeb, 0xf5, 0xd0, 0xb8, 0x03, 0x28,
						0xee, 0xf0, 0x07, 0xcd, 0xf1, 0xd6, 0x4b, 0xa1,
				};
				mockRandom.Values.Add(salt);
			}
		}
		else if (keyFormat == KeyFormat.Pkcs8 && encrypting)
		{
			var mockRandom = new MockRandom();
			var formatter = (Pkcs8KeyFormatter)KeyPair.Formatters[KeyFormat.Pkcs8];
			formatter.Random = mockRandom;

			var salt = new byte[]
			{
					0x1f, 0xc0, 0xf9, 0x60, 0xc9, 0x51, 0x89, 0x9a,
			};
			mockRandom.Values.Add(salt);

			var iv = new byte[]
			{
					0x38, 0xaf, 0x3d, 0x00, 0xec, 0xe6, 0x43, 0x42,
					0x7c, 0x94, 0x30, 0x73, 0xcb, 0x92, 0x4f, 0xa2,
			};
			mockRandom.Values.Add(iv);
		}
	}
}
