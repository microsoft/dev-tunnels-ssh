using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;

namespace Microsoft.DevTunnels.Ssh.Benchmark;

#if NETSTANDARD2_0 || NET4
using ValueTask = System.Threading.Tasks.Task;
#endif

class EncryptionBenchmark : Benchmark
{
	private const string EncryptDecryptTimeMeasurement = "Encrypt+Decrypt time (ms)";
	private const string ThroughputMeasurement = "Throughput (MB/s)";

	private readonly EncryptionAlgorithm algorithm;
	private readonly int payloadSize;

	public EncryptionBenchmark(EncryptionAlgorithm algorithm, int payloadSize)
		: base(
			$"Encryption {algorithm.Name} {payloadSize}B",
			"algorithm-encryption",
			new Dictionary<string, string>
			{
				{ "algo", algorithm.Name },
				{ "size", payloadSize.ToString() },
			})
	{
		HigherIsBetter[EncryptDecryptTimeMeasurement] = false;
		this.algorithm = algorithm;
		this.payloadSize = payloadSize;
	}

	protected override Task RunAsync(Stopwatch stopwatch)
	{
		var key = new Buffer(algorithm.KeyLength);
		var encIv = new Buffer(algorithm.BlockLength);
		var decIv = new Buffer(algorithm.BlockLength);
		SshAlgorithms.Random.GetBytes(key);
		SshAlgorithms.Random.GetBytes(encIv);
		encIv.CopyTo(decIv);

		// Round payload to block length
		var blockLen = algorithm.BlockLength;
		var alignedSize = (payloadSize / blockLen) * blockLen;
		if (alignedSize < blockLen) alignedSize = blockLen;

		var plaintext = new Buffer(alignedSize);
		SshAlgorithms.Random.GetBytes(plaintext);
		var ciphertext = new Buffer(alignedSize);
		var decrypted = new Buffer(alignedSize);

		using var encCipher = algorithm.CreateCipher(true, key, encIv);
		using var decCipher = algorithm.CreateCipher(false, key, decIv);

		stopwatch.Restart();

		encCipher.Transform(plaintext, ciphertext);

#if SSH_ENABLE_AESGCM
		// For GCM, copy tag from encryptor to decryptor
		if (encCipher is IMessageSigner signer && decCipher is IMessageVerifier verifier)
		{
			var tag = new Buffer(signer.DigestLength);
			signer.Sign(plaintext, tag);
			verifier.Verify(ciphertext, tag);
		}
#endif

		decCipher.Transform(ciphertext, decrypted);

		stopwatch.Stop();

		AddMeasurement(EncryptDecryptTimeMeasurement, stopwatch.Elapsed.TotalMilliseconds);

		// Skip throughput for small payloads — sub-millisecond operations produce
		// wildly noisy MB/s values due to timer resolution limits.
		if (alignedSize >= 4096)
		{
			double megabytes = (double)alignedSize / (1024 * 1024);
			double seconds = stopwatch.Elapsed.TotalSeconds;
			AddMeasurement(ThroughputMeasurement, seconds > 0 ? megabytes / seconds : 0);
		}

		return Task.CompletedTask;
	}

	public override Task VerifyAsync()
	{
		var key = new Buffer(algorithm.KeyLength);
		var encIv = new Buffer(algorithm.BlockLength);
		var decIv = new Buffer(algorithm.BlockLength);
		SshAlgorithms.Random.GetBytes(key);
		SshAlgorithms.Random.GetBytes(encIv);
		encIv.CopyTo(decIv);

		var blockLen = algorithm.BlockLength;
		var alignedSize = (payloadSize / blockLen) * blockLen;
		if (alignedSize < blockLen) alignedSize = blockLen;

		var plaintext = new Buffer(alignedSize);
		SshAlgorithms.Random.GetBytes(plaintext);
		var original = plaintext.ToArray();
		var ciphertext = new Buffer(alignedSize);
		var decrypted = new Buffer(alignedSize);

		using var encCipher = algorithm.CreateCipher(true, key, encIv);
		using var decCipher = algorithm.CreateCipher(false, key, decIv);

		encCipher.Transform(plaintext, ciphertext);

		// Check ciphertext differs from plaintext
		if (ciphertext.SequenceEqual(plaintext))
			throw new Exception("Ciphertext equals plaintext — encryption did nothing");

#if SSH_ENABLE_AESGCM
		if (encCipher is IMessageSigner signer && decCipher is IMessageVerifier verifier)
		{
			var tag = new Buffer(signer.DigestLength);
			signer.Sign(plaintext, tag);
			verifier.Verify(ciphertext, tag);
		}
#endif

		decCipher.Transform(ciphertext, decrypted);

		// Check decrypted matches original
		if (!decrypted.SequenceEqual((Buffer)original))
			throw new Exception("Decrypted data does not match original");

		return Task.CompletedTask;
	}

	public override ValueTask DisposeAsync()
	{
#if NETSTANDARD2_0 || NET4
		return Task.CompletedTask;
#else
		return ValueTask.CompletedTask;
#endif
	}
}

class HmacBenchmark : Benchmark
{
	private const string SignVerifyTimeMeasurement = "Sign+Verify time (ms)";

	private readonly HmacAlgorithm algorithm;

	public HmacBenchmark(HmacAlgorithm algorithm)
		: base(
			$"HMAC {algorithm.Name}",
			"algorithm-hmac",
			new Dictionary<string, string>
			{
				{ "algo", algorithm.Name },
			})
	{
		HigherIsBetter[SignVerifyTimeMeasurement] = false;
		this.algorithm = algorithm;
	}

	protected override Task RunAsync(Stopwatch stopwatch)
	{
		var key = new Buffer(algorithm.KeyLength);
		SshAlgorithms.Random.GetBytes(key);

		using var signer = algorithm.CreateSigner(key);
		using var verifier = algorithm.CreateVerifier(key);

		var data = new Buffer(256);
		SshAlgorithms.Random.GetBytes(data);
		var signature = new Buffer(signer.DigestLength);

		stopwatch.Restart();

		signer.Sign(data, signature);
		verifier.Verify(data, signature);

		stopwatch.Stop();

		AddMeasurement(SignVerifyTimeMeasurement, stopwatch.Elapsed.TotalMilliseconds);

		return Task.CompletedTask;
	}

	public override Task VerifyAsync()
	{
		var key = new Buffer(algorithm.KeyLength);
		SshAlgorithms.Random.GetBytes(key);

		using var signer = algorithm.CreateSigner(key);
		using var verifier = algorithm.CreateVerifier(key);

		var data = new Buffer(256);
		SshAlgorithms.Random.GetBytes(data);
		var signature = new Buffer(signer.DigestLength);

		signer.Sign(data, signature);
		if (!verifier.Verify(data, signature))
			throw new Exception("Valid signature failed verification");

		// Tamper with data
		var tampered = data.ToArray();
		tampered[0] ^= 0xFF;
		if (verifier.Verify((Buffer)tampered, signature))
			throw new Exception("Tampered data passed verification");

		return Task.CompletedTask;
	}

	public override ValueTask DisposeAsync()
	{
#if NETSTANDARD2_0 || NET4
		return Task.CompletedTask;
#else
		return ValueTask.CompletedTask;
#endif
	}
}

class KeyExchangeBenchmark : Benchmark
{
	private const string KexTimeMeasurement = "Key exchange time (ms)";

	private readonly KeyExchangeAlgorithm algorithm;

	public KeyExchangeBenchmark(KeyExchangeAlgorithm algorithm)
		: base(
			$"KEX {algorithm.Name}",
			"algorithm-kex",
			new Dictionary<string, string>
			{
				{ "algo", algorithm.Name },
			})
	{
		HigherIsBetter[KexTimeMeasurement] = false;
		this.algorithm = algorithm;
	}

	protected override Task RunAsync(Stopwatch stopwatch)
	{
		using var clientKex = algorithm.CreateKeyExchange();
		using var serverKex = algorithm.CreateKeyExchange();

		stopwatch.Restart();

		var clientPublic = clientKex.StartKeyExchange();
		var serverPublic = serverKex.StartKeyExchange();
		var clientSecret = clientKex.DecryptKeyExchange(serverPublic);
		var serverSecret = serverKex.DecryptKeyExchange(clientPublic);

		stopwatch.Stop();

		AddMeasurement(KexTimeMeasurement, stopwatch.Elapsed.TotalMilliseconds);

		return Task.CompletedTask;
	}

	public override Task VerifyAsync()
	{
		using var clientKex = algorithm.CreateKeyExchange();
		using var serverKex = algorithm.CreateKeyExchange();

		var clientPublic = clientKex.StartKeyExchange();
		var serverPublic = serverKex.StartKeyExchange();
		var clientSecret = clientKex.DecryptKeyExchange(serverPublic);
		var serverSecret = serverKex.DecryptKeyExchange(clientPublic);

		if (clientSecret == null || clientSecret.Count == 0)
			throw new Exception("Client shared secret is empty");
		if (!clientSecret.SequenceEqual(serverSecret))
			throw new Exception("Shared secrets differ");

		return Task.CompletedTask;
	}

	public override ValueTask DisposeAsync()
	{
#if NETSTANDARD2_0 || NET4
		return Task.CompletedTask;
#else
		return ValueTask.CompletedTask;
#endif
	}
}

class KeygenBenchmark : Benchmark
{
	private const string KeygenTimeMeasurement = "Keygen time (ms)";

	private readonly PublicKeyAlgorithm algorithm;
	private readonly int keySizeInBits;

	public KeygenBenchmark(PublicKeyAlgorithm algorithm, int keySizeInBits)
		: base(
			$"Keygen {algorithm.KeyAlgorithmName} {keySizeInBits}",
			"algorithm-keygen",
			new Dictionary<string, string>
			{
				{ "algo", algorithm.KeyAlgorithmName },
				{ "size", keySizeInBits.ToString() },
			})
	{
		HigherIsBetter[KeygenTimeMeasurement] = false;
		this.algorithm = algorithm;
		this.keySizeInBits = keySizeInBits;
	}

	protected override Task RunAsync(Stopwatch stopwatch)
	{
		stopwatch.Restart();

		using var keyPair = algorithm.GenerateKeyPair(keySizeInBits);

		// Force key materialization. .NET RSA.Create() is lazy and defers actual
		// key generation until first use; without this the measurement reads ~0.
		keyPair.GetPublicKeyBytes(algorithm.KeyAlgorithmName);

		stopwatch.Stop();

		AddMeasurement(KeygenTimeMeasurement, stopwatch.Elapsed.TotalMilliseconds);

		return Task.CompletedTask;
	}

	public override Task VerifyAsync()
	{
		using var keyPair = algorithm.GenerateKeyPair(keySizeInBits);

		// Verify the generated key has the expected bit size.
		KeySizeVerification.VerifyKeySize(keyPair, keySizeInBits, algorithm.KeyAlgorithmName);

		using var signer = algorithm.CreateSigner(keyPair);
		using var verifier = algorithm.CreateVerifier(keyPair);

		var data = new Buffer(256);
		SshAlgorithms.Random.GetBytes(data);
		var signature = new Buffer(signer.DigestLength);

		signer.Sign(data, signature);
		if (!verifier.Verify(data, signature))
			throw new Exception("Generated key cannot verify its own signature");

		return Task.CompletedTask;
	}

	public override ValueTask DisposeAsync()
	{
#if NETSTANDARD2_0 || NET4
		return Task.CompletedTask;
#else
		return ValueTask.CompletedTask;
#endif
	}
}

class SignatureBenchmark : Benchmark
{
	private const string SignVerifyTimeMeasurement = "Sign+Verify time (ms)";

	private readonly PublicKeyAlgorithm algorithm;
	private readonly int keySizeInBits;

	public SignatureBenchmark(PublicKeyAlgorithm algorithm, int keySizeInBits)
		: base(
			$"Signature {algorithm.Name} {keySizeInBits}",
			"algorithm-signature",
			new Dictionary<string, string>
			{
				{ "algo", algorithm.Name },
				{ "size", keySizeInBits.ToString() },
			})
	{
		HigherIsBetter[SignVerifyTimeMeasurement] = false;
		this.algorithm = algorithm;
		this.keySizeInBits = keySizeInBits;
	}

	protected override Task RunAsync(Stopwatch stopwatch)
	{
		using var keyPair = algorithm.GenerateKeyPair(keySizeInBits);
		using var signer = algorithm.CreateSigner(keyPair);
		using var verifier = algorithm.CreateVerifier(keyPair);

		var data = new Buffer(256);
		SshAlgorithms.Random.GetBytes(data);
		var signature = new Buffer(signer.DigestLength);

		stopwatch.Restart();

		signer.Sign(data, signature);
		verifier.Verify(data, signature);

		stopwatch.Stop();

		AddMeasurement(SignVerifyTimeMeasurement, stopwatch.Elapsed.TotalMilliseconds);

		return Task.CompletedTask;
	}

	public override Task VerifyAsync()
	{
		using var keyPair = algorithm.GenerateKeyPair(keySizeInBits);

		// Verify the generated key has the expected bit size.
		KeySizeVerification.VerifyKeySize(keyPair, keySizeInBits, algorithm.KeyAlgorithmName);

		using var signer = algorithm.CreateSigner(keyPair);
		using var verifier = algorithm.CreateVerifier(keyPair);

		var data = new Buffer(256);
		SshAlgorithms.Random.GetBytes(data);
		var signature = new Buffer(signer.DigestLength);

		signer.Sign(data, signature);
		if (!verifier.Verify(data, signature))
			throw new Exception("Valid signature failed verification");

		var wrongData = new Buffer(256);
		SshAlgorithms.Random.GetBytes(wrongData);
		if (verifier.Verify(wrongData, signature))
			throw new Exception("Wrong data passed verification");

		return Task.CompletedTask;
	}

	public override ValueTask DisposeAsync()
	{
#if NETSTANDARD2_0 || NET4
		return Task.CompletedTask;
#else
		return ValueTask.CompletedTask;
#endif
	}
}

/// <summary>
/// Verifies that a generated key pair has the expected bit size by inspecting
/// the SSH public key bytes. For RSA, checks that the public key byte length
/// is consistent with the expected modulus size.
/// </summary>
static class KeySizeVerification
{
	public static void VerifyKeySize(IKeyPair keyPair, int expectedSizeInBits, string keyAlgorithmName)
	{
		var pubKeyBytes = keyPair.GetPublicKeyBytes(keyAlgorithmName);

		if (keyAlgorithmName == "ssh-rsa")
		{
			// RSA public key SSH wire format: [string "ssh-rsa"] [mpint e] [mpint n]
			// The modulus n determines the key size. Expected total byte count:
			//   ~11 (algo string) + ~7 (exponent) + 5 (mpint header) + keySizeInBits/8.
			int expectedModulusBytes = expectedSizeInBits / 8;
			int minExpectedLength = expectedModulusBytes + 10;
			int maxExpectedLength = expectedModulusBytes + 25;

			if (pubKeyBytes.Count < minExpectedLength || pubKeyBytes.Count > maxExpectedLength)
			{
				throw new Exception(
					$"Expected {expectedSizeInBits}-bit RSA key (pub key ~{minExpectedLength}-{maxExpectedLength} bytes), " +
					$"but got {pubKeyBytes.Count} bytes. Key size mismatch.");
			}
		}
		else if (keyAlgorithmName.StartsWith("ecdsa-sha2-"))
		{
			// ECDSA public key SSH wire format: [string algo] [string curve] [string Q]
			// Q is uncompressed: 0x04 || X || Y, so Q length = 1 + 2*ceil(bits/8).
			int coordBytes = (expectedSizeInBits + 7) / 8;
			int expectedQLen = 1 + 2 * coordBytes;
			// Total: 4+algo.Length + 4+curve.Length + 4+Q.Length
			int algoLen = keyAlgorithmName.Length;
			string curveName = keyAlgorithmName.Substring("ecdsa-sha2-".Length);
			int expectedTotal = (4 + algoLen) + (4 + curveName.Length) + (4 + expectedQLen);
			// Allow small tolerance for encoding variations.
			if (pubKeyBytes.Count < expectedTotal - 2 || pubKeyBytes.Count > expectedTotal + 2)
			{
				throw new Exception(
					$"Expected {expectedSizeInBits}-bit ECDSA key (pub key ~{expectedTotal} bytes), " +
					$"but got {pubKeyBytes.Count} bytes. Key size mismatch.");
			}
		}
	}
}
