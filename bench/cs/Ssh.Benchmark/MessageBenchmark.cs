using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.IO;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Benchmark;

#if NETSTANDARD2_0 || NET4
using ValueTask = System.Threading.Tasks.Task;
#endif

class ChannelDataSerializationBenchmark : Benchmark
{
	private const string RoundTripTimeMeasurement = "Round-trip time (ms)";

	public ChannelDataSerializationBenchmark()
		: base(
			"Serialize ChannelData",
			"protocol-serialization",
			new Dictionary<string, string>
			{
				{ "msg", "channel-data" },
			})
	{
		HigherIsBetter[RoundTripTimeMeasurement] = false;
	}

	protected override Task RunAsync(Stopwatch stopwatch)
	{
		const int Iterations = 1000;

		var data = new Buffer(32768);
		SshAlgorithms.Random.GetBytes(data);

		var msg = new ChannelDataMessage
		{
			RecipientChannel = 1,
			Data = data,
		};

		stopwatch.Restart();

		for (int i = 0; i < Iterations; i++)
		{
			var buffer = msg.ToBuffer();
			var reader = new SshDataReader(buffer);
			var msg2 = new ChannelDataMessage();
			msg2.Read(ref reader);
		}

		stopwatch.Stop();

		AddMeasurement(RoundTripTimeMeasurement, stopwatch.Elapsed.TotalMilliseconds / Iterations);

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

class ChannelOpenSerializationBenchmark : Benchmark
{
	private const string RoundTripTimeMeasurement = "Round-trip time (ms)";

	public ChannelOpenSerializationBenchmark()
		: base(
			"Serialize ChannelOpen",
			"protocol-serialization",
			new Dictionary<string, string>
			{
				{ "msg", "channel-open" },
			})
	{
		HigherIsBetter[RoundTripTimeMeasurement] = false;
	}

	protected override Task RunAsync(Stopwatch stopwatch)
	{
		const int Iterations = 1000;

		var msg = new ChannelOpenMessage
		{
			ChannelType = "session",
			SenderChannel = 0,
			MaxWindowSize = SshChannel.DefaultMaxWindowSize,
			MaxPacketSize = SshChannel.DefaultMaxPacketSize,
		};

		stopwatch.Restart();

		for (int i = 0; i < Iterations; i++)
		{
			var buffer = msg.ToBuffer();
			var reader = new SshDataReader(buffer);
			var msg2 = new ChannelOpenMessage();
			msg2.Read(ref reader);
		}

		stopwatch.Stop();

		AddMeasurement(RoundTripTimeMeasurement, stopwatch.Elapsed.TotalMilliseconds / Iterations);

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

class KeyExchangeInitSerializationBenchmark : Benchmark
{
	private const string RoundTripTimeMeasurement = "Round-trip time (ms)";

	// Realistic algorithm lists matching SSH defaults
	private static readonly string[] KexAlgorithms = new[]
	{
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
	};
	private static readonly string[] HostKeyAlgorithms = new[]
	{
		"rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
	};
	private static readonly string[] EncryptionAlgorithms = new[]
	{
		"aes256-gcm@openssh.com", "aes256-cbc", "aes256-ctr",
	};
	private static readonly string[] MacAlgorithms = new[]
	{
		"hmac-sha2-256", "hmac-sha2-512",
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
	};
	private static readonly string[] CompressionAlgorithms = new[] { "none" };

	public KeyExchangeInitSerializationBenchmark()
		: base(
			"Serialize KeyExchangeInit",
			"protocol-serialization",
			new Dictionary<string, string>
			{
				{ "msg", "kex-init" },
			})
	{
		HigherIsBetter[RoundTripTimeMeasurement] = false;
	}

	protected override Task RunAsync(Stopwatch stopwatch)
	{
		const int Iterations = 1000;

		stopwatch.Restart();

		for (int i = 0; i < Iterations; i++)
		{
			// Serialize KEXINIT format: type(1) + cookie(16) + 10 lists + bool + uint32
			var writer = new SshDataWriter();
			writer.Write((byte)20); // SSH_MSG_KEXINIT
			writer.WriteRandom(16); // cookie
			writer.Write(KexAlgorithms, Encoding.ASCII);
			writer.Write(HostKeyAlgorithms, Encoding.ASCII);
			writer.Write(EncryptionAlgorithms, Encoding.ASCII); // client-to-server
			writer.Write(EncryptionAlgorithms, Encoding.ASCII); // server-to-client
			writer.Write(MacAlgorithms, Encoding.ASCII); // client-to-server
			writer.Write(MacAlgorithms, Encoding.ASCII); // server-to-client
			writer.Write(CompressionAlgorithms, Encoding.ASCII); // client-to-server
			writer.Write(CompressionAlgorithms, Encoding.ASCII); // server-to-client
			writer.Write(Array.Empty<string>(), Encoding.ASCII); // languages c-to-s
			writer.Write(Array.Empty<string>(), Encoding.ASCII); // languages s-to-c
			writer.Write(false); // first_kex_packet_follows
			writer.Write(0U); // reserved

			var buffer = writer.ToBuffer();

			// Deserialize
			var reader = new SshDataReader(buffer);
			reader.ReadByte(); // type
			reader.ReadBinary(16U); // cookie
			reader.ReadList(Encoding.ASCII); // kex algorithms
			reader.ReadList(Encoding.ASCII); // host key algorithms
			reader.ReadList(Encoding.ASCII); // encryption c-to-s
			reader.ReadList(Encoding.ASCII); // encryption s-to-c
			reader.ReadList(Encoding.ASCII); // mac c-to-s
			reader.ReadList(Encoding.ASCII); // mac s-to-c
			reader.ReadList(Encoding.ASCII); // compression c-to-s
			reader.ReadList(Encoding.ASCII); // compression s-to-c
			reader.ReadList(Encoding.ASCII); // languages c-to-s
			reader.ReadList(Encoding.ASCII); // languages s-to-c
			reader.ReadBoolean(); // first_kex_packet_follows
			reader.ReadUInt32(); // reserved
		}

		stopwatch.Stop();

		AddMeasurement(RoundTripTimeMeasurement, stopwatch.Elapsed.TotalMilliseconds / Iterations);

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

#if SSH_ENABLE_ECDH
class KexCycleBenchmark : Benchmark
{
	private const string KexCycleTimeMeasurement = "KEX cycle time (ms)";

	public KexCycleBenchmark()
		: base(
			"KEX Cycle ECDH P-384",
			"protocol-kex-cycle",
			new Dictionary<string, string>
			{
				{ "algo", "ecdh-sha2-nistp384" },
			})
	{
		HigherIsBetter[KexCycleTimeMeasurement] = false;
	}

	protected override Task RunAsync(Stopwatch stopwatch)
	{
		var kexAlgorithm = SshAlgorithms.KeyExchange.EcdhNistp384;
		var hostKeyAlgorithm = SshAlgorithms.PublicKey.ECDsaSha2Nistp384;

		// Pre-generate server host key (outside timed section)
		using var hostKeyPair = hostKeyAlgorithm.GenerateKeyPair(384);

		stopwatch.Restart();

		// 1. Both sides serialize KEXINIT
		SerializeKexInit();
		SerializeKexInit();

		// 2. Client starts key exchange
		using var clientKex = kexAlgorithm.CreateKeyExchange();
		var clientPublic = clientKex.StartKeyExchange();

		// 3. Serialize client's DH_INIT (E value)
		var dhInitWriter = new SshDataWriter();
		dhInitWriter.Write((byte)30); // SSH_MSG_KEXDH_INIT
		dhInitWriter.WriteBinary(clientPublic);
		var dhInitBuffer = dhInitWriter.ToBuffer();

		// 4. Server receives DH_INIT, deserializes E
		var dhInitReader = new SshDataReader(dhInitBuffer);
		dhInitReader.ReadByte(); // type
		var clientE = dhInitReader.ReadBinary();

		// 5. Server does key exchange
		using var serverKex = kexAlgorithm.CreateKeyExchange();
		var serverPublic = serverKex.StartKeyExchange();
		_ = serverKex.DecryptKeyExchange(clientE);

		// 6. Server signs exchange hash and serializes DH_REPLY
		var testData = new Buffer(48);
		SshAlgorithms.Random.GetBytes(testData);
		using var signer = hostKeyAlgorithm.CreateSigner(hostKeyPair);
		var signature = new Buffer(signer.DigestLength);
		signer.Sign(testData, signature);

		var dhReplyWriter = new SshDataWriter();
		dhReplyWriter.Write((byte)31); // SSH_MSG_KEXDH_REPLY
		dhReplyWriter.WriteBinary(hostKeyPair.GetPublicKeyBytes());
		dhReplyWriter.WriteBinary(serverPublic);
		dhReplyWriter.WriteBinary(signature);
		var dhReplyBuffer = dhReplyWriter.ToBuffer();

		// 7. Client receives DH_REPLY, deserializes
		var dhReplyReader = new SshDataReader(dhReplyBuffer);
		dhReplyReader.ReadByte(); // type
		_ = dhReplyReader.ReadBinary(); // hostKey
		var serverF = dhReplyReader.ReadBinary();
		var sig = dhReplyReader.ReadBinary();

		// 8. Client completes key exchange
		_ = clientKex.DecryptKeyExchange(serverF);

		// 9. Client verifies signature
		using var verifier = hostKeyAlgorithm.CreateVerifier(hostKeyPair);
		verifier.Verify(testData, sig);

		stopwatch.Stop();

		AddMeasurement(KexCycleTimeMeasurement, stopwatch.Elapsed.TotalMilliseconds);

		return Task.CompletedTask;
	}

	private static void SerializeKexInit()
	{
		var writer = new SshDataWriter();
		writer.Write((byte)20); // SSH_MSG_KEXINIT
		writer.WriteRandom(16); // cookie
		writer.Write(new[] { "ecdh-sha2-nistp384" }, Encoding.ASCII);
		writer.Write(new[] { "ecdsa-sha2-nistp384" }, Encoding.ASCII);
		writer.Write(new[] { "aes256-gcm@openssh.com" }, Encoding.ASCII);
		writer.Write(new[] { "aes256-gcm@openssh.com" }, Encoding.ASCII);
		writer.Write(new[] { "hmac-sha2-256" }, Encoding.ASCII);
		writer.Write(new[] { "hmac-sha2-256" }, Encoding.ASCII);
		writer.Write(new[] { "none" }, Encoding.ASCII);
		writer.Write(new[] { "none" }, Encoding.ASCII);
		writer.Write(Array.Empty<string>(), Encoding.ASCII);
		writer.Write(Array.Empty<string>(), Encoding.ASCII);
		writer.Write(false);
		writer.Write(0U);
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
#endif
