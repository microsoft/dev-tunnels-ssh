using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Benchmark;

#if NETSTANDARD2_0 || NET4
using ValueTask = System.Threading.Tasks.Task;
public abstract class Benchmark
#else
public abstract class Benchmark : IAsyncDisposable
#endif
{
	public static async Task Main(string[] args)
	{
		List<string> nameList = null;
		int runCount = 7;
		string jsonPath = null;
		foreach (var arg in args)
		{
			if (arg.StartsWith("--json="))
			{
				jsonPath = arg.Substring("--json=".Length);
			}
			else if (int.TryParse(arg, out var runCountArg))
			{
				runCount = runCountArg;
			}
			else
			{
				if (nameList == null)
				{
					nameList = new List<string>();
				}
				nameList.Add(arg);
			}
		}

		JsonResultWriter jsonWriter = jsonPath != null ? new JsonResultWriter() : null;

		var t = TimeSpan.FromSeconds(1);

		var benchmarks = new Dictionary<string, Func<Benchmark>>();

		benchmarks.Add("session", () => new SessionSetupBenchmark(withLatency: false));
		benchmarks.Add("session-with-latency", () => new SessionSetupBenchmark(withLatency: true));
		benchmarks.Add("encrypted-10", () => new ThroughputBenchmark(t, messageSize: 10, withEncryption: true));
		benchmarks.Add("encrypted-200", () => new ThroughputBenchmark(t, messageSize: 200, withEncryption: true));
		benchmarks.Add("encrypted-50000", () => new ThroughputBenchmark(t, messageSize: 50_000, withEncryption: true));
		benchmarks.Add("encrypted-1000000", () => new ThroughputBenchmark(t, messageSize: 1_000_000, withEncryption: true));
		benchmarks.Add("unencrypted-10", () => new ThroughputBenchmark(t, messageSize: 10, withEncryption: false));
		benchmarks.Add("unencrypted-200", () => new ThroughputBenchmark(t, messageSize: 200, withEncryption: false));
		benchmarks.Add("unencrypted-50000", () => new ThroughputBenchmark(t, messageSize: 50_000, withEncryption: false));
		benchmarks.Add("unencrypted-1000000", () => new ThroughputBenchmark(t, messageSize: 1_000_000, withEncryption: false));
		benchmarks.Add("portforward-ipv4", () => new PortForwardBenchmark(IPAddress.Loopback, IPAddress.Loopback.ToString()));
		benchmarks.Add("portforward-ipv4-localhost", () => new PortForwardBenchmark(IPAddress.Loopback, "localhost"));
		benchmarks.Add("portforward-ipv6", () => new PortForwardBenchmark(IPAddress.IPv6Loopback, IPAddress.IPv6Loopback.ToString()));
		benchmarks.Add("portforward-ipv6-localhost", () => new PortForwardBenchmark(IPAddress.IPv6Loopback, "localhost"));

		// Encryption benchmarks
#if SSH_ENABLE_AESGCM
		benchmarks.Add("enc-aes256gcm-1024", () => new EncryptionBenchmark(SshAlgorithms.Encryption.Aes256Gcm, 1024));
		benchmarks.Add("enc-aes256gcm-32768", () => new EncryptionBenchmark(SshAlgorithms.Encryption.Aes256Gcm, 32768));
		benchmarks.Add("enc-aes256gcm-65536", () => new EncryptionBenchmark(SshAlgorithms.Encryption.Aes256Gcm, 65536));
#endif
		benchmarks.Add("enc-aes256cbc-32768", () => new EncryptionBenchmark(SshAlgorithms.Encryption.Aes256Cbc, 32768));
		benchmarks.Add("enc-aes256ctr-32768", () => new EncryptionBenchmark(SshAlgorithms.Encryption.Aes256Ctr, 32768));

		// HMAC benchmarks
		benchmarks.Add("hmac-sha256", () => new HmacBenchmark(SshAlgorithms.Hmac.HmacSha256));
		benchmarks.Add("hmac-sha512", () => new HmacBenchmark(SshAlgorithms.Hmac.HmacSha512));
		benchmarks.Add("hmac-sha256-etm", () => new HmacBenchmark(SshAlgorithms.Hmac.HmacSha256Etm));
		benchmarks.Add("hmac-sha512-etm", () => new HmacBenchmark(SshAlgorithms.Hmac.HmacSha512Etm));

		// KEX benchmarks
#if SSH_ENABLE_ECDH
		benchmarks.Add("kex-ecdh-p256", () => new KeyExchangeBenchmark(SshAlgorithms.KeyExchange.EcdhNistp256));
		benchmarks.Add("kex-ecdh-p384", () => new KeyExchangeBenchmark(SshAlgorithms.KeyExchange.EcdhNistp384));
		benchmarks.Add("kex-ecdh-p521", () => new KeyExchangeBenchmark(SshAlgorithms.KeyExchange.EcdhNistp521));
#endif
		benchmarks.Add("kex-dh-group14", () => new KeyExchangeBenchmark(SshAlgorithms.KeyExchange.DHGroup14Sha256));
		benchmarks.Add("kex-dh-group16", () => new KeyExchangeBenchmark(SshAlgorithms.KeyExchange.DHGroup16Sha512));

		// Keygen benchmarks
		benchmarks.Add("keygen-rsa-2048", () => new KeygenBenchmark(SshAlgorithms.PublicKey.RsaWithSha256, 2048));
		benchmarks.Add("keygen-rsa-4096", () => new KeygenBenchmark(SshAlgorithms.PublicKey.RsaWithSha256, 4096));
		benchmarks.Add("keygen-ecdsa-p256", () => new KeygenBenchmark(SshAlgorithms.PublicKey.ECDsaSha2Nistp256, 256));
		benchmarks.Add("keygen-ecdsa-p384", () => new KeygenBenchmark(SshAlgorithms.PublicKey.ECDsaSha2Nistp384, 384));
		benchmarks.Add("keygen-ecdsa-p521", () => new KeygenBenchmark(SshAlgorithms.PublicKey.ECDsaSha2Nistp521, 521));

		// Signature benchmarks
		benchmarks.Add("sig-rsa-sha256", () => new SignatureBenchmark(SshAlgorithms.PublicKey.RsaWithSha256, 2048));
		benchmarks.Add("sig-rsa-sha512", () => new SignatureBenchmark(SshAlgorithms.PublicKey.RsaWithSha512, 2048));
		benchmarks.Add("sig-ecdsa-p256", () => new SignatureBenchmark(SshAlgorithms.PublicKey.ECDsaSha2Nistp256, 256));
		benchmarks.Add("sig-ecdsa-p384", () => new SignatureBenchmark(SshAlgorithms.PublicKey.ECDsaSha2Nistp384, 384));
		benchmarks.Add("sig-ecdsa-p521", () => new SignatureBenchmark(SshAlgorithms.PublicKey.ECDsaSha2Nistp521, 521));

		// Protocol serialization benchmarks
		benchmarks.Add("msg-channel-data", () => new ChannelDataSerializationBenchmark());
		benchmarks.Add("msg-channel-open", () => new ChannelOpenSerializationBenchmark());
		benchmarks.Add("msg-kex-init", () => new KeyExchangeInitSerializationBenchmark());

		// Protocol KEX cycle benchmark
#if SSH_ENABLE_ECDH
		benchmarks.Add("kex-cycle-ecdh-p384", () => new KexCycleBenchmark());
#endif

		var stopwatch = new Stopwatch();

		ServerPort = GetAvailableTcpPort();

		foreach (var benchmarkPair in benchmarks)
		{
			var benchmarkName = benchmarkPair.Key;
			var benchmarkFunc = benchmarkPair.Value;

			if (nameList != null && !nameList.Contains(benchmarkName))
			{
				continue;
			}

			var benchmark = benchmarkFunc();
			try
			{
				benchmark.ReportTitle();

				// Warmup run (not recorded).
				try { await benchmark.RunAsync(stopwatch); } catch { }
				benchmark.Measurements.Clear();

				for (int i = 0; i < runCount; i++)
				{
					await Task.Delay(TimeSpan.FromMilliseconds(100));
					stopwatch.Restart();
					try
					{
						await benchmark.RunAsync(stopwatch);
						Console.Write(".");
					}
					catch (Exception ex) when (ex is not OutOfMemoryException)
					{
						Console.Error.WriteLine(
							$"\nRun {i + 1} of '{benchmarkName}' failed: {ex.Message}");
					}
				}

				benchmark.ReportResults();
				jsonWriter?.AddBenchmark(benchmark);
			}
			catch (Exception ex) when (ex is not OutOfMemoryException)
			{
				Console.Error.WriteLine(
					$"\nBenchmark '{benchmarkName}' failed: {ex.Message}");
			}
			finally
			{
				await benchmark.DisposeAsync();
			}
		}

		if (jsonWriter != null)
		{
			jsonWriter.Write(jsonPath, runCount);
			Console.WriteLine($"JSON results written to {jsonPath}");
		}
	}

	protected static int ServerPort { get; private set; }

	protected Benchmark(
		string title,
		string category = "",
		IDictionary<string, string> tags = null)
	{
		Title = title;
		Category = category;
		Tags = tags ?? new Dictionary<string, string>();
		Measurements = new Dictionary<string, IList<decimal>>();
		HigherIsBetter = new Dictionary<string, bool>();
	}

	public string Title { get; }
	public string Category { get; }
	public IDictionary<string, string> Tags { get; }
	public IDictionary<string, IList<decimal>> Measurements { get; }
	public IDictionary<string, bool> HigherIsBetter { get; }

	protected abstract Task RunAsync(Stopwatch stopwatch);

	protected void AddMeasurement(string measurement, double value)
	{
		AddMeasurement(measurement, (decimal)value);
	}

	protected void AddMeasurement(string measurement, decimal value)
	{
		if (!Measurements.TryGetValue(measurement, out var measurements))
		{
			measurements = new List<decimal>();
			Measurements.Add(measurement, measurements);
		}

		measurements.Add(value);
	}

	private void ReportTitle()
	{
		if (Console.BackgroundColor == ConsoleColor.Black)
		{
			Console.ForegroundColor = ConsoleColor.Yellow;
		}

		Console.Write("# " + Title);
		Console.ResetColor();
		Console.Write(" ");
	}

	private void ReportResults()
	{
		Console.WriteLine();

		foreach (var measurementPair in Measurements)
		{
			var measurement = measurementPair.Key;
			var measurements = measurementPair.Value;

			if (!HigherIsBetter.TryGetValue(measurement, out var higherIsBetter))
			{
				higherIsBetter = true;
			}

			var min = measurements.Min();
			var minIndex = measurements.IndexOf(min);
			var max = measurements.Max();
			var maxIndex = measurements.IndexOf(max);
			var refinedMeasurements = measurements.Where((m, i) => i != minIndex && i != maxIndex).ToList();
			var allEqual = (min == max);

			Console.Write("{0,-24}", measurement);
			foreach (var value in measurements)
			{
				if (!allEqual && value == (higherIsBetter ? min : max))
				{
					Console.ForegroundColor = ConsoleColor.Red;
				}
				else if (!allEqual && value == (higherIsBetter ? max : min))
				{
					Console.ForegroundColor = ConsoleColor.Green;
				}

				Console.Write(" {0,8:F2}", value);
				Console.ResetColor();
			}

			if (refinedMeasurements.Count > 0)
			{
				var average = refinedMeasurements.Average();
				Console.ForegroundColor = ConsoleColor.Blue;
				Console.Write("     Average: {0,8:F2}", average);
				Console.ResetColor();
			}

			Console.WriteLine();
		}

		Console.WriteLine();
	}

	private static int GetAvailableTcpPort()
	{
		// Get any available local tcp port
		var l = new TcpListener(IPAddress.Loopback, 0);
		l.Start();
		int port = ((IPEndPoint)l.LocalEndpoint).Port;
		l.Stop();
		return port;
	}

	public abstract ValueTask DisposeAsync();
}
