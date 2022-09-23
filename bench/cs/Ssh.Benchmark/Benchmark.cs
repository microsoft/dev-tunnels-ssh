using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh.Benchmark;

public abstract class Benchmark
#if !NETSTANDARD2_0
		: IAsyncDisposable
#endif
{
	public static async Task Main(string[] args)
	{
		List<string> nameList = null;
		int runCount = 7;
		foreach (var arg in args)
		{
			if (int.TryParse(arg, out var runCountArg))
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

		var stopwatch = new Stopwatch();

		ServerPort = GetAvailableTcpPort();

		foreach (var (benchmarkName, benchmarkFunc) in benchmarks)
		{
			if (nameList != null && !nameList.Contains(benchmarkName))
			{
				continue;
			}

			var benchmark = benchmarkFunc();
			try
			{
				benchmark.ReportTitle();

				for (int i = 0; i < runCount; i++)
				{
					await Task.Delay(TimeSpan.FromMilliseconds(100));
					stopwatch.Restart();
					await benchmark.RunAsync(stopwatch);
					Console.Write(".");
				}

				benchmark.ReportResults();
			}
			finally
			{
				await benchmark.DisposeAsync();
			}
		}
	}

	protected static int ServerPort { get; private set; }

	protected Benchmark(string title)
	{
		Title = title;
		Measurements = new Dictionary<string, IList<decimal>>();
		HigherIsBetter = new Dictionary<string, bool>();
	}

	public string Title { get; }
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

		foreach (var (measurement, measurements) in Measurements)
		{
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
