using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Microsoft.DevTunnels.Ssh.Benchmark;

class JsonResultWriter
{
	private readonly List<SuiteResult> suites = new List<SuiteResult>();

	public void AddBenchmark(Benchmark benchmark, VerificationResult verificationResult = null)
	{
		var metrics = new List<MetricResult>();

		foreach (var measurementPair in benchmark.Measurements)
		{
			var name = measurementPair.Key;
			var values = measurementPair.Value;

			// Extract unit from measurement name, e.g. "Connect time (ms)" → name="Connect time", unit="ms"
			string unit = "";
			string metricName = name;
			var parenStart = name.LastIndexOf('(');
			var parenEnd = name.LastIndexOf(')');
			if (parenStart >= 0 && parenEnd > parenStart)
			{
				unit = name.Substring(parenStart + 1, parenEnd - parenStart - 1);
				metricName = name.Substring(0, parenStart).TrimEnd();
			}

			if (!benchmark.HigherIsBetter.TryGetValue(name, out var higherIsBetter))
			{
				higherIsBetter = true;
			}

			metrics.Add(new MetricResult
			{
				Name = metricName,
				Unit = unit,
				Values = values.Select(v => Math.Round((double)v, 6)).ToArray(),
				HigherIsBetter = higherIsBetter,
			});
		}

		suites.Add(new SuiteResult
		{
			Category = benchmark.Category,
			Name = benchmark.Title,
			Tags = new Dictionary<string, string>(benchmark.Tags),
			Metrics = metrics,
			Verification = verificationResult,
		});
	}

	public void Write(string path, int runCount)
	{
		var result = new ResultFile
		{
			Metadata = new MetadataResult
			{
				Platform = "cs",
				PlatformVersion = RuntimeInformation.FrameworkDescription,
				Os = GetOsString(),
				Timestamp = DateTime.UtcNow.ToString("o"),
				RunCount = runCount,
				GitCommit = GetGitCommit(),
			},
			Suites = suites.ToArray(),
		};

		var options = new JsonSerializerOptions
		{
			WriteIndented = true,
			PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
			DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
		};

		var json = JsonSerializer.Serialize(result, options);

		var dir = Path.GetDirectoryName(path);
		if (!string.IsNullOrEmpty(dir))
		{
			Directory.CreateDirectory(dir);
		}

		File.WriteAllText(path, json);
	}

	private static string GetOsString()
	{
		string os;
		if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
		{
			os = "darwin";
		}
		else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
		{
			os = "linux";
		}
		else
		{
			os = "win";
		}

		var arch = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant();
		return $"{os}-{arch}";
	}

	private static string GetGitCommit()
	{
		try
		{
			var process = new Process
			{
				StartInfo = new ProcessStartInfo
				{
					FileName = "git",
					Arguments = "rev-parse HEAD",
					RedirectStandardOutput = true,
					UseShellExecute = false,
					CreateNoWindow = true,
				}
			};
			process.Start();
			var commit = process.StandardOutput.ReadToEnd().Trim();
			process.WaitForExit();
			return commit;
		}
		catch
		{
			return "unknown";
		}
	}

	private class ResultFile
	{
		public MetadataResult Metadata { get; set; }
		public SuiteResult[] Suites { get; set; }
	}

	private class MetadataResult
	{
		public string Platform { get; set; }
		public string PlatformVersion { get; set; }
		public string Os { get; set; }
		public string Timestamp { get; set; }
		public int RunCount { get; set; }
		public string GitCommit { get; set; }
	}

	private class SuiteResult
	{
		public string Category { get; set; }
		public string Name { get; set; }
		public Dictionary<string, string> Tags { get; set; }
		public List<MetricResult> Metrics { get; set; }
		public VerificationResult Verification { get; set; }
	}

	public class VerificationResult
	{
		public bool Passed { get; set; }
		public string Error { get; set; }
	}

	private class MetricResult
	{
		public string Name { get; set; }
		public string Unit { get; set; }
		public double[] Values { get; set; }
		public bool HigherIsBetter { get; set; }
	}
}
