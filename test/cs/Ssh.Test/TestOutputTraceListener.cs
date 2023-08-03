using Microsoft;
using System.Diagnostics;
using System.Text;
using System;
using Xunit.Abstractions;

/// <summary>
/// A trace listener that writes to Xunit's test output.
/// </summary>
public class TestOutputTraceListener : TraceListener
{
	private readonly StringBuilder lineBuilder = new();

	public TestOutputTraceListener(ITestOutputHelper testOutput)
	{
		TestOutput = Requires.NotNull(testOutput, nameof(testOutput));
	}

	public ITestOutputHelper TestOutput { get; }

	public override void Write(string message)
	{
		lock (this.lineBuilder)
		{
			this.lineBuilder.Append(message);
		}
	}

	public override void WriteLine(string message)
	{
		lock (this.lineBuilder)
		{
			this.lineBuilder.Append(message);

			try
			{
				TestOutput.WriteLine(this.lineBuilder.ToString());
			}
			catch (InvalidOperationException)
			{
				// This can happen if the test has already completed.
			}

			this.lineBuilder.Clear();
		}
	}
}
