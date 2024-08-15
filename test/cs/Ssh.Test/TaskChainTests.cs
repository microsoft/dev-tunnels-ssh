using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class TaskChainTests
{
	public TaskChainTests()
	{
		Trace = new TraceSource("test");
		TaskChain = new TaskChain(Trace);
	}

	private TraceSource Trace { get; }

	private TaskChain TaskChain { get; }

	[Fact]
	public async Task RunInSequence_WhenTaskIsDisposed_ShouldCallOnError()
	{
		// Arrange
		Exception exception = null;
		TaskChain.Dispose();

		// Act
		await TaskChain.RunInSequence(
			() => Task.CompletedTask, (e) => exception = e, CancellationToken.None);

		// Assert
		Assert.IsType<ObjectDisposedException>(exception);
	}

	[Fact]
	public async Task RunInSequence_ExecutesInSequence()
	{
		const int TaskCount = 20;

		// Arrange
		var syncRoot = new object();
		var random = new Random();
		var taskNumbers = new List<int>();
		Exception exception = null;

		// Act
		for (int i = 0; i < TaskCount; i++)
		{
			await TaskChain.RunInSequence(CreateTask(i), (e) => exception = e, CancellationToken.None);
		}

		await TaskChain.WaitForAllCurrentTasks(CancellationToken.None);

		// Assert
		Assert.Null(exception);
		Assert.Equal(Enumerable.Range(0, TaskCount), taskNumbers);

		Func<Task> CreateTask(int iteration) =>
			async () =>
			{
				int delayMs;
				lock (syncRoot)
				{
					delayMs = random.Next(20);
				}

				await Task.Delay(delayMs);
				lock (syncRoot)
				{
					taskNumbers.Add(iteration);
				}
			};
	}
}
