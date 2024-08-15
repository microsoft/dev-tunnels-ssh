// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Helper class to run tasks in sequence.
/// </summary>
public sealed class TaskChain : IDisposable
{
	private Task? runInSequenceTask;

#pragma warning disable CA2213 // Disposable fields should be disposed
	private readonly SemaphoreSlim semaphore = new (1);
#pragma warning restore CA2213 // Disposable fields should be disposed

	private bool isDisposed;
	private readonly TraceSource trace;

	/// <summary>
	/// Create a new instance of <see cref="TaskChain"/>"/> class.
	/// </summary>
	/// <param name="trace">Trace source to use for errors.</param>
	/// <exception cref="ArgumentNullException">Thrown if <paramref name="trace"/> is null.</exception>
	public TaskChain(TraceSource trace)
	{
		this.trace = trace ?? throw new ArgumentNullException(nameof(trace));
	}

	/// <summary>
	/// Run a tasks in the sequence in which they are queued
	/// </summary>
	/// <param name="task">The task that has to be queued</param>
	/// <param name="onError">Called when an error happens while running the task or scheduling the task</param>
	/// <param name="cancellation">Cancellation Token for adding a task to the queue. And note that it does not cancel the task once added.</param>
	public Task RunInSequence(Func<Task> task, Action<Exception> onError, CancellationToken cancellation)
	{
		return RunInSequence(task, onError, null, cancellation);
	}

	/// <summary>
	/// Run a tasks in the sequence in which they are queued
	/// </summary>
	/// <param name="task">The task that has to be queued</param>
	/// <param name="onError">Called when an error happens while running the task or scheduling the task</param>
	/// <param name="preTask">A task which has to be called right after adding task to the queue. And pre task has to be completed before running the task.</param>
	/// <param name="cancellation">Cancellation Token for adding a task to the queue. And note that it does not cancel the task once added.</param>
	/// <exception cref="ArgumentNullException">Throw if <paramref name="task"/> or <paramref name="onError"/> is null.</exception>
	public async Task RunInSequence(Func<Task> task, Action<Exception> onError, Func<Task>? preTask, CancellationToken cancellation)
	{
		if (task == null) throw new ArgumentNullException(nameof(task));
		if (onError == null) throw new ArgumentNullException(nameof(onError));

		if (isDisposed)
		{
			onError(new ObjectDisposedException(GetType().Name));
			return;
		}

		TaskCompletionSource<bool> completionSource = new ();
		try
		{
			await semaphore.WaitAsync(cancellation).ConfigureAwait(false);

			if (runInSequenceTask != null &&
				(runInSequenceTask.IsCanceled || runInSequenceTask.Exception != null))
			{
				// If one task in the sequence is cancelled we have to reset runInSequenceTask
				// so that all subsequent queueing will succeed.
				runInSequenceTask = null;
			}

			async Task RunTaskAsync()
			{
				try
				{
					await completionSource.Task.ConfigureAwait(false);
					await task.Invoke().ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					onError(ex);
				}
			}

			if (runInSequenceTask == null)
			{
				runInSequenceTask = Task.Run(RunTaskAsync, cancellation);
			}
			else
			{
				runInSequenceTask = runInSequenceTask.ContinueWith(
					(_) => RunTaskAsync(),
					cancellation,
					TaskContinuationOptions.None,
					TaskScheduler.Default)
					.Unwrap();
			}
		}
		catch (Exception ex)
		{
			onError(ex);
		}
		finally
		{
			semaphore.TryRelease();
		}

		try
		{
			if (preTask != null)
			{
				await preTask.Invoke().ConfigureAwait(false);
			}
		}
		catch (Exception ex)
		{
			onError(ex);
			throw;
		}
		finally
		{
			completionSource.SetResult(true);
		}
	}

	/// <summary>
	/// Wait for all scheduled tasks.
	/// </summary>
	/// <param name="cancellationToken">Cancellation token for waiting for all the tasks.</param>
	public async Task WaitForAllCurrentTasks(CancellationToken cancellationToken)
	{
		using (var semaphore = new SemaphoreSlim(0))
		{
			await RunInSequence(
				() =>
				{
					semaphore.TryRelease();
					return Task.CompletedTask;
				},
				(ex) =>
				{
					semaphore.TryRelease();
					trace.TraceEvent(
						TraceEventType.Error,
						SshTraceEventIds.TaskChainError,
						$"Waiting for task chain failed with exception {ex}.");
				},
				cancellationToken).ConfigureAwait(false);
			await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
		}
	}

	/// <inheritdoc/>
	public void Dispose()
	{
		isDisposed = true;

		// SemaphoreSlim.Dispose() is not thread-safe and may cause WaitAsync(CancellationToken) not being cancelled
		// when SemaphoreSlim.Dispose is invoked immediately after CancellationTokenSource.Cancel.
		// See https://github.com/dotnet/runtime/issues/59639
		// SemaphoreSlim.Dispose() only disposes it's wait handle, which is not initialized unless its AvailableWaitHandle
		// property is read, which we don't use.

		// semaphore.Dispose();
	}
}
