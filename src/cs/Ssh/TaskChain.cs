// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh;

internal class TaskChain : IDisposable
{
	private Task? runInSequenceTask;

#pragma warning disable CA2213 // Disposable fields should be disposed
	private readonly SemaphoreSlim semaphore = new (1);
#pragma warning restore CA2213 // Disposable fields should be disposed

	private bool isDisposed;
	private readonly TraceSource trace;

	public TaskChain(TraceSource trace)
	{
		this.trace = trace;
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
	public async Task RunInSequence(Func<Task> task, Action<Exception> onError, Func<Task>? preTask, CancellationToken cancellation)
	{
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

			if (runInSequenceTask == null)
			{
				runInSequenceTask = Task.Factory.StartNew(
					async () =>
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
					},
					cancellation,
					TaskCreationOptions.None,
					TaskScheduler.Default);
			}
			else
			{
				runInSequenceTask = runInSequenceTask.ContinueWith(
					async _ =>
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
					},
					cancellation,
					TaskContinuationOptions.None,
					TaskScheduler.Default);
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
						$"Waiting for task chain failed with exception ${ex?.ToString()}.");
				},
				cancellationToken).ConfigureAwait(false);
			await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
		}
	}

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
