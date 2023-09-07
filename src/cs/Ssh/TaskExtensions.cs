// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh;

internal static class TaskExtensions
{
	/// <summary>
	/// Waits either for <paramref name="task"/> to complete or for <paramref name="cancellation"/> to be cancelled.
	/// Throws any exception off <paramref name="task"/> if it completes first and is faulted.
	/// If <paramref name="cancellation"/> is cancelled first, throws <see cref="OperationCanceledException"/>
	/// from that cancellation, leaving <paramref name="task"/> run its course unobserved.
	/// </summary>
	/// <exception cref="ArgumentNullException">If <paramref name="task"/> is null.</exception>
	/// <exception cref="OperationCanceledException">If <paramref name="cancellation"/> is cancelled first.</exception>
	public static async Task WaitAsync(this Task task, CancellationToken cancellation)
	{
		if (task == null)
		{
			throw new ArgumentNullException(nameof(task));
		}

		if (!cancellation.CanBeCanceled)
		{
			await task.ConfigureAwait(false);
			return;
		}

		cancellation.ThrowIfCancellationRequested();
		var cancellationCompletionSource = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
		using var cancellationRegistration = cancellation.Register(() => cancellationCompletionSource.TrySetCanceled(cancellation));
		var firstTaskToComplete = await Task.WhenAny(task, cancellationCompletionSource.Task).ConfigureAwait(false);

		// This may throw OperationCancelledException if the first task to complete is from cancellationCompletionSource.Task
		// or throw any exceptions from executing task argument.
		await firstTaskToComplete.ConfigureAwait(false);
	}

	/// <summary>
	/// Waits either for <paramref name="task"/> to complete or for <paramref name="cancellation"/> to be cancelled.
	/// If <paramref name="task"/> completes first, returns its result or throws it's exception if it faulted.
	/// If <paramref name="cancellation"/> is cancelled first, throws <see cref="OperationCanceledException"/>
	/// from that cancellation, leaving <paramref name="task"/> run its course unobserved.
	/// </summary>
	/// <typeparam name="T">The type of task to wait on.</typeparam>
	/// <exception cref="ArgumentNullException">If <paramref name="task"/> is null.</exception>
	/// <exception cref="OperationCanceledException">If <paramref name="cancellation"/> is cancelled first.</exception>
	public static async Task<T> WaitAsync<T>(this Task<T> task, CancellationToken cancellation)
	{
		if (task == null)
		{
			throw new ArgumentNullException(nameof(task));
		}

		if (!cancellation.CanBeCanceled)
		{
			return await task.ConfigureAwait(false);
		}

		cancellation.ThrowIfCancellationRequested();
		var cancellationCompletionSource = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
		using var cancellationRegistration = cancellation.Register(() => cancellationCompletionSource.TrySetCanceled(cancellation));
		var firstTaskToComplete = await Task.WhenAny(task, cancellationCompletionSource.Task).ConfigureAwait(false);
		if (firstTaskToComplete != task)
		{
			// This will throw OperationCanceledException.
			await firstTaskToComplete.ConfigureAwait(false);
		}

		return await task.ConfigureAwait(false);
	}
}
