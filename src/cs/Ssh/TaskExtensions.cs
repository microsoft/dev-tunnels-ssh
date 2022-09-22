// Copyright (c) Microsoft. All rights reserved.

using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.DevTunnels.Ssh;

internal static class TaskExtensions
{
	/// <summary>
	/// Waits either for a task to complete for for a cancellation token to be cancelled.
	/// </summary>
	public static async Task WaitAsync(this Task task, CancellationToken cancellation)
	{
		if (cancellation.CanBeCanceled)
		{
			var cancellationCompletionSource = new TaskCompletionSource<bool>(
				TaskCreationOptions.RunContinuationsAsynchronously);
			using (cancellation.Register(() => cancellationCompletionSource.SetCanceled()))
			{
				cancellation.ThrowIfCancellationRequested();
				await Task.WhenAny(task, cancellationCompletionSource.Task).ConfigureAwait(false);
			}
		}
		else
		{
			await task.ConfigureAwait(false);
		}
	}

	/// <summary>
	/// Waits either for a task to complete for for a cancellation token to be cancelled.
	/// </summary>
	/// <typeparam name="T">The type of task to wait on.</typeparam>
	public static async Task<T> WaitAsync<T>(this Task<T> task, CancellationToken cancellation)
	{
		if (cancellation.CanBeCanceled)
		{
			var cancellationCompletionSource = new TaskCompletionSource<bool>(
				TaskCreationOptions.RunContinuationsAsynchronously);
			using (cancellation.Register(() => cancellationCompletionSource.SetCanceled()))
			{
				cancellation.ThrowIfCancellationRequested();
				await Task.WhenAny(task, cancellationCompletionSource.Task).ConfigureAwait(false);
				return task.Result;
			}
		}
		else
		{
			return await task.ConfigureAwait(false);
		}
	}
}
