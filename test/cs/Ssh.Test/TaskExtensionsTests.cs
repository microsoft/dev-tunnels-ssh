using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

#if !NET6_0_OR_GREATER

public class TaskExtensionsTests
{
	[Fact]
	public async Task WaitAsync_ThrowsForNullTask()
	{
		await Assert.ThrowsAsync<ArgumentNullException>(() => ((Task)null).WaitAsync(default));
		await Assert.ThrowsAsync<ArgumentNullException>(() => ((Task<bool>)null).WaitAsync(default));
	}

	[Fact]
	public async Task WaitAsync_ThrowsForCancellation()
	{
		using var cts = new CancellationTokenSource();
		cts.Cancel();

		await Assert.ThrowsAsync<OperationCanceledException>(() => Task.CompletedTask.WaitAsync(cts.Token));
		await Assert.ThrowsAsync<OperationCanceledException>(() => Task.FromResult(true).WaitAsync(cts.Token));
	}

	[Fact]
	public async Task WaitAsync_CannotBeCancelled()
	{
		await Task.CompletedTask.WaitAsync(default);
		Assert.True(await Task.FromResult(true).WaitAsync(default));
	}

	[Fact]
	public async Task WaitAsync_Cancelled()
	{
		using var cts = new CancellationTokenSource();
		var tcs = new TaskCompletionSource<bool>();

		var task1 = (tcs.Task as Task).WaitAsync(cts.Token);
		var task2 = tcs.Task.WaitAsync(cts.Token);

		Assert.False(task1.IsCompleted);
		Assert.False(task2.IsCompleted);

		cts.Cancel();

		Assert.Equal(cts.Token, (await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task1)).CancellationToken);
		Assert.Equal(cts.Token, (await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task2)).CancellationToken);
	}

	[Fact]
	public async Task WaitAsync_ReturnsResult()
	{

		using var cts = new CancellationTokenSource();
		var tcs = new TaskCompletionSource<bool>();

		var task1 = (tcs.Task as Task).WaitAsync(cts.Token);
		var task2 = tcs.Task.WaitAsync(cts.Token);

		Assert.False(task1.IsCompleted);
		Assert.False(task2.IsCompleted);

		tcs.SetResult(true);

		await task1;
		Assert.True(await task2);
	}

	[Fact]
	public async Task WaitAsync_ThrowsException()
	{
		using var cts = new CancellationTokenSource();
		var tcs = new TaskCompletionSource<bool>();

		var task1 = (tcs.Task as Task).WaitAsync(cts.Token);
		var task2 = tcs.Task.WaitAsync(cts.Token);

		Assert.False(task1.IsCompleted);
		Assert.False(task2.IsCompleted);

		var exception = new InvalidOperationException();
		tcs.SetException(exception);

		Assert.Equal(exception, await Assert.ThrowsAsync<InvalidOperationException>(() => task1));
		Assert.Equal(exception, await Assert.ThrowsAsync<InvalidOperationException>(() => task2));
	}
}

#endif