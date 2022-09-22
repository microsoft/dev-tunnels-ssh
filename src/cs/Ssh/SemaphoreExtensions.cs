// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Threading;

namespace Microsoft.DevTunnels.Ssh;

internal static class SemaphoreExtensions
{
	public static void TryRelease(this SemaphoreSlim semaphore)
	{
		try
		{
			semaphore.Release();
		}
		catch (ObjectDisposedException)
		{
		}
	}
}
