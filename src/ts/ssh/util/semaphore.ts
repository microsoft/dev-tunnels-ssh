//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { PromiseCompletionSource } from './promiseCompletionSource';
import { Disposable } from 'vscode-jsonrpc';
import { CancellationToken, CancellationError } from './cancellation';
import { ObjectDisposedError } from '../errors';

/**
 * Semaphore-like object that allows multiple awaiters to coordinate exclusive access to a resource.
 */
export class Semaphore implements Disposable {
	private count: number;
	private readonly completions: PromiseCompletionSource<boolean>[] = [];
	private disposed: boolean = false;

	/**
	 * Creates a new semaphore instance.
	 * @param initialCount Optional initial count. Defaults to 0.
	 */
	public constructor(initialCount: number = 0) {
		this.count = initialCount;
	}

	/**
	 * Gets the current available count of the semaphore.
	 */
	public get currentCount() {
		return this.count;
	}

	/**
	 * Releases the semaphore, increasing the available count or unblicking one or more awaiters.
	 * @param releaseCount Optional specified count to release. Defaults to 1.
	 * @returns The previous count (before release).
	 */
	public release(releaseCount: number = 1): number {
		if (this.disposed) throw new ObjectDisposedError(this);

		const previousCount = this.count;

		for (; releaseCount > 0; releaseCount--) {
			if (this.completions.length > 0) {
				// Something is waiting on the semaphore.
				// Remove and complete the wait without incrementing the count.
				const completion = this.completions.shift();
				completion!.resolve(true);
			} else {
				// Nothing is currently waiting on the semaphore. Increment the available count.
				this.count++;
			}
		}

		return previousCount;
	}

	/**
	 * Releases the semaphore, but does not throw an `ObjectDisposedError` if it is already disposed.
	 */
	public tryRelease() {
		try {
			this.release();
		} catch (e) {
			if (!(e instanceof ObjectDisposedError)) {
				throw e;
			}
		}
	}

	/**
	 * Waits until the semaphore is available. If the current count is greater than zero, this
	 * decreases the available count by one and returns immediately.
	 * @param cancellation Optional cancellation token that cancels the wait.
	 * @throws CancellationError if the cancellation token is cancelled before the wait completes.
	 */
	public wait(cancellation?: CancellationToken): Promise<void>;

	/**
	 * Waits until the semaphore is available or until a timeout expires. If the current count is
	 * greater than zero, this decreases the available count by one and returns immediately.
	 * @param millisecondsTimeout Optional timeout in milliseconds.
	 * @param cancellation Optional cancellation token that cancels the wait.
	 * @returns True if the wait succeeded, false if the timeout expired.
	 * @throws CancellationError if the cancellation token is cancelled before the wait completes
	 * or the timeout expires.
	 */
	public async wait(
		millisecondsTimeout?: number,
		cancellation?: CancellationToken,
	): Promise<boolean>;

	public async wait(
		timeoutOrCancellation?: number | CancellationToken,
		cancellation?: CancellationToken,
	): Promise<void | boolean> {
		const millisecondsTimeout =
			typeof timeoutOrCancellation === 'number' ? timeoutOrCancellation : undefined;
		if (typeof cancellation === 'undefined' && typeof timeoutOrCancellation === 'object') {
			cancellation = timeoutOrCancellation;
		}

		if (this.disposed) throw new ObjectDisposedError(this);
		if (cancellation?.isCancellationRequested) throw new CancellationError();

		if (this.count > 0) {
			// The semaphore is available now.
			this.count--;
			return true;
		} else if (millisecondsTimeout === 0) {
			// The semaphore is not available and the caller doesn't want to wait.
			return false;
		} else {
			const completion = new PromiseCompletionSource<boolean>();
			this.completions.push(completion);

			// Start with a promise that completes with `true` when the wait succeeds.
			const promises = [completion.promise];

			if (millisecondsTimeout) {
				// Race against a promise that completes with `false` when the timeout expires.
				promises.push(
					new Promise<boolean>((resolve) =>
						setTimeout(() => resolve(false), millisecondsTimeout),
					),
				);
			}

			if (cancellation) {
				// Race against a promise that throws when the cancellation token is cancelled.
				const cancellationCompletion = new PromiseCompletionSource<boolean>();
				cancellation.onCancellationRequested(() => {
					cancellationCompletion.reject(new CancellationError());
				});
				promises.push(cancellationCompletion.promise);
			}

			if (await Promise.race(promises)) {
				// The wait succeeded.
				return true;
			} else {
				// The wait timed out. Remove the (not-completed) completion from the array.
				const completionIndex = this.completions.indexOf(completion);
				if (completionIndex >= 0) this.completions.splice(completionIndex, 1);
				return false;
			}
		}
	}

	/**
	 * Disposes the semaphore and throws a diposed error to any awaiters.
	 */
	public dispose(): void {
		if (this.disposed) return;

		this.disposed = true;
		for (const completion of this.completions) {
			completion.reject(new ObjectDisposedError(this));
		}
		this.completions.splice(0, this.completions.length);
		this.count = 0;
	}
}
