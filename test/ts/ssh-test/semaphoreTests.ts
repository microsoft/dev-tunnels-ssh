//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout, pending, params } from '@testdeck/mocha';

import {
	Semaphore,
	CancellationTokenSource,
	CancellationError,
	ObjectDisposedError,
} from '@microsoft/dev-tunnels-ssh';

@suite
export class SemaphoreTests {
	@test
	public async initialCount() {
		const s = new Semaphore(2);
		assert.equal(s.currentCount, 2);
		await s.wait();
		assert.equal(s.currentCount, 1);
		await s.wait();
		assert.equal(s.currentCount, 0);
	}

	@test
	@params({ releaseCount: 0, waitCount: 0, iterationCount: 1 })
	@params({ releaseCount: 1, waitCount: 1, iterationCount: 1 })
	@params({ releaseCount: 10, waitCount: 5, iterationCount: 1 })
	@params({ releaseCount: 30, waitCount: 5, iterationCount: 50 })
	@params({ releaseCount: 1, waitCount: 1, iterationCount: 10000 })
	@params({ releaseCount: 10, waitCount: 5, iterationCount: 10000 })
	@params.naming((p) => `releaseAndWait(${p.releaseCount},${p.waitCount},${p.iterationCount})`)
	public async releaseAndWait({
		releaseCount,
		waitCount,
		iterationCount,
	}: {
		releaseCount: number;
		waitCount: number;
		iterationCount: number;
	}) {
		const s = new Semaphore();
		for (let i = 0; i < iterationCount; i++) {
			const startCount = i * (releaseCount - waitCount);
			assert.equal(s.currentCount, startCount);
			assert.equal(s.release(releaseCount), startCount);
			assert.equal(s.currentCount, startCount + releaseCount);

			for (let w = 0; w < waitCount; w++) {
				await s.wait();
			}
			assert.equal(s.currentCount, startCount + releaseCount - waitCount);
		}
	}

	@test
	public async cancelWait() {
		const s = new Semaphore();
		const cancellationSource = new CancellationTokenSource();

		let resolved = false;
		let rejection: Error | undefined;
		const waitPromise = s
			.wait(cancellationSource.token)
			.then(() => (resolved = true))
			.catch((e) => (rejection = e));
		await new Promise((c) => setTimeout(c, 5));
		assert(!resolved);
		assert(!rejection);

		cancellationSource.cancel();
		await waitPromise;
		assert(!resolved);
		assert(<any>rejection instanceof CancellationError);

		assert.equal(s.currentCount, 0);
	}

	@test
	public async waitWithTimeout() {
		const s = new Semaphore();

		const startTime = Date.now();
		const result = await s.wait(200);
		const endTime = Date.now();

		// Allow for some error - the wait uses setTimeout() which is not very accurate.
		assert(endTime - startTime > 150);
		assert(!result);

		assert.equal(s.currentCount, 0);

		// After release this shouldn't wait -- the test will timeout if it actually does.
		s.release();
		const result2 = await s.wait(1000000);
		assert(result2);
	}

	@test
	public async dispose() {
		const s = new Semaphore();
		s.dispose();
		assert.rejects(async () => {
			await s.wait();
		}, ObjectDisposedError);
	}

	@test
	public async disposeWhileAvailable() {
		const s = new Semaphore();
		s.release();
		s.dispose();
		assert.rejects(async () => {
			await s.wait();
		}, ObjectDisposedError);
	}

	@test
	public async disposeWhileWaiting() {
		const s = new Semaphore();
		const waitPromise = s.wait();
		await new Promise((c) => setTimeout(c, 5));
		s.dispose();
		assert.rejects(async () => {
			await waitPromise;
		}, ObjectDisposedError);
	}
}
