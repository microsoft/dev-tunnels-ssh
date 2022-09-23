//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout, pending, params } from '@testdeck/mocha';

import { Queue } from '@microsoft/dev-tunnels-ssh';

@suite
export class QueueTests {
	@test
	@params({ enqueueCount: 0, dequeueCount: 0, iterationCount: 1 })
	@params({ enqueueCount: 1, dequeueCount: 1, iterationCount: 1 })
	@params({ enqueueCount: 10, dequeueCount: 5, iterationCount: 1 })
	@params({ enqueueCount: 30, dequeueCount: 5, iterationCount: 50 })
	@params({ enqueueCount: 1, dequeueCount: 1, iterationCount: 10000 })
	@params({ enqueueCount: 10, dequeueCount: 5, iterationCount: 10000 })
	@params.naming((p) => `enqueueDequeue(${p.enqueueCount},${p.dequeueCount},${p.iterationCount})`)
	public enqueueDequeue({
		enqueueCount,
		dequeueCount,
		iterationCount,
	}: {
		enqueueCount: number;
		dequeueCount: number;
		iterationCount: number;
	}) {
		const q = new Queue<number>();
		for (let i = 0; i < iterationCount; i++) {
			for (let e = 0; e < enqueueCount; e++) {
				const v = e % dequeueCount;
				q.enqueue(v);
			}

			for (let d = 0; d < dequeueCount; d++) {
				const v = q.dequeue();
				assert(typeof v === 'number');
				assert.strictEqual(v, d);
			}

			assert.strictEqual(q.size, (i + 1) * (enqueueCount - dequeueCount));
		}
	}

	@test
	@params({ enqueueCount: 0, dequeueCount: 0, iterationCount: 1 })
	@params({ enqueueCount: 1, dequeueCount: 1, iterationCount: 1 })
	@params({ enqueueCount: 10, dequeueCount: 5, iterationCount: 1 })
	@params({ enqueueCount: 30, dequeueCount: 5, iterationCount: 50 })
	@params({ enqueueCount: 1, dequeueCount: 1, iterationCount: 10000 })
	@params({ enqueueCount: 10, dequeueCount: 5, iterationCount: 10000 })
	@params.naming((p) => `enqueuePeek(${p.enqueueCount},${p.dequeueCount},${p.iterationCount})`)
	public enqueuePeek({
		enqueueCount,
		dequeueCount,
		iterationCount,
	}: {
		enqueueCount: number;
		dequeueCount: number;
		iterationCount: number;
	}) {
		const q = new Queue<number>();
		for (let i = 0; i < iterationCount; i++) {
			for (let e = 0; e < enqueueCount; e++) {
				const v = e % dequeueCount;
				q.enqueue(v);
			}

			for (let d = 0; d < dequeueCount; d++) {
				const v = q.dequeue();
				assert(typeof v === 'number');
				assert.strictEqual(v, d);
			}

			assert.strictEqual(q.peek(), dequeueCount < enqueueCount ? 0 : undefined);
		}
	}

	@test
	public emptyDequeue() {
		const q = new Queue<number>();
		assert.strictEqual(q.size, 0);
		let v = q.dequeue();
		assert.strictEqual(v, undefined);
		assert.strictEqual(q.size, 0);
	}

	@test
	public emptyPeek() {
		const q = new Queue<number>();
		assert.strictEqual(q.size, 0);
		let v = q.peek();
		assert.strictEqual(v, undefined);
		assert.strictEqual(q.size, 0);
	}

	@test
	public clear() {
		const q = new Queue<number>();
		for (let i = 0; i < 20; i++) {
			q.enqueue(i);
		}
		assert.strictEqual(q.size, 20);
		q.clear();
		assert.strictEqual(q.size, 0);
	}

	@test
	public iterate() {
		const q = new Queue<number>();
		for (let i = 0; i < 20; i++) {
			q.enqueue(i);
		}

		let i = 0;
		for (let v of q) {
			assert.strictEqual(v, i++);
		}
		assert.equal(i, 20);
	}

	@test
	@params({ invalidate: (q: Queue<number>) => q.enqueue(1), name: 'enqueue' })
	@params({ invalidate: (q: Queue<number>) => q.dequeue(), name: 'dequeue' })
	@params({ invalidate: (q: Queue<number>) => q.clear(), name: 'clear' })
	@params({ invalidate: (q: Queue<number>) => q.peek(), name: 'peek' })
	@params.naming((p) => `invalidateIterator(${p.name})`)
	public invalidateIterator({
		invalidate,
		name,
	}: {
		invalidate: (q: Queue<number>) => void;
		name: string;
	}) {
		const q = new Queue<number>();
		for (let i = 0; i < 4; i++) {
			q.enqueue(i);
		}

		let expectedLast = q.size / 2;
		let assertThrows = assert.throws;
		if (name === 'peek') {
			// Peek actually does NOT invalidate the iterator. So bypass the assert.throws().
			assertThrows = <any>((block: () => any) => block());
			expectedLast = q.size - 1;
		}

		let i = 0;
		assertThrows(() => {
			for (let v of q) {
				if (v === q.size / 2) {
					invalidate(q);
				}
				i = v;
			}
		}, /invalid/);

		assert.equal(i, expectedLast);
	}
}
