//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * Generic iterable queue implementation using an auto-expanding circular array buffer.
 * Designed to be more efficient for high-volume use compared to a simpler JS queue using
 * `Array.shift()` (which would cause a lot of allocations).
 */
export class Queue<T> implements Iterable<T> {
	private array = new Array<T | undefined>();
	private first = 0;
	private count = 0;

	/**
	 * The version is incremented upon any changes to the queue, so that any iterators can detect the
	 * change and become invalid. `MAX_SAFE_INTEGER` is 2^53-1 so this isn't likely to ever overflow.
	 */
	private version = 0;

	/**
	 * Gets the current size of the queue.
	 */
	public get size(): number {
		return this.count;
	}

	/**
	 * Adds an item to the end of the queue.
	 */
	public enqueue(item: T): void {
		if (this.count === this.array.length) {
			const newArray = new Array<T | undefined>(Math.max(16, this.count * 2));
			for (let i = 0; i < this.count; i++) {
				newArray[i] = this.array[(this.first + i) % this.count];
			}
			this.array = newArray;
			this.first = 0;
		}

		this.array[(this.first + this.count) % this.array.length] = item;
		this.count++;
		this.version++;
	}

	/**
	 * Removes an item from the front of the queue.
	 * @returns The removed item, or `undefined` if the queue is empty.
	 */
	public dequeue(): T | undefined {
		if (this.count === 0) return undefined;

		const item = this.array[this.first];
		this.array[this.first] = undefined; // Allow the item to be GC'd.
		this.first = (this.first + 1) % this.array.length;
		this.count--;
		this.version++;

		return item;
	}

	/**
	 * Gets the item at the front of the queue without removing it.
	 * @returns The front item, or `undefined` if the queue is empty.
	 */
	public peek(): T | undefined {
		if (this.count === 0) return undefined;

		const item = this.array[this.first];
		return item;
	}

	/**
	 * Clears the queue.
	 */
	public clear(): void {
		this.first = 0;
		this.count = 0;
		this.array.fill(undefined); // Allow items to be GC'd.
		this.version++;
	}

	/**
	 * Creates an iterator over the items in the queue.
	 * (Any changes to the queue will invalidate the iterator.)
	 */
	public *[Symbol.iterator](): Iterator<T> {
		const iteratorVersion = this.version;
		for (let i = 0; i < this.count; i++) {
			const item = <T>this.array[(this.first + i) % this.array.length];
			yield item;
			if (this.version !== iteratorVersion) {
				throw new Error('Iterator is invalid due to changes in the collection.');
			}
		}
	}
}
