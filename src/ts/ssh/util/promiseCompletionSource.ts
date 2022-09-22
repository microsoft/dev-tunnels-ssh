//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

export class PromiseCompletionSource<T> {
	public constructor() {
		this.promise = new Promise<T>((resolve, reject) => {
			this.resolve = resolve;
			this.reject = reject;
		});
	}

	public readonly promise: Promise<T>;

	public resolve(result: T) {}
	public reject(e: Error) {}
}
