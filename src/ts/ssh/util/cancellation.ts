//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken, CancellationTokenSource } from 'vscode-jsonrpc';
export { CancellationToken, CancellationTokenSource };

/**
 * Error thrown when an operation is cancelled via a CancellationToken.
 */
export class CancellationError extends Error {
	constructor(message?: string) {
		super(message || 'Operation cancelled.');
	}
}

export function withCancellation<T>(
	promise: Promise<T>,
	cancellation?: CancellationToken,
): Promise<T> {
	if (!cancellation) {
		return promise;
	}

	return Promise.race([
		promise,
		new Promise<T>((resolve, reject) => {
			if (cancellation.isCancellationRequested) {
				reject(new CancellationError());
			} else {
				cancellation.onCancellationRequested(() => {
					reject(new CancellationError());
				});
			}
		}),
	]);
}
