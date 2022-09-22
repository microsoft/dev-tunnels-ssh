//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Event, Emitter, CancellationToken } from 'vscode-jsonrpc';
import { Stream } from '@microsoft/dev-tunnels-ssh';

export class SlowStream implements Stream {
	public constructor(public readonly baseStream: Stream, public readonly addedLatency: number) {}

	private readonly closedEmitter = new Emitter<{ error?: Error }>();
	public readonly closed: Event<{ error?: Error }> = this.closedEmitter.event;

	public async read(count: number, cancellation?: CancellationToken): Promise<Buffer | null> {
		return await this.baseStream.read(count, cancellation);
	}

	public async write(data: Buffer, cancellation?: CancellationToken): Promise<void> {
		const copy = Buffer.from(data);

		function timeMs(): number {
			// Use Node.js high-resolution time API.
			const [s, ns] = process.hrtime();
			return s * 1000 + ns / 1000000;
		}
		const startTime = timeMs();

		new Promise<void>((resolve) => {
			// Spinning like this is horribly inefficient, but for benchmarking purposes it enables
			// a much more precise latency simulation compared to something like setTimeout(f, ms).
			const resolveAfterDelay = () => {
				if (timeMs() - startTime >= this.addedLatency) {
					resolve();
				} else {
					setImmediate(resolveAfterDelay);
				}
			};
			resolveAfterDelay();
		}).then(() => {
			return this.baseStream.write(copy, cancellation);
		});
	}

	public async close(error?: Error, cancellation?: CancellationToken): Promise<void> {
		await this.baseStream.close(error, cancellation);
	}

	public dispose(): void {
		this.baseStream.dispose();
	}

	public get isDisposed(): boolean {
		return this.baseStream.isDisposed;
	}
}
