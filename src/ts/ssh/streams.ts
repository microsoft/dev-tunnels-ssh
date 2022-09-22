//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { Socket } from 'net';
import { Readable, Writable, Duplex } from 'stream';
import { Emitter, Event, Disposable } from 'vscode-jsonrpc';
import { CancellationError, CancellationToken } from './util/cancellation';
import { ObjectDisposedError } from './errors';

/**
 * Stream interface used by the SSH library. Implementations of this interface
 * allow the SSH protocol to communicate over different transport mechanisms.
 */
export interface Stream extends Disposable {
	/**
	 * Reads bytes from the stream.
	 * @param count Maximum number of bytes to read.
	 * @param cancellation Optional cancellation token.
	 * @returns Buffer containing the bytes read, or null if the end of the
	 * (cleanly closed) stream was reached. The buffer length is less than or
	 * equal to the requested count.
	 * @throws If there was an error reading from the stream.
	 */
	read(count: number, cancellation?: CancellationToken): Promise<Buffer | null>;

	/**
	 * Writes bytes to the stream.
	 * @param data Buffer containing bytes to write.
	 * @param cancellation Optional cancellation token.
	 * @throws If there was an error writing to the stream.
	 */
	write(data: Buffer, cancellation?: CancellationToken): Promise<void>;

	/**
	 * Closes the stream.
	 * @param error Error that caused the stream closure, if any.
	 */
	close(error?: Error, cancellation?: CancellationToken): Promise<void>;

	/**
	 * Event raised when the stream was closed.
	 * @param error Error that caused the stream closure, if any.
	 */
	readonly closed: Event<{ error?: Error }>;

	/**
	 * Gets a value indicating whether the stream is disposed.
	 */
	readonly isDisposed: boolean;
}

interface ReadOperation {
	readonly count: number;
	readonly resolve: (data: Buffer | null) => void;
	readonly reject: (e: Error) => void;
	readonly cancellation?: CancellationToken;
}

function handleCancellation(reject: (reason?: any) => void, cancellation?: CancellationToken) {
	if (cancellation) {
		if (cancellation.isCancellationRequested) {
			reject(new CancellationError());
		} else {
			cancellation.onCancellationRequested(() => {
				reject(new CancellationError());
			});
		}
	}
}

/**
 * Base class for stream adapters.
 */
export abstract class BaseStream implements Stream {
	private readonly incomingData: Buffer[] = [];
	private readonly pendingReads: ReadOperation[] = [];
	private error: Error | null = null;
	protected disposed = false;

	protected onData(data: Buffer): void {
		while (this.pendingReads.length > 0) {
			const read = this.pendingReads.shift()!;

			if (read.count >= data.length) {
				// This read operation consumes all of the incoming data.
				read.resolve(data);
				return;
			} else {
				// This read operation consumes part of the incoming data.
				const readData = data.slice(0, read.count);
				data = data.slice(read.count);
				read.resolve(readData);
			}
		}

		this.incomingData.push(data);
	}

	protected onEnd(): void {
		while (this.pendingReads.length > 0) {
			const read = this.pendingReads.shift()!;
			read.resolve(null);
		}

		this.incomingData.push(Buffer.alloc(0));
	}

	protected onError(error: Error): void {
		if (!this.error) {
			this.error = error;
		}

		while (this.pendingReads.length > 0) {
			const read = this.pendingReads.shift()!;
			read.reject(error);
		}
	}

	public async read(count: number, cancellation?: CancellationToken): Promise<Buffer | null> {
		if (this.disposed) throw new ObjectDisposedError(this);

		if (this.incomingData.length > 0) {
			// Consume data that has already arrived.
			let data = this.incomingData[0];
			if (data.length === 0) {
				// Reached the end of the stream.
				return null;
			} else if (count >= data.length) {
				// Consuming the whole chunk.
				this.incomingData.shift();
			} else {
				// Consuming part of the chunk.
				this.incomingData[0] = data.slice(count);
				data = data.slice(0, count);
			}
			return data;
		} else if (this.error) {
			throw this.error;
		} else {
			// Wait for more data to arrive.
			return await new Promise<Buffer | null>((resolve, reject) => {
				if (cancellation) {
					if (cancellation.isCancellationRequested) {
						reject(new CancellationError());
						return;
					}

					cancellation.onCancellationRequested(() => {
						// Discard any pending reads that use this cancellation token.
						for (let i = 0; i < this.pendingReads.length; i++) {
							if (Object.is(cancellation, this.pendingReads[i].cancellation)) {
								const read = this.pendingReads.splice(i--, 1)[0];
								read.reject(new CancellationError());
							}
						}
					});
				}

				this.pendingReads.push({ count, resolve, reject, cancellation });
			});
		}
	}

	public abstract write(data: Buffer, cancellation?: CancellationToken): Promise<void>;

	public abstract close(error?: Error, cancellation?: CancellationToken): Promise<void>;

	protected readonly closedEmitter = new Emitter<{ error?: Error }>();
	public readonly closed: Event<{ error?: Error }> = this.closedEmitter.event;

	public dispose(): void {
		if (!this.disposed) {
			this.disposed = true;
			const error = new ObjectDisposedError(this);
			this.onError(error);
			this.fireOnClose(error);
		}
	}

	protected fireOnClose(error?: Error) {
		this.closedEmitter.fire({ error });
	}

	public get isDisposed() {
		return this.disposed;
	}
}

/**
 * Stream adapter for a Node.js Socket, Duplex stream, or Readable/Writable stream pair.
 */
export class NodeStream extends BaseStream {
	private readonly readStream: Readable;
	private readonly writeStream: Writable;

	public constructor(duplexStream: Duplex | Socket);
	public constructor(readStream: Readable, writeStream: Writable);
	public constructor(duplexOrReadStream: Duplex | Readable, writeStream?: Writable) {
		super();
		if (!duplexOrReadStream)
			throw new TypeError('Duplex or Readable/Writable stream are required.');

		this.readStream = duplexOrReadStream;
		this.writeStream = writeStream || <Duplex>duplexOrReadStream;

		this.readStream.on('data', this.onData.bind(this));
		this.readStream.on('end', this.onEnd.bind(this));
		this.readStream.on('error', this.onError.bind(this));
		this.readStream.on('close', () => {
			this.onEnd();
			this.fireOnClose();
		});
	}

	public async write(data: Buffer, cancellation?: CancellationToken): Promise<void> {
		if (!data) throw new TypeError('Data is required.');
		if (this.disposed) throw new ObjectDisposedError(this);

		return new Promise((resolve, reject) => {
			handleCancellation(reject, cancellation);
			this.writeStream.write(data, (err) => {
				if (!err) {
					resolve();
				} else {
					reject(err);
				}
			});
		});
	}

	public async close(error?: Error, cancellation?: CancellationToken): Promise<void> {
		if (this.disposed) throw new ObjectDisposedError(this);

		await new Promise((resolve, reject) => {
			handleCancellation(reject, cancellation);
			this.writeStream.end(resolve);
		});
		this.disposed = true;
		this.onError(error || new ObjectDisposedError(this));
		this.closedEmitter.fire({ error });
	}

	public dispose(): void {
		if (!this.disposed) {
			const error = new ObjectDisposedError(this);
			this.readStream.destroy(error);
			this.writeStream.destroy(error);
		}

		super.dispose();
	}
}

// The adapter only requires a few basic websocket members.
interface WebSocketLike {
	onmessage: ((e: { data: ArrayBuffer }) => void) | null;
	onclose: ((e: { code: number; reason: string; wasClean: boolean }) => void) | null;
	send(data: ArrayBuffer): void;
	close(code?: number, reason?: string): void;
}

/**
 * WebSocket.readyState values enum
 *
 * https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState
 */
const enum WebSocketReadyState {
	Connecting = 0,
	Open = 1,
	Closing = 2,
	Closed = 3,
}

/**
 * Stream adapter for a browser websocket.
 */
export class WebSocketStream extends BaseStream {
	public constructor(private readonly websocket: WebSocket | WebSocketLike) {
		super();
		if (!websocket) throw new TypeError('WebSocket is required.');

		if (
			typeof (websocket as any).binaryType === 'string' &&
			(websocket as any).binaryType !== 'arraybuffer'
		) {
			throw new Error('WebSocket must use arraybuffer binary type.');
		}

		websocket.onmessage = (e: { data: ArrayBuffer }) => {
			this.onData(Buffer.from(e.data));
		};
		websocket.onclose = (e: { code: number; reason: string; wasClean: boolean }) => {
			if (e.wasClean) {
				this.onEnd();
			} else {
				const error = new Error(e.reason);
				(<any>error).code = e.code;
				this.onError(error);
			}
		};
	}

	public async write(data: Buffer, cancellation?: CancellationToken): Promise<void> {
		if (!data) throw new TypeError('Data is required.');
		if (this.disposed) throw new ObjectDisposedError(this);

		if ('readyState' in this.websocket) {
			if (
				this.websocket.readyState === WebSocketReadyState.Closing ||
				this.websocket.readyState === WebSocketReadyState.Closed
			) {
				throw new DOMException(
					'WebSocket is already in CLOSING or CLOSED state.',
					'InvalidStateError',
				);
			}
		}

		this.websocket.send(data);
	}

	public async close(error?: Error, cancellation?: CancellationToken): Promise<void> {
		if (this.disposed) throw new ObjectDisposedError(this);

		if (!error) {
			this.websocket.close();
		} else {
			const code = typeof (<any>error).code === 'number' ? (<any>error).code : undefined;
			this.websocket.close(code, error.message);
		}
		this.disposed = true;
		this.closedEmitter.fire({ error });
		this.onError(error || new Error('Stream closed.'));
	}

	public dispose(): void {
		if (!this.disposed) {
			this.websocket.close();
		}

		super.dispose();
	}
}
