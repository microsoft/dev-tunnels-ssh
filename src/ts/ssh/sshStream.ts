//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshChannel } from './sshChannel';
import { PromiseCompletionSource } from './util/promiseCompletionSource';
import { Duplex } from 'stream';

/**
 * Adapts an SshChannel as a Readable+Writable stream.
 */
export class SshStream extends Duplex {
	public constructor(channel: SshChannel) {
		let readPaused: PromiseCompletionSource<void> | null = null;
		super({
			async write(chunk: Buffer | string | any, encoding: BufferEncoding, cb) {
				let error: Error | undefined;
				try {
					let buffer: Buffer;
					if (typeof chunk === 'string') {
						buffer = Buffer.from(chunk, encoding);
					} else if (chunk instanceof Buffer || chunk instanceof Uint8Array) {
						buffer = chunk as Buffer;
					} else {
						throw new Error('Unsupported chunk type: ' + typeof chunk);
					}

					await channel.send(buffer);
				} catch (e) {
					if (!(e instanceof Error)) throw e;
					error = e;
				}

				if (cb) {
					cb(error);
				}
			},

			async writev(chunks: { chunk: Buffer; encoding: BufferEncoding }[], cb) {
				let error: Error | undefined;
				try {
					if (chunks.length === 1) {
						return this.write(chunks[0].chunk, chunks[0].encoding, cb);
					} else {
						function BufferReduce(
							accumulator: number,
							chunk: { chunk: Buffer | string | any; encoding?: BufferEncoding },
						): number {
							if (chunk.chunk instanceof Buffer || chunk.chunk instanceof Uint8Array) {
								return accumulator + chunk.chunk.length;
							} else {
								throw new Error('Unsupported chunk type: ' + typeof chunk.chunk);
							}
						}

						const totalLength = chunks.reduce(BufferReduce, 0);
						const singleBuffer = Buffer.alloc(totalLength);
						let singleBufferIndex = 0;
						for (let i = 0; i < chunks.length; i++) {
							chunks[i].chunk.copy(singleBuffer, singleBufferIndex);
							singleBufferIndex += chunks[i].chunk.length;
						}

						await channel.send(singleBuffer);
					}
				} catch (e) {
					if (!(e instanceof Error)) throw e;
					error = e;
				}

				if (cb) {
					cb(error);
				}
			},

			async final(cb?: (err?: Error | null) => void) {
				let error: Error | undefined;
				try {
					await channel.close();
				} catch (e) {
					if (!(e instanceof Error)) throw e;
					error = e;
				}

				if (cb) {
					cb(error);
				}
			},

			read() {
				if (readPaused) {
					readPaused.resolve();
					readPaused = null;
				}
			},
		});

		channel.onDataReceived(async (data) => {
			const buffer = Buffer.alloc(data.length);
			data.copy(buffer);
			const result = this.push(buffer);

			// Our flow control isn't great. Once we hit the highWaterMark,
			// we stop adjusting the SSH window until our own reader has caught up,
			// and then *all* the data received and buffered in the interim suddenly
			// gets 'adjusted' so that we tend to be somewhat choppy about adjusting the window.
			// Improving this would require that we know when the data we push gets passed to
			// the Duplex reader, and I don't think there's a way to get that notification.
			// So I suspect we'd have to dump Duplex and implement the stream ourselves.
			if (!result) {
				if (!readPaused) {
					readPaused = new PromiseCompletionSource<void>();
				}

				await readPaused.promise;
			}

			// Notify the channel that the data has been consumed and more data may be sent.
			channel.adjustWindow(buffer.length);
		});

		channel.onClosed(() => {
			this.push(null);
		});

		this.channel = channel;
	}

	public readonly channel: SshChannel;

	/**
	 * Destroys the stream and closes the underlying SSH channel.
	 */
	public destroy(error?: Error) {
		void this.channel.close().catch();
		super.destroy(error);
		return this;
	}

	public toString() {
		return `SshStream(Channel Type: ${this.channel.channelType}, Id: ${this.channel.channelId}, RemoteId: ${this.channel.remoteChannelId})`;
	}
}
