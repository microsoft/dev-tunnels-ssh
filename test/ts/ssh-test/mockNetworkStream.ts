//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//
import { CancellationToken, Event, Emitter } from 'vscode-jsonrpc';
import { Stream, PromiseCompletionSource, ObjectDisposedError } from '@microsoft/dev-tunnels-ssh';

export class MockNetworkStream implements Stream {
	private dropSendBytesCount: number | undefined;
	private disconnectError: Error | undefined;
	private readonly disposedCompletionSource = new PromiseCompletionSource<Buffer | null>();

	public constructor(public readonly underlyingStream: Stream) {}

	public disposeUnderlyingStream: boolean = true;

	public isDisposed: boolean = false;

	private readonly closedEmitter = new Emitter<{ error?: Error }>();
	public readonly closed = this.closedEmitter.event;

	public async read(count: number, cancellation?: CancellationToken): Promise<Buffer | null> {
		const disposedPromise = this.disposedCompletionSource.promise;
		if (this.isDisposed) await disposedPromise;

		const readPromise = this.underlyingStream.read(count, cancellation);
		return await Promise.race([readPromise, disposedPromise]);
	}

	public async write(data: Buffer, cancellation?: CancellationToken): Promise<void> {
		const disposedPromise = this.disposedCompletionSource.promise;
		if (this.isDisposed) await disposedPromise;

		if (typeof this.dropSendBytesCount === 'number') {
			if (data.length <= this.dropSendBytesCount) {
				// Drop these bytes by returning without writing to the underlying stream.
				this.dropSendBytesCount -= data.length;

				if (this.dropSendBytesCount === 0) {
					// This write() call does not throw an error, but the next one will.
					this.disposedCompletionSource.reject(this.disconnectError!);
					this.dispose();
				}

				return;
			} else {
				this.disposedCompletionSource.reject(this.disconnectError!);
				this.dispose();
				await disposedPromise;
			}
		}

		const writePromise = this.underlyingStream.write(data, cancellation);
		await Promise.race([writePromise, disposedPromise]);
	}

	public async close(error?: Error, cancellation?: CancellationToken): Promise<void> {
		await this.underlyingStream.close(error, cancellation);
	}

	public mockDisconnect(disconnectError: Error, dropSendBytesCount?: number) {
		if (typeof dropSendBytesCount !== 'number') {
			this.disposedCompletionSource.reject(disconnectError);
			this.dispose();
		} else {
			this.disconnectError = disconnectError;
			this.dropSendBytesCount = dropSendBytesCount;
		}
	}

	public dispose(): void {
		this.isDisposed = true;

		this.disposedCompletionSource.reject(new ObjectDisposedError(this));

		if (this.disposeUnderlyingStream) {
			this.underlyingStream.dispose();
		}
	}
}
