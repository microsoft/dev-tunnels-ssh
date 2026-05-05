//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Trace, TraceLevel, SshTraceEventIds, SshStream } from '@microsoft/dev-tunnels-ssh';
import { Disposable } from 'vscode-jsonrpc';
import { Duplex } from 'stream';
import { Socket } from 'net';

export class StreamForwarder implements Disposable {
	private disposed: boolean = false;
	private readonly onDisposedCallback?: (forwarder: StreamForwarder) => void;

	public get isDisposed(): boolean {
		return this.disposed;
	}

	public constructor(
		public readonly localStream: Duplex,
		public readonly remoteStream: Duplex,
		public readonly trace: Trace,
		onDisposed?: (forwarder: StreamForwarder) => void,
	) {
		if (!localStream) throw new TypeError('Local stream is required.');
		if (!remoteStream) throw new TypeError('Remote stream is required.');

		this.onDisposedCallback = onDisposed;

		// Without these listeners, errors from either side of the forwarder
		// propagate up to the Node process as unhandled 'error' events and
		// crash the host. Node's pipe() does not propagate errors between
		// streams, so each side must be handled independently.
		localStream.on('error', (err) => this.onStreamError('local', err));
		remoteStream.on('error', (err) => this.onStreamError('remote', err));

		// pipe() forwards 'end' (so EOF on one side gracefully ends the other),
		// but does NOT forward 'error'. Error propagation is handled above
		// by disposing the forwarder, which tears down both sides.
		localStream.pipe(remoteStream);
		remoteStream.pipe(localStream);
	}

	private onStreamError(side: 'local' | 'remote', err: Error): void {
		this.trace(
			TraceLevel.Warning,
			SshTraceEventIds.unknownError,
			`Stream forwarder ${side} stream error: ${err.message}`,
		);
		this.dispose();
	}

	private close(abort: boolean, errorMessage?: string): void {
		try {
			if (abort && this.localStream instanceof Socket) {
				this.localStream.destroy();
			} else {
				this.localStream.end();
			}

			if (this.remoteStream instanceof SshStream) {
				this.remoteStream.channel.close('SIGABRT', errorMessage).catch((e) => {});
			} else {
				this.remoteStream.end();
			}

			this.trace(
				TraceLevel.Verbose,
				SshTraceEventIds.portForwardChannelClosed,
				`Stream forwarder ${abort ? 'aborted' : 'closed'} connection.`,
			);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			this.trace(
				TraceLevel.Warning,
				SshTraceEventIds.unknownError,
				`Stream forwarder unexpected error closing connection:  ${e.message}`,
			);
		}
	}

	public dispose(): void {
		if (!this.disposed) {
			this.disposed = true;
			this.close(true);
			if (this.onDisposedCallback) {
				try {
					this.onDisposedCallback(this);
				} catch (e) {
					const errorMessage = e instanceof Error ? e.message : String(e);
					this.trace(
						TraceLevel.Warning,
						SshTraceEventIds.unknownError,
						`Stream forwarder onDisposed callback threw: ${errorMessage}`,
					);
				}
			}
		}
	}
}
