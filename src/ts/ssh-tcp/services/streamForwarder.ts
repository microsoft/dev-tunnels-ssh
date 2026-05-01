//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Trace, TraceLevel, SshTraceEventIds, SshStream } from '@microsoft/dev-tunnels-ssh';
import { Disposable } from 'vscode-jsonrpc';
import { Duplex } from 'stream';
import { Socket } from 'net';

export class StreamForwarder implements Disposable {
	private disposed: boolean = false;

	/* @internal */
	public constructor(
		public readonly localStream: Duplex,
		public readonly remoteStream: Duplex,
		public readonly trace: Trace,
	) {
		if (!localStream) throw new TypeError('Local stream is required.');
		if (!remoteStream) throw new TypeError('Remote stream is required.');

		// Without these listeners, errors from either side of the forwarder
		// propagate up to the Node process as unhandled 'error' events and
		// crash the host. Node's pipe() does not propagate errors between
		// streams, so each side must be handled independently.
		localStream.on('error', (err) => this.onStreamError('local', err));
		remoteStream.on('error', (err) => this.onStreamError('remote', err));

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
		}
	}
}
