//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as net from 'net';
import {
	SshChannel,
	SshChannelClosedEventArgs,
	Trace,
	TraceLevel,
	SshTraceEventIds,
} from '@microsoft/dev-tunnels-ssh';
import { CancellationTokenSource, Disposable } from 'vscode-jsonrpc';
import { PortForwardingService } from './portForwardingService';

export class ChannelForwarder implements Disposable {
	private readonly disposeCancellationSource = new CancellationTokenSource();

	/* @internal */
	public constructor(
		private readonly pfs: PortForwardingService,
		public readonly channel: SshChannel,
		public readonly socket: net.Socket,
	) {
		socket.on('data', this.onSocketDataReceived.bind(this));
		socket.on('error', this.onSocketError.bind(this));
		socket.on('close', this.onSocketClosed.bind(this));
		channel.onDataReceived(this.onChannelDataReceived.bind(this));
		channel.onClosed(this.onChannelClosed.bind(this));
	}

	private get trace(): Trace {
		return this.channel.session.trace;
	}

	private onSocketDataReceived(data: Buffer): void {
		this.socket.pause(); // Block further data events while sending.
		this.channel
			.send(data, this.disposeCancellationSource.token)
			.then(this.socket.resume.bind(this.socket), (e: Error) => {
				this.trace(
					TraceLevel.Warning,
					SshTraceEventIds.portForwardConnectionFailed,
					`Forwarder error sending channel data: ${e.message}`,
					e,
				);
			});
	}

	private onSocketClosed(hadError: boolean): void {
		const closePromise = hadError
			? this.channel.close('SIGABRT', 'Socket closed with error.')
			: this.channel.close();
		closePromise.catch((e: Error) => {
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.portForwardConnectionFailed,
				`Forwarder channel close failed with error: ${e.message}`,
				e,
			);
		});
	}

	private onSocketError(error: Error): void {
		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.portForwardChannelClosed,
			`Forwarder socket closed with error: ${error.message}`,
		);
		this.channel.close('SIGABRT', error.message).catch((e: Error) => {
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.portForwardConnectionFailed,
				`Forwarder channel close failed with error: ${e.message}`,
				e,
			);
		});
	}

	private onChannelDataReceived(data: Buffer): void {
		this.socket.write(data, (error?: Error) => {
			if (error) {
				this.trace(
					TraceLevel.Error,
					SshTraceEventIds.portForwardConnectionFailed,
					`Forwarder failed to write to socket: ${error.message}`,
					error,
				);
			} else {
				this.channel.adjustWindow(data.length);
			}
		});
	}

	private onChannelClosed(e: SshChannelClosedEventArgs): void {
		if (!e.errorMessage) {
			this.trace(
				TraceLevel.Info,
				SshTraceEventIds.portForwardConnectionClosed,
				`Forwarder channel ${this.channel.channelId} closed.`,
			);
			this.socket.end();
		} else {
			this.trace(
				TraceLevel.Info,
				SshTraceEventIds.portForwardConnectionClosed,
				`Forwarder channel ${this.channel.channelId} closed with error: ${e.errorMessage}`,
			);
			// TODO: Destroy the socket in a way that causes a connection reset:
			// https://github.com/nodejs/node/issues/27428
			this.socket.destroy();
		}

		const index = this.pfs.channelForwarders.indexOf(this);
		if (index >= 0) {
			this.pfs.channelForwarders.splice(index, 1);
		}

		this.dispose();
	}

	public dispose(): void {
		this.disposeCancellationSource.dispose();
		this.socket.destroy();
	}
}
