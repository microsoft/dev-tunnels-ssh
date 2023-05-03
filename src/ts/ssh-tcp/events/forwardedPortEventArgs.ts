//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken, SshChannel, SshStream } from '@microsoft/dev-tunnels-ssh';
import { Duplex } from 'stream';
import { ForwardedPort } from './forwardedPort';

export class ForwardedPortEventArgs {
	public constructor(public readonly port: ForwardedPort) {}

	public toString() {
		return this.port.toString();
	}
}

export class ForwardedPortChannelEventArgs extends ForwardedPortEventArgs {
	public constructor(public port: ForwardedPort, public readonly channel: SshChannel) {
		super(port);
	}

	public toString() {
		return `${this.port} ${this.channel}`;
	}
}

/**
 * Event raised when an incoming or outgoing connection to a forwarded port is
 * about to be established.
 */
export class ForwardedPortConnectingEventArgs {
	public constructor(
		/**
		 * The remote forwarded port number. This may be different from the local port number,
		 * if the local TCP listener chose a different port.
		 */
		public readonly port: number,

		/**
		 * True if this connection is incoming (remote connection to a local port);
		 * false if it is outgoing (local connection to a remote port).
		 */
		public readonly isIncoming: boolean,

		/**
		 * A stream for the forwarded connection.
		 */
		public readonly stream: SshStream,

		/**
		 * A cancellation token that is cancelled when the session is closed.
		 */
		public readonly cancellation?: CancellationToken,
	) {}

	/**
	 * Gets or sets an optional promise that resolves to a transformed stream.
	 * An event-handler may apply a transformation to the stream before the stream is connected
	 * to the local port or returned to the application. If the promise result is null, the
	 * connection is rejected.
	 */
	public transformPromise?: Promise<Duplex | null>;

	public toString() {
		return `${this.port} isIncoming=${this.isIncoming}`;
	}
}
