//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken, Emitter, Event } from 'vscode-jsonrpc';
import { SshChannelOpeningEventArgs, SshSession, SshStream } from '@microsoft/dev-tunnels-ssh';
import { RemotePortConnector } from './remotePortConnector';

/**
 * Receives SSH channels forwarded from a remote port and exposes them as streams.
 */
export class RemotePortStreamer extends RemotePortConnector {
	/* @internal */
	public constructor(session: SshSession, remoteIPAddress: string, remotePort: number) {
		super(session, remoteIPAddress, remotePort);
	}

	private readonly streamOpenedEmitter = new Emitter<SshStream>();

	/**
	 * Event raised when a new connection stream is forwarded from the remote port.
	 */
	public readonly onStreamOpened: Event<SshStream> = this.streamOpenedEmitter.event;

	/* @internal */
	public async onPortChannelOpening(
		request: SshChannelOpeningEventArgs,
		cancellation?: CancellationToken,
	): Promise<void> {
		const stream = new SshStream(request.channel);
		this.streamOpenedEmitter.fire(stream);
	}
}
