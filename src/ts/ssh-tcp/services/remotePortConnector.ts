//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import {
	CancellationToken,
	SshService,
	SshSession,
	SessionRequestFailureMessage,
	SshChannelOpeningEventArgs,
} from '@microsoft/dev-tunnels-ssh';
import { PortForwardRequestMessage } from '../messages/portForwardRequestMessage';
import { PortForwardSuccessMessage } from '../messages/portForwardSuccessMessage';
import { PortForwardingService } from './portForwardingService';

/**
 * Base class for services that receive SSH channels forwarded from a remote port.
 */
export abstract class RemotePortConnector extends SshService {
	private port: number;
	private forwarding: boolean = false;

	/* @internal */
	protected constructor(session: SshSession, remoteIPAddress: string, remotePort: number) {
		super(session);

		this.remoteIPAddress = remoteIPAddress;
		this.port = remotePort;
	}

	/**
	 * IP address of the network interface bound by the remote listener.
	 */
	public readonly remoteIPAddress: string;

	/**
	 * Port that the remote server is listening on. If the request specified port 0, this
	 * property returns the actual available port that was chosen by the server.
	 */
	public get remotePort() {
		return this.port;
	}

	/* @internal */
	public abstract onPortChannelOpening(
		request: SshChannelOpeningEventArgs,
		cancellation?: CancellationToken,
	): Promise<void>;

	/* @internal */
	public async request(
		request: PortForwardRequestMessage,
		cancellation?: CancellationToken,
	): Promise<boolean> {
		if (this.forwarding) {
			throw new Error('Already forwarding.');
		}

		request.addressToBind = this.remoteIPAddress;
		request.port = this.remotePort;
		request.wantReply = true;

		const response = await this.session.requestResponse(
			request,
			PortForwardSuccessMessage,
			SessionRequestFailureMessage,
			cancellation,
		);

		let result = false;
		if (response instanceof PortForwardSuccessMessage) {
			if (response.port !== 0) {
				this.port = response.port;
			}

			result = true;
		}

		this.forwarding = result;
		return result;
	}

	public dispose() {
		if (this.forwarding) {
			this.forwarding = false;

			const request = new PortForwardRequestMessage();
			request.requestType = PortForwardingService.cancelPortForwardRequestType;
			request.addressToBind = this.remoteIPAddress;
			request.port = this.remotePort;
			request.wantReply = false;

			try {
				this.session.request(request).catch((e) => {
					// Ignore async cancel failure.
					// Error details have already been trace.
				});
			} catch (e) {}
		}

		super.dispose();
	}
}
