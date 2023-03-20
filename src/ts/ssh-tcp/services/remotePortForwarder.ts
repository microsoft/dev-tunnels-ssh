//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as net from 'net';
import {
	CancellationToken,
	SshChannelOpeningEventArgs,
	SshSession,
	PromiseCompletionSource,
	SshChannelOpenFailureReason,
	SshTraceEventIds,
	Trace,
	TraceLevel,
} from '@microsoft/dev-tunnels-ssh';
import { ChannelForwarder } from './channelForwarder';
import { PortForwardingService } from './portForwardingService';
import { RemotePortConnector } from './remotePortConnector';

/**
 * Receives SSH channels forwarded from a remote port and forwards them on to a local port.
 */
export class RemotePortForwarder extends RemotePortConnector {
	/* @internal */
	public constructor(
		private readonly pfs: PortForwardingService,
		session: SshSession,
		remoteIPAddress: string,
		remotePort: number,
		localHost: string,
		localPort: number,
	) {
		super(session, remoteIPAddress, remotePort);

		this.localHost = localHost;
		this.localPort = localPort;
	}

	/**
	 * Forwarding target host. Typically the loopback address ("127.0.0.1" or "::1") but may also be
	 * another hostname or IP address to be resolved locally.
	 */
	public readonly localHost: string;

	/**
	 * Forwarding target port.
	 */
	public readonly localPort: number;

	/* @internal */
	public async onPortChannelOpening(
		request: SshChannelOpeningEventArgs,
		cancellation?: CancellationToken,
	): Promise<void> {
		await RemotePortForwarder.forwardChannel(
			this.pfs,
			request,
			this.localHost,
			this.localPort,
			this.trace,
			cancellation,
		);
	}

	/* @internal */
	public static async forwardChannel(
		pfs: PortForwardingService,
		request: SshChannelOpeningEventArgs,
		host: string,
		port: number,
		trace: Trace,
		cancellation?: CancellationToken,
	): Promise<void> {
		const channel = request.channel;

		const socket = net.createConnection({
			host: host,
			port: port,
		});

		const connectCompletion = new PromiseCompletionSource<void>();
		const cancellationRegistration = cancellation
			? cancellation.onCancellationRequested(() => socket.destroy(new Error('Cancelled.')))
			: null;
		try {
			socket.once('connect', () => {
				connectCompletion.resolve();
			});
			socket.once('error', (e: Error) => {
				connectCompletion.reject(e);
			});
			await connectCompletion.promise;
		} catch (e) {
			if (!(e instanceof Error) || cancellation?.isCancellationRequested) {
				throw e;
			}

			trace(
				TraceLevel.Error,
				SshTraceEventIds.portForwardConnectionFailed,
				`${channel.session} PortForwardingService forwarded channel #${channel.channelId} ` +
					`connection to ${host}:${port} failed: ${e.message}`,
				e,
			);
			request.failureReason = SshChannelOpenFailureReason.connectFailed;
			request.failureDescription = e.message;
		} finally {
			cancellationRegistration?.dispose();
		}

		// TODO: Set socket options?

		const channelForwarder = new ChannelForwarder(pfs, channel, socket);
		trace(
			TraceLevel.Info,
			SshTraceEventIds.portForwardConnectionOpened,
			`${channel.session} PortForwardingService forwarded channel #${channel.channelId} connection to ${host}:${port}.`,
		);
		pfs.channelForwarders.push(channelForwarder);
	}
}
