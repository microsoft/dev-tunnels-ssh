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
	SshStream,
} from '@microsoft/dev-tunnels-ssh';
import { StreamForwarder } from './streamForwarder';
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
			this.remotePort,
			this.trace,
			cancellation,
		);
	}

	/* @internal */
	public static async forwardChannel(
		pfs: PortForwardingService,
		request: SshChannelOpeningEventArgs,
		localHost: string,
		localPort: number,
		remotePort: number | undefined,
		trace: Trace,
		cancellation?: CancellationToken,
	): Promise<void> {
		const channel = request.channel;

		const forwardedStream = await pfs.forwardedPortConnecting(
			remotePort ?? localPort,
			true,
			new SshStream(channel),
			cancellation,
		);

		if (!forwardedStream) {
			// The event handler rejected the connection.
			request.failureReason = SshChannelOpenFailureReason.connectFailed;
			return;
		}

		const socket = net.createConnection({
			host: localHost,
			port: localPort,

			// This option enables connection attempts for multiple resolved IP addresses,
			// aka "Happy Eyeballs" as described in https://datatracker.ietf.org/doc/html/rfc8305.
			// Effectively this enables fast connections to either 127.0.0.1 or ::1 when 'localhost'
			// is specified as the hostname. Note this option is available starting with Node.js
			// v18.13 and is enabled by default starting with Node.js v20.0.
			autoSelectFamily: true,

			// Use the minimum supported connection attempt delay when connecting to 'localhost'.
			// See https://nodejs.org/api/net.html#socketconnectoptions-connectlistener
			autoSelectFamilyAttemptTimeout: localHost === 'localhost' ? 10 : 250,
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
				TraceLevel.Warning,
				SshTraceEventIds.portForwardConnectionFailed,
				`PortForwardingService connection ` +
					`to ${localHost}:${localPort} failed: ${e.message}`,
				e,
			);
			request.failureReason = SshChannelOpenFailureReason.connectFailed;
			request.failureDescription = e.message;
		} finally {
			cancellationRegistration?.dispose();
		}

		// TODO: Set socket options?

		const streamForwarder = new StreamForwarder(socket, forwardedStream, channel.session.trace);
		trace(
			TraceLevel.Info,
			SshTraceEventIds.portForwardConnectionOpened,
			`${channel.session} PortForwardingService forwarded channel ` +
				`#${channel.channelId} connection to ${localHost}:${localPort}.`,
		);
		pfs.streamForwarders.push(streamForwarder);
	}
}
