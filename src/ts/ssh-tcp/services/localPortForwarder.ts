//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as net from 'net';
import {
	SshService,
	SshSession,
	CancellationToken,
	SshChannel,
	SshTraceEventIds,
	TraceLevel,
	PromiseCompletionSource,
	SshProtocolExtensionNames,
} from '@microsoft/dev-tunnels-ssh';
import { ChannelForwarder } from './channelForwarder';
import { PortForwardingService } from './portForwardingService';

/**
 * Listens on a local port and forwards incoming connections as SSH channels.
 */
export class LocalPortForwarder extends SshService {
	private tcpListener?: net.Server;
	private tcpListener2?: net.Server;
	private port: number;

	/* @internal */
	public constructor(
		private readonly pfs: PortForwardingService,
		session: SshSession,
		private readonly channelType: string,
		localIPAddress: string,
		localPort: number,
		remoteHost?: string,
		remotePort?: number,
	) {
		super(session);

		this.localIPAddress = localIPAddress;
		this.port = localPort;
		this.remoteHost = remoteHost;

		// The remote port defaults to the same as the local port, if the remote port
		// was unspecified and a specific (nonzero) local port was specified. Whether
		// or not a specific local port was specified, the local port may be changed
		// by the TCP listener factory. In that case the remote port does not change.
		this.remotePort = remotePort ?? (localPort !== 0 ? localPort : undefined);
	}

	/**
	 * IP address of the local network interface the forwarder is listening on.
	 */
	public readonly localIPAddress: string;

	/**
	 * Local port that the forwarder is listening on.
	 */
	public get localPort() {
		return this.port;
	}

	/**
	 * Remote forwarding target host, or `undefined` if this forwarding was requested
	 * by the remote side (without specifying the remote target).
	 */
	public readonly remoteHost?: string;

	/**
	 * Remote forwarding target port, or `undefined` if this forwarding was requested
	 * by the remote side (without specifying the remote target).
	 */
	public readonly remotePort?: number;

	/* @internal */
	public async startForwarding(cancellation?: CancellationToken): Promise<void> {
		let listenAddress = this.localIPAddress;
		try {
			this.tcpListener = await this.pfs.tcpListenerFactory.createTcpListener(
				listenAddress,
				this.port,
			);
			const serverAddress = this.tcpListener.address() as net.AddressInfo;
			if (!(serverAddress.port > 0)) {
				this.tcpListener.close();
				throw new Error('Could not get server port.');
			}

			this.port = serverAddress.port;

			// The SSH protocol specifies that "localhost" or "" (any) should be dual-mode.
			// So 2 TCP listener instances are required in those cases.
			if (this.localIPAddress === '127.0.0.1' || this.localIPAddress === '0.0.0.0') {
				// Call the factory again to create another listener, but this time with the
				// corresponding IPv6 local address, and not allowing a port change.
				listenAddress = '0.0.0.0' ? '::' : '::1';
				try {
					this.tcpListener2 = await this.pfs.tcpListenerFactory.createTcpListener(
						listenAddress,
						this.port,
					);
				} catch (e) {
					if (!(e instanceof Error) || (<any>e).code !== 'EADDRNOTAVAIL') {
						throw e;
					}

					// The OS may not support IPv6 or there may be no IPv6 network interfaces.
					this.trace(
						TraceLevel.Warning,
						SshTraceEventIds.portForwardServerListenFailed,
						`PortForwardingService failed to listen on {listenAddress}:{LocalPort}: {e.message}`,
						e,
					);

					// Do not rethrow, just skip IPv6 in this case.
				}
			}
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.portForwardServerListenFailed,
				`PortForwardingService failed to listen on ${listenAddress}:${this.port}: ${e.message}`,
				e,
			);
			throw e;
		}

		this.tcpListener.on('connection', this.acceptConnection.bind(this));
		this.tcpListener2?.on('connection', this.acceptConnection.bind(this));
		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.portForwardServerListening,
			`PortForwardingService listening on ${this.localIPAddress}:${this.port}.`,
		);
		if (this.tcpListener2) {
			this.trace(
				TraceLevel.Info,
				SshTraceEventIds.portForwardServerListening,
				`PortForwardingService also listening on ${listenAddress}:${this.port}.`,
			);
		}
	}

	private async acceptConnection(socket: net.Socket) {
		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.portForwardConnectionAccepted,
			'PortForwardingService accepted connection from: ' +
				`${socket.remoteAddress} on port ${this.port}`,
		);

		// TODO: Set socket options?

		let channel: SshChannel | null;
		try {
			channel = await this.pfs.openChannel(
				this.session,
				this.channelType,
				socket.remoteAddress ?? null,
				socket.remotePort ?? null,
				this.remoteHost ?? this.localIPAddress,
				this.remotePort ?? this.localPort,
			);
		} catch (e) {
			if (!(e instanceof Error)) throw e;

			// TODO: Destroy the socket in a way that causes a connection reset:
			// https://github.com/nodejs/node/issues/27428
			socket.destroy();

			// Don't re-throw. This is an async event handler so the caller isn't awaiting.
			// The error details have already been traced.
			return;
		}

		const forwarder = new ChannelForwarder(this.pfs, channel, socket);
		this.pfs.channelForwarders.push(forwarder);
	}

	public dispose() {
		// Note stopping the listener does not disconnect any already-accepted sockets.
		this.tcpListener?.close();
		this.tcpListener2?.close();
		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.portForwardServerListening,
			`PortForwardingService stopped listening on ${this.localIPAddress}:${this.port}.`,
		);

		super.dispose();
	}
}
