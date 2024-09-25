//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as net from 'net';
import { Event, Emitter, Disposable } from 'vscode-jsonrpc';
import {
	SshServerSession,
	SshServerCredentials,
	SshSessionConfiguration,
	SshProtocolExtensionNames,
	NodeStream,
	Stream,
	SshConnectionError,
	SshDisconnectReason,
	Trace,
	TraceLevel,
	SshTraceEventIds,
} from '@microsoft/dev-tunnels-ssh';
import { TcpListenerFactory, DefaultTcpListenerFactory } from './tcpListenerFactory';

/**
 * Enables accepting SSH sessions on a TCP socket.
 *
 * It's possible to create an `SshServerSession` over any `Stream` instance;
 * this class is merely a convenient helper that manages creating sessions
 * over Node.js TCP `Socket`s from incoming connections.
 */
export class SshServer implements Disposable {
	private tcpListener?: net.Server;
	private readonly sessions: SshServerSession[] = [];
	private readonly reconnectableSessions: SshServerSession[] | undefined;

	public constructor(private config: SshSessionConfiguration) {
		if (!config) throw new TypeError('SshSessionConfiguration is required.');

		if (config.protocolExtensions.includes(SshProtocolExtensionNames.sessionReconnect)) {
			this.reconnectableSessions = [];
		}
	}

	/**
	 * Gets or sets a function that handles trace messages associated with the server sessions.
	 *
	 * By default, no messages are traced. To enable tracing, set this property to a function
	 * that routes the message to console.log, a file, or anywhere else.
	 *
	 * @param level The level of message being traced: error, warning, info, or verbose.
	 * @param eventId An integer that identifies the type of event. Normally this is one of
	 * the values from `SshTraceEventIds`, but extensions may define additional event IDs.
	 * @param msg A description of the event (non-localized).
	 * @param err Optional `Error` object associated with the event, often included with
	 * warning or error events. While the `Error.message` property is typically included as
	 * (part of) the `msg` parameter, the error object may contain additional useful context
	 * such as the stack trace.
	 */
	public trace: Trace = (level, eventId, msg, err) => {};

	private readonly errorEmitter = new Emitter<Error>();
	public readonly onError: Event<Error> = this.errorEmitter.event;

	private readonly sessionOpenedEmitter = new Emitter<SshServerSession>();
	public readonly onSessionOpened: Event<SshServerSession> = this.sessionOpenedEmitter.event;

	public readonly credentials: SshServerCredentials = { publicKeys: [] };

	/**
	 * Gets or sets a factory for creating TCP listeners.
	 *
	 * Applications may override this factory to provide custom logic for selecting
	 * local port numbers to listen on for port-forwarding.
	 */
	public tcpListenerFactory: TcpListenerFactory = new DefaultTcpListenerFactory();

	public async acceptSessions(localPort: number, localAddress?: string): Promise<void> {
		if (!localAddress) {
			localAddress = '0.0.0.0';
		}

		const portPrefix = localAddress === '0.0.0.0' ? 'port ' : localAddress + ':';

		try {
			this.tcpListener = await this.tcpListenerFactory.createTcpListener(
				undefined, // remotePort
				localAddress,
				localPort,
				false,
			);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.serverListenFailed,
				`SshServer failed to listen on ${portPrefix}${localPort}: ${e.message}`,
				e,
			);
			throw e;
		}

		this.tcpListener.addListener('connection', this.acceptSession.bind(this));
		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.serverListening,
			`SshServer listening on ${portPrefix}${localPort}.`,
		);
	}

	protected async acceptConnection(socket: net.Socket): Promise<Stream> {
		socket.setNoDelay(true);
		return new NodeStream(socket);
	}

	private async acceptSession(socket: net.Socket): Promise<void> {
		this.trace(
			TraceLevel.Info,
			SshTraceEventIds.serverClientConnected,
			'SshServer client connected.',
		);

		const stream = await this.acceptConnection(socket);
		const session = new SshServerSession(this.config, this.reconnectableSessions);
		session.trace = this.trace;
		session.credentials = this.credentials;
		this.sessions.push(session);

		session.onClosed((e) => {
			const sessionIndex = this.sessions.indexOf(session);
			if (sessionIndex >= 0) {
				this.sessions.splice(sessionIndex, 1);
			}
		});
		this.sessionOpenedEmitter.fire(session);

		try {
			await session.connect(stream);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			if (e instanceof SshConnectionError) {
				await session.close(e.reason || SshDisconnectReason.connectionLost, e.message, e);
			} else {
				await session.close(SshDisconnectReason.protocolError, e.message, e);
			}
			this.errorEmitter.fire(e);
		}
	}

	public dispose(): void {
		this.tcpListener?.close();
	}
}
