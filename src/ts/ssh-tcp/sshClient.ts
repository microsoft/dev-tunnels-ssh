//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as net from 'net';
import { Disposable } from 'vscode-jsonrpc';
import {
	SshClientSession,
	SshSessionConfiguration,
	CancellationError,
	NodeStream,
	Stream,
	CancellationToken,
	Trace,
} from '@microsoft/dev-tunnels-ssh';

/**
 * Enables opening an SSH session over a TCP connection.
 *
 * It's possible to create an `SshClientSession` over any `Stream` instance;
 * this class is merely a convenient helper that manages creating a session
 * over a Node.js TCP `Socket`.
 */
export class SshClient implements Disposable {
	private static readonly defaultServerPort = 22;

	private readonly sessions: SshClientSession[] = [];

	public constructor(private config: SshSessionConfiguration) {
		if (!config) throw new TypeError('SshSessionConfiguration is required.');
	}

	/**
	 * Gets or sets a function that handles trace messages associated with the client session.
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

	public async openSession(
		serverHost: string,
		serverPort?: number,
		cancellation?: CancellationToken,
	): Promise<SshClientSession> {
		if (!serverHost) throw new TypeError('Server host is reqiured.');

		const connectionResult = await this.openConnection(serverHost, serverPort, cancellation);
		const session = new SshClientSession(this.config);
		session.trace = this.trace;
		session.remoteIPAddress = connectionResult.ipAddress;
		await session.connect(connectionResult.stream, cancellation);
		this.sessions.push(session);
		return session;
	}

	protected async openConnection(
		serverHost: string,
		serverPort?: number,
		cancellation?: CancellationToken,
	): Promise<{ stream: Stream; ipAddress: string | undefined }> {
		let socket = new net.Socket();
		await new Promise((resolve, reject) => {
			socket.on('connect', resolve);
			socket.on('error', reject);

			if (cancellation) {
				if (cancellation.isCancellationRequested) {
					reject(new CancellationError());
					return;
				}

				cancellation.onCancellationRequested(reject);
			}

			socket.connect(serverPort || SshClient.defaultServerPort, serverHost);
		});
		return { stream: new NodeStream(socket), ipAddress: socket.remoteAddress };
	}

	public async reconnectSession(
		session: SshClientSession,
		serverHost: string,
		serverPort?: number,
		cancellation?: CancellationToken,
	): Promise<void> {
		const connectionResult = await this.openConnection(serverHost, serverPort, cancellation);
		await session.reconnect(connectionResult.stream, cancellation);
	}

	public dispose(): void {
		while (this.sessions.length > 0) {
			const session = this.sessions.shift()!;
			session.dispose();
		}
	}
}
