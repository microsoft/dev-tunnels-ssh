//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken, Disposable, Emitter } from 'vscode-jsonrpc';
import { Stream } from './streams';
import { SshChannel } from './sshChannel';
import { SshStream } from './sshStream';
import { SshSession } from './sshSession';
import { SshSessionConfiguration } from './sshSessionConfiguration';
import { SshDisconnectReason } from './messages/transportMessages';
import { SshSessionClosedEventArgs } from './events/sshSessionClosedEventArgs';
import { Trace, TraceLevel, SshTraceEventIds } from './trace';
import { ChannelOpenMessage } from './messages/connectionMessages';
import { SshClientCredentials, SshServerCredentials } from './sshCredentials';
import { SshClientSession } from './sshClientSession';
import { SshServerSession } from './sshServerSession';
import { SshAuthenticatingEventArgs } from './events/sshAuthenticatingEventArgs';
import { SshConnectionError } from './errors';
import { Duplex } from 'stream';

/**
 * Establishes an end-to-end encrypted two-way authenticated data stream over an underlying
 * transport stream, using the SSH protocol but providing simplified interface that is limited to
 * a single duplex stream (channel).
 *
 * This class is a complement to `MultiChannelStream`, which provides only the channel-multiplexing
 * functions of SSH.
 *
 * To establish a secure connection, the two sides first establish an insecure transport stream
 * over a pipe, socket, or anything else. Then they encrypt and authenticate the connection
 * before beginning to send and receive data.
 */
export class SecureStream extends Duplex implements Disposable {
	private readonly session: SshSession;
	private readonly clientCredentials: SshClientCredentials | null = null;
	private readonly serverCredentials: SshServerCredentials | null = null;
	private stream?: SshStream;
	private disposed: boolean = false;
	private disposables: Disposable[] = [];

	/**
	 * Creates a new multi-channel stream over an underlying transport stream.
	 * @param transportStream Stream that is used to multiplex all the channels.
	 */
	public constructor(
		private readonly transportStream: Stream,
		credentials: SshClientCredentials | SshServerCredentials,
	) {
		super({
			write(
				this: SecureStream,
				chunk: Buffer | string | any,
				encoding: BufferEncoding,
				cb: (error?: Error | null) => void,
			) {
				if (!this.stream) throw new Error('Stream is not connected.');
				return this.stream._write(chunk, encoding, cb);
			},
			writev(
				this: SecureStream,
				chunks: { chunk: Buffer; encoding: BufferEncoding }[],
				cb: (error?: Error | null) => void,
			) {
				if (!this.stream) throw new Error('Stream is not connected.');
				return this.stream._writev!(chunks, cb);
			},
			final(this: SecureStream, cb: (err?: Error | null) => void) {
				if (!this.stream) throw new Error('Stream is not connected.');
				return this.stream._final(cb);
			},
			read(this: SecureStream, size: number) {
				if (!this.stream) throw new Error('Stream is not connected.');
				return this.stream?._read(size);
			},
		});

		if (!transportStream) throw new TypeError('A transport stream is required.');
		if (!credentials) throw new TypeError('Client or server credentials are required.');

		const sessionConfig = new SshSessionConfiguration(true);

		if ('username' in credentials) {
			this.clientCredentials = credentials;
			this.session = new SshClientSession(sessionConfig);
		} else if (credentials.publicKeys) {
			this.serverCredentials = <SshServerCredentials>credentials;
			this.session = new SshServerSession(sessionConfig);
		} else {
			throw new TypeError('Client or server credentials are required.');
		}

		this.session.onClosed(this.onSessionClosed, this, this.disposables);
	}

	public get trace(): Trace {
		return this.session.trace;
	}

	public set trace(trace: Trace) {
		this.session.trace = trace;
	}

	/**
	 * Gets or sets the maximum window size for channels within the multi-channel stream.
	 * @see `SshChannel.maxWindowSize`
	 */
	public channelMaxWindowSize: number = SshChannel.defaultMaxWindowSize;

	public get isClosed(): boolean {
		return this.disposed || this.session.isClosed;
	}

	private readonly closedEmitter = new Emitter<SshSessionClosedEventArgs>();
	public readonly onClosed = this.closedEmitter.event;

	public onAuthenticating(
		listener: (e: SshAuthenticatingEventArgs) => any,
		thisArgs?: any,
		disposables?: Disposable[],
	) {
		return this.session.onAuthenticating(listener, thisArgs, disposables);
	}

	/**
	 * Initiates the SSH session over the transport stream by exchanging initial messages with the
	 * remote peer. Waits for the protocol version exchange and key exchange. Additional message
	 * processing is kicked off as a background promise chain.
	 * @param cancellation optional cancellation token.
	 */
	public async connect(cancellation?: CancellationToken) {
		if (this.serverCredentials) {
			const serverSession = <SshServerSession>this.session;
			serverSession.credentials = this.serverCredentials;
		}

		await this.session.connect(this.transportStream, cancellation);

		let channel: SshChannel | null = null;
		if (this.clientCredentials) {
			let error: SshConnectionError | null = null;
			const clientSession = <SshClientSession>this.session;
			if (!(await clientSession.authenticateServer(cancellation))) {
				error = new SshConnectionError(
					'Server authentication failed.',
					SshDisconnectReason.hostKeyNotVerifiable,
				);
			}

			if (
				!error &&
				!(await clientSession.authenticateClient(this.clientCredentials, cancellation))
			) {
				error = new SshConnectionError(
					'Client authentication failed.',
					SshDisconnectReason.noMoreAuthMethodsAvailable,
				);
			}

			if (error) {
				await this.session.close(error.reason!, error.message, error);
				throw error;
			}

			channel = await this.session.openChannel(cancellation);
		} else {
			channel = await this.session.acceptChannel(cancellation);
		}

		this.stream = this.createStream(channel);
		// Do not forward the 'readable' event because adding a listener causes a read.
		this.stream.on('data', (data) => this.emit('data', data));
		this.stream.on('end', () => this.emit('end'));
		this.stream.on('close', () => this.emit('close'));
		this.stream.on('error', () => this.emit('error'));
		channel.onClosed(() => this.dispose());
	}

	/**
	 * Creates a stream instance for a channel. May be overridden to create a `SshStream` subclass.
	 */
	protected createStream(channel: SshChannel): SshStream {
		return new SshStream(channel);
	}

	public dispose() {
		if (!this.disposed) {
			this.disposed = true;
			this.session.dispose();
			this.unsubscribe();

			try {
				if (this.transportStream)
					this.transportStream.close().catch((e) => {
						this.trace(
							TraceLevel.Error,
							SshTraceEventIds.streamCloseError,
							`Error closing transport stream: ${e.message}`,
							e,
						);
					});
			} catch (e) {
				if (!(e instanceof Error)) throw e;
				this.trace(
					TraceLevel.Error,
					SshTraceEventIds.streamCloseError,
					`Error closing transport stream: ${e.message}`,
					e,
				);
			}
		}
	}

	public async close() {
		if (!this.disposed) {
			this.disposed = true;

			await this.session.close(SshDisconnectReason.none, 'SshSession disposed');
			this.session.dispose();
			this.unsubscribe();

			await this.transportStream.close();
		}
	}

	private onSessionClosed(e: SshSessionClosedEventArgs) {
		this.unsubscribe();
		this.closedEmitter.fire(e);
	}

	private unsubscribe() {
		this.disposables.forEach((d) => d.dispose());
		this.disposables = [];
	}
}
