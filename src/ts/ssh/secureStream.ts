//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken, Disposable, Emitter } from 'vscode-jsonrpc';
import { NodeStream, Stream } from './streams';
import { SshChannel } from './sshChannel';
import { SshStream } from './sshStream';
import { SshSession } from './sshSession';
import { SshSessionConfiguration } from './sshSessionConfiguration';
import { SshDisconnectReason } from './messages/transportMessages';
import { SshSessionClosedEventArgs } from './events/sshSessionClosedEventArgs';
import { Trace, TraceLevel, SshTraceEventIds } from './trace';
import { SshClientCredentials, SshServerCredentials } from './sshCredentials';
import { SshClientSession } from './sshClientSession';
import { SshServerSession } from './sshServerSession';
import { SshAuthenticatingEventArgs } from './events/sshAuthenticatingEventArgs';
import { SshConnectionError } from './errors';
import { Duplex } from 'stream';
import { PromiseCompletionSource } from './util/promiseCompletionSource';

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
	private readonly connectCompletion = new PromiseCompletionSource<SshStream>();
	private stream?: SshStream;
	private disposed: boolean = false;
	private disposables: Disposable[] = [];

	/**
	 * Creates a new multi-channel stream over an underlying transport stream.
	 * @param transportStream Stream that is used to multiplex all the channels.
	 */
	public constructor(
		private readonly transportStream: Stream | Duplex,
		credentials: SshClientCredentials | SshServerCredentials,
	) {
		super({
			write(
				this: SecureStream,
				chunk: Buffer | string | any,
				encoding: BufferEncoding,
				cb: (error?: Error | null) => void,
			): void {
				this.connectCompletion.promise.then((stream) => {
					// eslint-disable-next-line no-underscore-dangle
					stream._write(chunk, encoding, cb);
				}, cb);
			},
			writev(
				this: SecureStream,
				chunks: { chunk: Buffer; encoding: BufferEncoding }[],
				cb: (error?: Error | null) => void,
			): void {
				this.connectCompletion.promise.then((stream) => {
					// eslint-disable-next-line no-underscore-dangle
					stream._writev!(chunks, cb);
				}, cb);
			},
			final(this: SecureStream, cb: (err?: Error | null) => void): void {
				this.connectCompletion.promise.then((stream) => {
					// eslint-disable-next-line no-underscore-dangle
					stream._final(cb);
				}, cb);
			},
			read(this: SecureStream, size: number): void {
				this.connectCompletion.promise.then(
					(stream) => {
						// eslint-disable-next-line no-underscore-dangle
						stream._read(size);
					},
					(e) => {
						// The error will be thrown from the connect() method.
					},
				);
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
		try {
			if (this.serverCredentials) {
				const serverSession = <SshServerSession>this.session;
				serverSession.credentials = this.serverCredentials;
			}

			let stream = this.transportStream;
			if (stream instanceof Duplex) {
				stream = new NodeStream(stream);
			}

			await this.session.connect(stream, cancellation);

			let channel: SshChannel | null = null;
			if (this.clientCredentials) {
				const clientSession = <SshClientSession>this.session;
				if (!(await clientSession.authenticateServer(cancellation))) {
					throw new SshConnectionError(
						'Server authentication failed.',
						SshDisconnectReason.hostKeyNotVerifiable,
					);
				}

				if (!(await clientSession.authenticateClient(this.clientCredentials, cancellation))) {
					throw new SshConnectionError(
						'Client authentication failed.',
						SshDisconnectReason.noMoreAuthMethodsAvailable,
					);
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
			this.connectCompletion.resolve(this.stream);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			let disconnectReason = e instanceof SshConnectionError ? e.reason : undefined;
			disconnectReason ??= SshDisconnectReason.protocolError;
			await this.session.close(disconnectReason, e.message, e);
			this.connectCompletion.reject(e);
			throw e;
		}
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
				if (this.transportStream) {
					if (this.transportStream instanceof Duplex) {
						this.transportStream.end();
						this.transportStream.destroy();
					} else {
						this.transportStream.close().catch((e) => {
							this.trace(
								TraceLevel.Error,
								SshTraceEventIds.streamCloseError,
								`Error closing transport stream: ${e.message}`,
								e,
							);
						});
					}
				}
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

			if (this.transportStream instanceof Duplex) {
				await new Promise((resolve) => {
					(<Duplex>this.transportStream).end(resolve);
				});
			} else {
				await this.transportStream.close();
			}
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
