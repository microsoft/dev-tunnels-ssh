//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken, Disposable, Emitter, Event } from 'vscode-jsonrpc';
import { Stream } from './streams';
import { SshChannel } from './sshChannel';
import { SshStream } from './sshStream';

import { SshSession } from './sshSession';
import { SshSessionConfiguration } from './sshSessionConfiguration';
import { SshDisconnectReason } from './messages/transportMessages';
import { SshSessionClosedEventArgs } from './events/sshSessionClosedEventArgs';
import { SshChannelOpeningEventArgs } from './events/sshChannelOpeningEventArgs';
import { Trace, TraceLevel, SshTraceEventIds } from './trace';
import { ChannelOpenMessage } from './messages/connectionMessages';
import { Progress } from './progress';

/**
 * Multiplexes multiple virtual streams (channels) over a single transport stream, using the
 * SSH protocol while providing a simplified interface without any encryption or authentication.
 *
 * This class is a complement to `SecureStream`, which provides only the encryption and
 * authentication functions of SSH.
 *
 * To communicate over multiple channels, two sides first establish a transport stream
 * over a pipe, socket, or anything else. Then one side accepts a channel while the
 * other side opens a channel. Either side can both open and accept channels over the
 * same transport stream, as long as the other side does the complementary action.
 */
export class MultiChannelStream implements Disposable {
	protected readonly session: SshSession;
	private disposed: boolean = false;
	private disposables: Disposable[] = [];

	private readonly reportProgressEmitter = new Emitter<Progress>();

	/**
	 * Event that is raised to report connection progress.
	 *
	 * See `Progress` for a description of the different progress events that can be reported.
	 */
	public readonly onReportProgress: Event<Progress> = this.reportProgressEmitter.event;

	/**
	 * Creates a new multi-channel stream over an underlying transport stream.
	 * @param transportStream Stream that is used to multiplex all the channels.
	 */
	public constructor(protected readonly transportStream: Stream) {
		if (!transportStream) throw new TypeError('transportStream is required.');

		const noSecurityConfig = new SshSessionConfiguration(false);
		this.session = new SshSession(noSecurityConfig);
		this.session.onReportProgress(this.raiseReportProgress, this, this.disposables);
		this.session.onClosed(this.onSessionClosed, this, this.disposables);
		this.session.onChannelOpening(this.onSessionChannelOpening, this, this.disposables);
	}

	public get trace(): Trace {
		return this.session.trace;
	}

	public set trace(trace: Trace) {
		this.session.trace = trace;
	}

	protected raiseReportProgress(progress: Progress) {
		this.reportProgressEmitter.fire(progress);
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

	private readonly channelOpeningEmitter = new Emitter<SshChannelOpeningEventArgs>();
	public readonly onChannelOpening = this.channelOpeningEmitter.event;

	/**
	 * Initiates the SSH session over the transport stream by exchanging initial messages with the
	 * remote peer. Waits for the protocol version exchange and key exchange. Additional message
	 * processing is kicked off as a background promise chain.
	 * @param cancellation optional cancellation token.
	 */
	public async connect(cancellation?: CancellationToken) {
		await this.session.connect(this.transportStream, cancellation);
	}

	/**
	 * Asynchronously waits for the other side to open a channel.
	 * @param channelType optional channel type
	 * @param cancellation optional cancellation token.
	 */
	public async acceptChannel(
		channelType?: string,
		cancellation?: CancellationToken,
	): Promise<SshChannel> {
		await this.session.connect(this.transportStream, cancellation);
		const channel = await this.session.acceptChannel(channelType, cancellation);
		return channel;
	}

	/**
	 * Asynchronously waits for the other side to open a channel.
	 * @param channelType optional channel type
	 * @param cancellation optional cancellation token.
	 */
	public async acceptStream(
		channelType?: string,
		cancellation?: CancellationToken,
	): Promise<SshStream> {
		return this.createStream(await this.acceptChannel(channelType, cancellation));
	}

	/**
	 * Opens a channel and asynchronously waits for the other side to accept it.
	 * @param channelType optional channel type
	 * @param cancellation optional cancellation token.
	 */
	public async openChannel(
		channelType?: string,
		cancellation?: CancellationToken,
	): Promise<SshChannel> {
		await this.session.connect(this.transportStream, cancellation);

		const openMessage = new ChannelOpenMessage();
		openMessage.channelType = channelType ?? SshChannel.sessionChannelType;
		openMessage.maxWindowSize = this.channelMaxWindowSize;
		const channel = await this.session.openChannel(openMessage, null, cancellation);
		return channel;
	}

	/**
	 * Opens a channel and asynchronously waits for the other side to accept it.
	 * @param channelType optional channel type
	 * @param cancellation optional cancellation token.
	 */
	public async openStream(
		channelType?: string,
		cancellation?: CancellationToken,
	): Promise<SshStream> {
		return this.createStream(await this.openChannel(channelType, cancellation));
	}

	/**
	 * Creates a stream instance for a channel. May be overridden to create a `SshStream` subclass.
	 */
	protected createStream(channel: SshChannel): SshStream {
		return new SshStream(channel);
	}

	/**
	 * Connects, waits until the session closes or `cancellation` is cancelled, and then disposes the
	 * session and the transport stream.
	 * @param cancellation optional cancellation token.
	 */
	public async connectAndRunUntilClosed(cancellation?: CancellationToken) {
		const disposables: Disposable[] = [];
		const sessionClosedPromise = new Promise<SshSessionClosedEventArgs>((resolve, reject) => {
			cancellation?.onCancellationRequested(reject, null, disposables);
			this.session.onClosed(resolve, null, disposables);
		});

		try {
			await this.connect(cancellation);
			await sessionClosedPromise;
		} finally {
			disposables.forEach((d) => d.dispose());
			await this.close();
		}
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

	private onSessionChannelOpening(e: SshChannelOpeningEventArgs) {
		if (e.isRemoteRequest) {
			e.channel.maxWindowSize = this.channelMaxWindowSize;
		}

		this.channelOpeningEmitter.fire(e);
	}

	private unsubscribe() {
		this.disposables.forEach((d) => d.dispose());
		this.disposables = [];
	}
}
