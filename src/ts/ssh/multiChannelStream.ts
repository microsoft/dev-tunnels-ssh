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
import { SshChannelOpeningEventArgs } from './events/sshChannelOpeningEventArgs';
import { ConnectionService } from './services/connectionService';
import { Trace, TraceLevel, SshTraceEventIds } from './trace';
import { ChannelOpenMessage } from './messages/connectionMessages';

/**
 * This class allows to establish an ssh session with no security beign defined.
 * Both side could open multiple channel to send/receive data.
 */
export class MultiChannelStream implements Disposable {
	private readonly streamFactory: (channel: SshChannel) => SshStream;
	private readonly session: SshSession;
	private disposed: boolean = false;
	private disposables: Disposable[] = [];

	/**
	 * Creates a new multi-channel stream over an underlying transport stream.
	 * @param transportStream Stream that is used to multiplex all the channels.
	 * @param streamFactory Optional factory function for creating stream instances.
	 */
	public constructor(
		private readonly transportStream: Stream,
		streamFactory?: (channel: SshChannel) => SshStream,
	) {
		if (!transportStream) throw new TypeError('transportStream is required.');

		this.streamFactory = streamFactory ?? ((channel: SshChannel) => new SshStream(channel));

		const noSecurityConfig = new SshSessionConfiguration(false);
		this.session = new SshSession(noSecurityConfig);
		this.session.onClosed(this.onSessionClosed, this, this.disposables);
		this.session.onChannelOpening(this.onSessionChannelOpening, this, this.disposables);
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

	private readonly channelOpeningEmitter = new Emitter<SshChannelOpeningEventArgs>();
	public get onChannelOpening() {
		if (!this.isClosed) {
			this.session.activateService(ConnectionService);
		}

		return this.channelOpeningEmitter.event;
	}

	/**
	 * Connects ssh session.
	 * @param cancellation optional cancellation token.
	 */
	public async connect(cancellation?: CancellationToken) {
		await this.session.connect(this.transportStream, cancellation);
	}

	/**
	 * Accept a new channel on the ssh session.
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
	 * Accept a remote ssh stream.
	 * @param channelType optional channel type
	 * @param cancellation optional cancellation token.
	 */
	public async acceptStream(
		channelType?: string,
		cancellation?: CancellationToken,
	): Promise<SshStream> {
		return this.streamFactory(await this.acceptChannel(channelType, cancellation));
	}

	/**
	 * Open a channel to a remote ssh session
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
	 * open a stream to a remote ssh session
	 * @param channelType optional channel type
	 * @param cancellation optional cancellation token.
	 */
	public async openStream(
		channelType?: string,
		cancellation?: CancellationToken,
	): Promise<SshStream> {
		return this.streamFactory(await this.openChannel(channelType, cancellation));
	}

	/**
	 * Connect ssh session and run it until closed.
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
