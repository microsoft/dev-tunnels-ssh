//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Event, Emitter, Disposable } from 'vscode-jsonrpc';
import { ConnectionService } from './services/connectionService';
import { findService, ServiceActivation } from './services/serviceActivation';
import { SshMessage } from './messages/sshMessage';
import {
	ChannelEofMessage,
	ChannelDataMessage,
	ChannelWindowAdjustMessage,
	ChannelCloseMessage,
	ChannelRequestMessage,
	ChannelRequestType,
	ChannelSignalMessage,
	ChannelSuccessMessage,
	ChannelFailureMessage,
	ChannelOpenMessage,
	ChannelOpenConfirmationMessage,
	ChannelExtendedDataMessage,
} from './messages/connectionMessages';
import { SshDisconnectReason } from './messages/transportMessages';
import { ChannelMetrics } from './metrics/channelMetrics';
import { PromiseCompletionSource } from './util/promiseCompletionSource';
import { SshConnectionError, ObjectDisposedError, SshChannelError } from './errors';
import { SshRequestEventArgs } from './events/sshRequestEventArgs';
import { SshChannelClosedEventArgs } from './events/sshChannelClosedEventArgs';
import { CancellationToken, CancellationError, withCancellation } from './util/cancellation';
import { Semaphore } from './util/semaphore';
import { TraceLevel, SshTraceEventIds } from './trace';
import { PipeExtensions } from './pipeExtensions';
import { SshExtendedDataEventArgs, SshExtendedDataType } from './events/sshExtendedDataEventArgs';

/**
 * Represents a channel on an SSH session. A session may include multiple channels, which
 * are multiplexed over the connection. Each channel within a session has a unique integer ID.
 */
export class SshChannel implements Disposable {
	public static readonly sessionChannelType = 'session';

	/**
	 * Default maximum packet size. Channel data payloads larger than the max packet size will
	 * be broken into chunks before sending. The actual `maxPacketSize` may be smaller (but
	 * never larger) than the default if requested by the other side.
	 */
	public static readonly defaultMaxPacketSize = ChannelOpenMessage.defaultMaxPacketSize;

	/**
	 * Default maximum window size for received data. The other side will not send more data than
	 * the window size until it receives an acknowledgement that some of the data was received and
	 * processed by this side. A non-default `maxWindowSize` may be configured at the time of
	 * opening the channel.
	 */
	public static readonly defaultMaxWindowSize = ChannelOpenMessage.defaultMaxWindowSize;

	private remoteWindowSize: number;
	private maxWindowSizeValue: number;
	private windowSize: number;
	private remoteClosed: boolean = false;
	private localClosed: boolean = false;
	private sentEof: boolean = false;
	private exitStatus?: number;
	private exitSignal?: string;
	private exitErrorMessage?: string;
	private disposed: boolean = false;
	private openSendingWindowCompletionSource: PromiseCompletionSource<void> | null = null;
	private requestCompletionSource: PromiseCompletionSource<boolean> | null = null;
	private readonly sendSemaphore = new Semaphore(0);

	/**
	 * Gets an object that reports measurements about the channel.
	 */
	public readonly metrics = new ChannelMetrics();

	private readonly dataReceivedEmitter = new Emitter<Buffer>();

	private readonly extendedDataReceivedEmitter = new Emitter<SshExtendedDataEventArgs>();

	/**
	 * Event raised when a data message is received on the channel.
	 *
	 * Users of a channel MUST add a `onDataReceived` event handler immediately after a
	 * channel is opened/accepted, or else all session communication will be blocked.
	 * (The `SshStream` class does this automatically.)
	 *
	 * The event handler must call `adjustWindow` when the data has been consumed,
	 * to notify the remote side that it may send more data.
	 */
	public readonly onDataReceived: Event<Buffer> = this.dataReceivedEmitter.event;

	public readonly onExtendedDataReceived: Event<SshExtendedDataEventArgs> = this.extendedDataReceivedEmitter.event;

	private readonly eofEmitter = new Emitter<void>();

	/**
	 * Event raised when an EOF message is received on the channel.
	 */
	public readonly onEof: Event<void> = this.eofEmitter.event;

	private readonly closedEmitter = new Emitter<SshChannelClosedEventArgs>();
	public readonly onClosed: Event<SshChannelClosedEventArgs> = this.closedEmitter.event;

	private readonly requestEmitter = new Emitter<SshRequestEventArgs<ChannelRequestMessage>>();
	public readonly onRequest: Event<SshRequestEventArgs<ChannelRequestMessage>> =
		this.requestEmitter.event;

	/* @internal */
	public constructor(
		private readonly connectionService: ConnectionService,
		public readonly channelType: string,
		public readonly channelId: number,
		public readonly remoteChannelId: number,
		remoteMaxWindowSize: number,
		remoteMaxPacketSize: number,
		public readonly openMessage: ChannelOpenMessage,
		public openConfirmationMessage: ChannelOpenConfirmationMessage,
	) {
		this.remoteWindowSize = remoteMaxWindowSize;
		this.maxWindowSizeValue = SshChannel.defaultMaxWindowSize;
		this.windowSize = this.maxWindowSizeValue;
		this.maxPacketSize = Math.min(remoteMaxPacketSize, SshChannel.defaultMaxPacketSize);
	}

	public get session() {
		return this.connectionService.session;
	}

	public get isClosed(): boolean {
		return this.localClosed || this.remoteClosed;
	}

	/**
	 * Gets the maximum window size for received data. The other side will not send more
	 * data than the window size until it receives an acknowledgement that some of the data was
	 * received and processed by this side.
	 */
	public get maxWindowSize(): number {
		return this.maxWindowSizeValue;
	}

	/**
	 * Sets the maximum window size for received data. The other side will not send more
	 * data than the window size until it receives an acknowledgement that some of the data was
	 * received and processed by this side.
	 *
	 * The default value is `defaultMaxWindowSize`. The value may be configured for a channel
	 * opened by this side by setting `ChannelOpenMessage.maxWindowSize` in the message object
	 * passed to `SshSession.openChannel()`, or for a channel opened by the other side by
	 * assigning to this property while handling the `SshSession.onChannelOpening` event.
	 * Changing the maximum window size at any other time is not valid because the other
	 * side would not be aware of the change.
	 */
	public set maxWindowSize(value: number) {
		if (this.isMaxWindowSizeLocked) {
			throw new Error('Cannot change the max window size after opening the channel.');
		}

		if (value < this.maxPacketSize) {
			throw new Error('Maximum window size cannot be less than maximum packet size.');
		}

		this.maxWindowSizeValue = value;
	}

	/**
	 * Gets or sets a value indicating whether `maxWindowSize is locked, so that it cannot be
	 * changed after the channel is opened.
	 */
	/* @internal */
	public isMaxWindowSizeLocked = false;

	/**
	 * Gets the maximum packet size. Channel data payloads larger than the max packet size will
	 * be broken into chunks before sending. The actual max packet size may be smaller (but
	 * never larger) than `defaultMaxPacketSize` if requested by the other side.
	 */
	public readonly maxPacketSize: number;

	/**
	 * Sends a channel request and waits for a response.
	 *
	 * Note if `wantReply` is `false`, this method returns `true` immediately after sending the
	 * request, without waiting for a reply.
	 *
	 * @returns The authorization status of the response; if false, the other side denied the
	 * request.
	 * @throws `ObjectDisposedError` if the channel was closed before sending the request.
	 * @throws `SshChannelError` if the channel was closed while waiting for a reply to the request.
	 */
	public async request(
		request: ChannelRequestMessage,
		cancellation?: CancellationToken,
	): Promise<boolean> {
		if (!request) throw new TypeError('Request is required.');
		if (this.disposed) throw new ObjectDisposedError(this);

		request.recipientChannel = this.remoteChannelId;
		if (!request.wantReply) {
			// If a reply is not requested, there's no need to set up a completion source.
			await this.session.sendMessage(request, cancellation);
			return true;
		}

		// TODO: enable sending multiple requests in TS
		// see https://dev.azure.com/devdiv/DevDiv/_git/SSH/commit/0b84a48811e2f015107c73bf4584b6c3b676a6de
		if (this.requestCompletionSource != null) {
			throw new Error('Another request is already pending.');
		}

		// Capture as a local variable because the member may change.
		const requestCompletionSource = new PromiseCompletionSource<boolean>();
		this.requestCompletionSource = requestCompletionSource;
		if (cancellation) {
			if (cancellation.isCancellationRequested) throw new CancellationError();
			cancellation.onCancellationRequested(() => {
				requestCompletionSource.reject(new CancellationError());
			});
		}

		await this.session.sendMessage(request, cancellation);

		return await requestCompletionSource.promise;
	}

	public async send(data: Buffer, cancellation?: CancellationToken): Promise<void> {
		if (this.disposed) throw new ObjectDisposedError(this);

		if (data.length === 0) {
			await this.sendEof();
			return;
		} else if (this.sentEof) {
			throw new Error('Cannot send more data after EOF.');
		}

		// Prevent out-of-order message chunks even if the caller does not await.
		// Also don't send until the channel is fully opened.
		await this.sendSemaphore.wait(cancellation);
		try {
			let offset = 0;
			let count = data.length;
			while (count > 0) {
				let packetSize = Math.min(Math.min(this.remoteWindowSize, this.maxPacketSize), count);
				while (packetSize === 0) {
					if (!this.openSendingWindowCompletionSource) {
						this.openSendingWindowCompletionSource = new PromiseCompletionSource<void>();
					}

					this.session.trace(
						TraceLevel.Warning,
						SshTraceEventIds.channelWaitForWindowAdjust,
						`${this} send window is full. Waiting for window adjustment before sending.`,
					);
					await withCancellation(this.openSendingWindowCompletionSource.promise, cancellation);

					this.openSendingWindowCompletionSource = null;
					packetSize = Math.min(Math.min(this.remoteWindowSize, this.maxPacketSize), count);
				}

				const msg = new ChannelDataMessage();
				msg.recipientChannel = this.remoteChannelId;

				// Unfortunately the data must be copied to a new buffer at this point
				// to ensure it is still available to be re-sent later in case of disconnect.
				msg.data = Buffer.from(data.slice(offset, offset + packetSize));

				await this.session.sendMessage(msg, cancellation);

				this.remoteWindowSize -= packetSize;
				count -= packetSize;
				offset += packetSize;

				this.metrics.addBytesSent(packetSize);
			}
		} finally {
			this.sendSemaphore.tryRelease();
		}
	}

	public async sendExtendedData(dataTypeCode: SshExtendedDataType, data: Buffer, cancellation?: CancellationToken): Promise<void> {
		if (this.disposed) throw new ObjectDisposedError(this);

		if (data.length === 0) {
			await this.sendEof();
			return;
		} else if (this.sentEof) {
			throw new Error('Cannot send more data after EOF.');
		}

		// Prevent out-of-order message chunks even if the caller does not await.
		// Also don't send until the channel is fully opened.
		await this.sendSemaphore.wait(cancellation);
		try {
			let offset = 0;
			let count = data.length;
			while (count > 0) {
				let packetSize = Math.min(Math.min(this.remoteWindowSize, this.maxPacketSize), count);
				while (packetSize === 0) {
					if (!this.openSendingWindowCompletionSource) {
						this.openSendingWindowCompletionSource = new PromiseCompletionSource<void>();
					}

					this.session.trace(
						TraceLevel.Warning,
						SshTraceEventIds.channelWaitForWindowAdjust,
						`${this} send window is full. Waiting for window adjustment before sending.`,
					);
					await withCancellation(this.openSendingWindowCompletionSource.promise, cancellation);

					this.openSendingWindowCompletionSource = null;
					packetSize = Math.min(Math.min(this.remoteWindowSize, this.maxPacketSize), count);
				}

				const msg = new ChannelExtendedDataMessage();
				msg.dataTypeCode = dataTypeCode;
				msg.recipientChannel = this.remoteChannelId;

				// Unfortunately the data must be copied to a new buffer at this point
				// to ensure it is still available to be re-sent later in case of disconnect.
				msg.data = Buffer.from(data.slice(offset, offset + packetSize));

				await this.session.sendMessage(msg, cancellation);

				this.remoteWindowSize -= packetSize;
				count -= packetSize;
				offset += packetSize;

				this.metrics.addBytesSent(packetSize);
			}
		} finally {
			this.sendSemaphore.tryRelease();
		}
	}

	/* @internal */
	public enableSending(): void {
		this.sendSemaphore.tryRelease();
	}

	private async sendEof(cancellation?: CancellationToken): Promise<void> {
		if (this.sentEof) {
			return;
		}

		await this.sendSemaphore.wait(cancellation);
		try {
			this.sentEof = true;
			const msg = new ChannelEofMessage();
			msg.recipientChannel = this.remoteChannelId;
			await this.session.sendMessage(msg, cancellation);
		} finally {
			this.sendSemaphore.tryRelease();
		}
	}

	/* @internal */
	public async handleRequest(
		request: ChannelRequestMessage,
		cancellation?: CancellationToken,
	): Promise<boolean> {
		if (!request.requestType) {
			throw new SshConnectionError(
				'Channel request type not specified.',
				SshDisconnectReason.protocolError,
			);
		}

		if (request.requestType === ChannelRequestType.exitStatus) {
			const signal = new ChannelSignalMessage();
			request.convertTo(signal);
			this.exitStatus = signal.exitStatus;
			return true;
		} else if (request.requestType === ChannelRequestType.exitSignal) {
			const signal = new ChannelSignalMessage();
			request.convertTo(signal);
			this.exitSignal = signal.exitSignal;
			this.exitErrorMessage = signal.errorMessage;
			return true;
		} else if (request.requestType === ChannelRequestType.signal) {
			const signal = new ChannelSignalMessage();
			request.convertTo(signal);
		}

		const args = new SshRequestEventArgs<ChannelRequestMessage>(
			request.requestType,
			request,
			this.session.principal,
			cancellation,
		);

		const serviceType = findService(
			this.session.config.services,
			(a: ServiceActivation) =>
				(!a.channelType || a.channelType === this.channelType) &&
				a.channelRequest === request.requestType,
		);

		await this.sendSemaphore.wait(cancellation);
		try {
			let response: SshMessage | null = null;
			if (serviceType) {
				// A service was configured for activation via this session request type.
				const service = this.session.activateService(serviceType);

				// `onChannelRequest` should really be 'protected internal'.
				await (<any>service).onChannelRequest(this, args, cancellation);
			} else {
				this.requestEmitter.fire(args);
			}

			// TODO: do not block requests in TS (similar to CS)
			// see https://dev.azure.com/devdiv/DevDiv/_git/SSH/commit/0b84a48811e2f015107c73bf4584b6c3b676a6de
			if (args.responsePromise) {
				response = await args.responsePromise;
				args.isAuthorized = response instanceof ChannelSuccessMessage;
			}

			if (request.wantReply) {
				if (args.isAuthorized) {
					response = response ?? new ChannelSuccessMessage();
					(<ChannelSuccessMessage>response).recipientChannel = this.remoteChannelId;
				} else {
					response = response ?? new ChannelFailureMessage();
					(<ChannelFailureMessage>response).recipientChannel = this.remoteChannelId;
				}

				await this.session.sendMessage(response, cancellation);
			}
		} finally {
			this.sendSemaphore.tryRelease();
		}

		return args.isAuthorized || false;
	}

	/* @internal */
	public handleResponse(result: boolean) {
		if (this.requestCompletionSource) {
			this.requestCompletionSource.resolve(result);
			this.requestCompletionSource = null;
		}
	}

	/* @internal */
	public handleDataReceived(data: Buffer): void {
		this.metrics.addBytesReceived(data.length);

		// DataReceived handler is to adjust the window when it's done with the data.
		this.dataReceivedEmitter.fire(data);
	}

	public handleExtendedDataReceived(data: SshExtendedDataEventArgs): void {
		// this.metrics.addBytesReceived(data.length);
		this.extendedDataReceivedEmitter.fire(data);
	}

	/**
	 * Adjusts the local receiving window size by the specified amount, notifying
	 * the remote side that it is free to send more data.
	 *
	 * This method MUST be called either immediately or eventually by the
	 * `onDataReceived` event handler as incoming data is processed.
	 */
	public adjustWindow(messageLength: number): void {
		if (this.disposed) return;

		this.windowSize -= messageLength;
		if (this.windowSize <= this.maxWindowSizeValue / 2) {
			const windowAdjustMessage = new ChannelWindowAdjustMessage();
			windowAdjustMessage.recipientChannel = this.remoteChannelId;
			windowAdjustMessage.bytesToAdd = this.maxWindowSizeValue - this.windowSize;
			this.windowSize = this.maxWindowSizeValue;

			this.session.sendMessage(windowAdjustMessage).catch((e) => {
				this.session.trace(
					TraceLevel.Error,
					SshTraceEventIds.channelWindowAdjustFailed,
					`Error sending window adjust message: ${e.message}`,
					e,
				);
			});
		}
	}

	/* @internal */
	public adjustRemoteWindow(bytesToAdd: number): void {
		this.remoteWindowSize += bytesToAdd;

		if (this.openSendingWindowCompletionSource) {
			this.openSendingWindowCompletionSource.resolve(undefined);
		}
	}

	/* @internal */
	public handleEof(): void {
		this.session.trace(
			TraceLevel.Info,
			SshTraceEventIds.channelEofReceived,
			`${this} EOF received.`,
		);
		this.eofEmitter.fire();
	}

	public close(cancellation?: CancellationToken): Promise<void>;
	public close(exitStatus: number, cancellation?: CancellationToken): Promise<void>;
	public close(
		exitSignal: string,
		errorMessage?: string,
		cancellation?: CancellationToken,
	): Promise<void>;

	/* @internal */
	public close(error: Error): void;

	public close(
		exitStatusOrSignal?: number | string | CancellationToken | Error,
		errorMessage?: string | CancellationToken,
		cancellation?: CancellationToken,
	): Promise<void> | void {
		if (exitStatusOrSignal instanceof Error) {
			const error = exitStatusOrSignal;

			if (!this.localClosed) {
				this.localClosed = true;
				this.session.trace(
					TraceLevel.Info,
					SshTraceEventIds.channelClosed,
					`${this} Closed: ${error.message}`,
				);
				this.closedEmitter.fire(new SshChannelClosedEventArgs(error));
			}

			this.disposeInternal();
			return;
		}

		if (typeof exitStatusOrSignal === 'number') {
			return this.closeWithStatus(exitStatusOrSignal, <CancellationToken>errorMessage);
		} else if (typeof exitStatusOrSignal === 'string') {
			return this.closeWithSignal(
				exitStatusOrSignal,
				<string>errorMessage,
				<CancellationToken>cancellation,
			);
		} else {
			return this.closeDefault(<CancellationToken>exitStatusOrSignal);
		}
	}

	private async closeDefault(cancellation?: CancellationToken): Promise<void> {
		if (!this.remoteClosed && !this.localClosed) {
			this.remoteClosed = true;

			await this.sendSemaphore.wait(cancellation);
			try {
				const closeMessage = new ChannelCloseMessage();
				closeMessage.recipientChannel = this.remoteChannelId;
				await this.session.sendMessage(closeMessage);
			} catch (e) {
				// The session was already closed.
			} finally {
				this.sendSemaphore.tryRelease();
			}
		}

		if (!this.localClosed) {
			this.localClosed = true;
			const closedMessage = this.raiseClosedEvent();
			this.requestCompletionSource?.reject(new SshChannelError(closedMessage));
		}

		this.disposeInternal();
	}

	private async closeWithStatus(
		exitStatus: number,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (!this.remoteClosed && !this.localClosed) {
			this.exitStatus = exitStatus;

			const signalMessage = new ChannelSignalMessage();
			signalMessage.recipientChannel = this.remoteChannelId;
			signalMessage.exitStatus = exitStatus;
			await this.session.sendMessage(signalMessage);
		}

		await this.closeDefault(cancellation);
	}

	private async closeWithSignal(
		exitSignal: string,
		errorMessage?: string,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (!this.remoteClosed && !this.localClosed) {
			this.exitSignal = exitSignal;
			this.exitErrorMessage = errorMessage;

			const signalMessage = new ChannelSignalMessage();
			signalMessage.recipientChannel = this.remoteChannelId;
			signalMessage.exitSignal = exitSignal;
			signalMessage.errorMessage = errorMessage;
			await this.session.sendMessage(signalMessage);
		}

		await this.closeDefault(cancellation);
	}

	/* @internal */
	public handleClose(): void {
		if (!this.localClosed) {
			this.localClosed = true;
			const closedMessage = this.raiseClosedEvent(true);
			this.requestCompletionSource?.reject(new SshChannelError(closedMessage));
		}

		this.disposeInternal();
	}

	private raiseClosedEvent(closedByRemote = false): string {
		const metricsMessage = ` (S: ${this.metrics.bytesSent}, R: ${this.metrics.bytesReceived})`;
		const originMessage = closedByRemote ? 'remotely' : 'locally';
		let closedMessage: string;
		let args: SshChannelClosedEventArgs;

		if (typeof this.exitStatus !== 'undefined') {
			args = new SshChannelClosedEventArgs(this.exitStatus);
			closedMessage = `${this} closed ${originMessage}: status=${this.exitStatus}`;
		} else if (typeof this.exitSignal !== 'undefined') {
			args = new SshChannelClosedEventArgs(this.exitSignal, this.exitErrorMessage);
			closedMessage = `${this} closed ${originMessage}: signal=${this.exitSignal} ${this.exitErrorMessage}`;
		} else {
			args = new SshChannelClosedEventArgs();
			closedMessage = `${this} closed ${originMessage}.`;
		}

		this.session.trace(
			TraceLevel.Info,
			SshTraceEventIds.channelClosed,
			closedMessage + metricsMessage,
		);
		this.closedEmitter.fire(args);
		return closedMessage;
	}

	public dispose(): void {
		if (!this.disposed && !this.localClosed) {
			if (!this.remoteClosed) {
				this.remoteClosed = true;
				const closeMessage = new ChannelCloseMessage();
				closeMessage.recipientChannel = this.remoteChannelId;
				this.session.sendMessage(closeMessage).catch((e) => {
					// The session was already closed, or some other sending error occurred.
					// The details have already been traced.
				});
			}

			const message = this.session.isClosed ? `${this.session} closed.` : `${this} disposed.`;
			this.session.trace(TraceLevel.Info, SshTraceEventIds.channelClosed, message);
			const args = new SshChannelClosedEventArgs('SIGABRT', message);

			this.localClosed = true;
			this.closedEmitter.fire(args);
			this.requestCompletionSource?.reject(new SshChannelError(message));
		}

		this.disposeInternal();
	}

	private disposeInternal(): void {
		if (this.disposed) return;
		this.disposed = true;

		this.requestCompletionSource?.reject(new ObjectDisposedError(this));
		this.connectionService.removeChannel(this);
		this.sendSemaphore.dispose();
	}

	/**
	 * Pipes one SSH channel into another, relaying all data between them.
	 * @param toChannel Channel to which the current channel will be connected via the pipe.
	 * @returns A promise that resolves when the channels are closed.
	 */
	public pipe(toChannel: SshChannel): Promise<void> {
		return PipeExtensions.pipeChannel(this, toChannel);
	}

	public toString() {
		return `SshChannel(Type: ${this.channelType}, Id: ${this.channelId}, RemoteId: ${this.remoteChannelId})`;
	}
}
