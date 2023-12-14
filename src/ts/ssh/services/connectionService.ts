//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshService } from './sshService';
import {
	ConnectionMessage,
	ChannelOpenMessage,
	ChannelCloseMessage,
	ChannelOpenConfirmationMessage,
	ChannelOpenFailureMessage,
	ChannelWindowAdjustMessage,
	ChannelDataMessage,
	ChannelRequestMessage,
	ChannelSuccessMessage,
	ChannelFailureMessage,
	ChannelEofMessage,
	SshChannelOpenFailureReason,
	ChannelMessage,
	ChannelExtendedDataMessage,
} from '../messages/connectionMessages';
import { SshSession } from '../sshSession';
import { CancellationToken, Disposable } from 'vscode-jsonrpc';
import { PromiseCompletionSource } from '../util/promiseCompletionSource';
import { SshChannel } from '../sshChannel';
import { CancellationError } from '../util/cancellation';
import { ObjectDisposedError, SshChannelError } from '../errors';
import { SshChannelOpeningEventArgs } from '../events/sshChannelOpeningEventArgs';
import { serviceActivation } from './serviceActivation';
import { TraceLevel, SshTraceEventIds } from '../trace';
import { SshExtendedDataEventArgs } from '../events/sshExtendedDataEventArgs';

interface PendingChannel {
	openMessage: ChannelOpenMessage;
	completionSource: PromiseCompletionSource<SshChannel>;
	cancellationRegistration: Disposable | null;
}

@serviceActivation({ serviceRequest: ConnectionService.serviceName })
export class ConnectionService extends SshService {
	public static readonly serviceName = 'ssh-connection';

	private channelCounter: number = 0;

	private readonly channelMap = new Map<number, SshChannel>();
	private readonly nonAcceptedChannels = new Map<number, SshChannel>();
	private readonly pendingChannels = new Map<number, PendingChannel>();
	private readonly pendingAcceptChannels = new Map<
		string,
		PromiseCompletionSource<SshChannel>[]
	>();

	public constructor(session: SshSession) {
		super(session);
	}

	public get channels(): SshChannel[] {
		return Array.from(this.channelMap.values());
	}

	public close(e: Error): void {
		let channelCompletions = [...this.pendingChannels.values()].map((pc) => pc.completionSource);
		if (this.pendingAcceptChannels.size > 0) {
			channelCompletions = channelCompletions.concat(
				[...this.pendingAcceptChannels.values()].reduce((a, b) => a.concat(b)),
			);
		}

		for (const channel of this.channelMap.values()) {
			channel.close(e);
		}

		for (const channelCompletion of channelCompletions) {
			channelCompletion.reject(e);
		}
	}

	public dispose(): void {
		const channels = [...this.channelMap.values()];

		let channelCompletions = [...this.pendingChannels.values()].map((pc) => pc.completionSource);
		if (this.pendingAcceptChannels.size > 0) {
			channelCompletions = channelCompletions.concat(
				[...this.pendingAcceptChannels.values()].reduce((a, b) => a.concat(b)),
			);
		}

		for (const channel of channels) {
			channel.dispose();
		}

		for (const channelCompletion of channelCompletions) {
			channelCompletion.reject(new ObjectDisposedError('Session closed.'));
		}

		super.dispose();
	}

	public async acceptChannel(
		channelType: string,
		cancellation?: CancellationToken,
	): Promise<SshChannel> {
		const completionSource = new PromiseCompletionSource<SshChannel>();

		let cancellationRegistration: Disposable | undefined;
		if (cancellation) {
			if (cancellation.isCancellationRequested) throw new CancellationError();
			cancellationRegistration = cancellation.onCancellationRequested(() => {
				const list = this.pendingAcceptChannels.get(channelType);
				if (list) {
					const index = list.findIndex((item) => Object.is(item, completionSource));
					if (index >= 0) {
						list.splice(index, 1);
					}
				}

				completionSource.reject(new CancellationError());
			});
		}

		let channel: SshChannel | null = null;

		channel =
			Array.from(this.nonAcceptedChannels.values()).find((c) => c.channelType === channelType) ||
			null;
		if (channel) {
			// Found a channel that was already opened but not accepted.
			this.nonAcceptedChannels.delete(channel.channelId);
		} else {
			// Set up the completion source to wait for a channel of the requested type.
			let list = this.pendingAcceptChannels.get(channelType);
			if (!list) {
				list = [];
				this.pendingAcceptChannels.set(channelType, list);
			}

			list.push(completionSource);
		}

		try {
			return channel || (await completionSource.promise);
		} finally {
			if (cancellationRegistration) cancellationRegistration.dispose();
		}
	}

	public async openChannel(
		openMessage: ChannelOpenMessage,
		completionSource: PromiseCompletionSource<SshChannel>,
		cancellation?: CancellationToken,
	): Promise<number> {
		const channelId = ++this.channelCounter;
		openMessage.senderChannel = channelId;

		let cancellationRegistration: Disposable | null = null;
		if (cancellation) {
			if (cancellation.isCancellationRequested) throw new CancellationError();
			cancellationRegistration = cancellation.onCancellationRequested(() => {
				if (this.pendingChannels.delete(channelId)) {
					completionSource.reject(new CancellationError());
				}
			});
		}

		this.pendingChannels.set(channelId, {
			openMessage: openMessage,
			completionSource: completionSource,
			cancellationRegistration: cancellationRegistration,
		});

		await this.session.sendMessage(openMessage);

		return channelId;
	}

	public handleMessage(
		message: ConnectionMessage,
		cancellation?: CancellationToken,
	): void | Promise<void> {
		if (message instanceof ChannelDataMessage) {
			return this.handleDataMessage(message);
		} else if (message instanceof ChannelExtendedDataMessage) {
			return this.handleExtendedDataMessage(message);
		} else if (message instanceof ChannelWindowAdjustMessage) {
			return this.handleAdjustWindowMessage(message);
		} else if (message instanceof ChannelEofMessage) {
			return this.handleEofMessage(message);
		} else if (message instanceof ChannelOpenMessage) {
			return this.handleOpenMessage(message, cancellation);
		} else if (message instanceof ChannelCloseMessage) {
			return this.handleCloseMessage(message);
		} else if (message instanceof ChannelOpenConfirmationMessage) {
			return this.handleOpenConfirmationMessage(message, cancellation);
		} else if (message instanceof ChannelOpenFailureMessage) {
			return this.handleOpenFailureMessage(message);
		} else if (message instanceof ChannelRequestMessage) {
			return this.handleRequestMessage(message, cancellation);
		} else if (message instanceof ChannelSuccessMessage) {
			return this.handleSuccessMessage(message);
		} else if (message instanceof ChannelFailureMessage) {
			return this.handleFailureMessage(message);
		} else {
			throw new Error(`Message not implemented: ${message}`);
		}
	}

	private async handleOpenMessage(
		message: ChannelOpenMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		const senderChannel = message.senderChannel;
		if (!this.session.canAcceptRequests) {
			this.trace(
				TraceLevel.Warning,
				SshTraceEventIds.channelOpenFailed,
				'Channel open request blocked because the session is not yet authenticated.',
			);
			const openFailureMessage = new ChannelOpenFailureMessage();
			openFailureMessage.recipientChannel = senderChannel;
			openFailureMessage.reasonCode = SshChannelOpenFailureReason.administrativelyProhibited;
			openFailureMessage.description = 'Authenticate before opening channels.';
			await this.session.sendMessage(openFailureMessage, cancellation);
			return;
		} else if (!message.channelType) {
			const openFailureMessage = new ChannelOpenFailureMessage();
			openFailureMessage.recipientChannel = senderChannel;
			openFailureMessage.reasonCode = SshChannelOpenFailureReason.unknownChannelType;
			openFailureMessage.description = 'Channel type not specified.';
			await this.session.sendMessage(openFailureMessage, cancellation);
			return;
		}

		// Save a copy of the message because its buffer will be overwitten by the next receive.
		message = message.convertTo(new ChannelOpenMessage(), true);

		// The confirmation message may be reassigned if the opening task returns a custom message.
		let confirmationMessage = new ChannelOpenConfirmationMessage();

		const channelId = ++this.channelCounter;
		const channel = new SshChannel(
			this,
			message.channelType!,
			channelId,
			senderChannel!,
			message.maxWindowSize!,
			message.maxPacketSize!,
			message,
			confirmationMessage,
		);

		let responseMessage: ChannelMessage;
		const args = new SshChannelOpeningEventArgs(message, channel, true);
		try {
			await this.session.handleChannelOpening(args, cancellation);
			if (args.openingPromise) {
				responseMessage = await args.openingPromise;
			} else if (args.failureReason !== SshChannelOpenFailureReason.none) {
				const failureMessage = new ChannelOpenFailureMessage();
				failureMessage.reasonCode = args.failureReason;
				failureMessage.description = args.failureDescription ?? undefined;
				responseMessage = failureMessage;
			} else {
				responseMessage = confirmationMessage;
			}
		} catch (e) {
			channel.dispose();
			throw e;
		}

		if (responseMessage instanceof ChannelOpenFailureMessage) {
			responseMessage.recipientChannel = senderChannel;
			try {
				await this.session.sendMessage(responseMessage, cancellation);
			} finally {
				channel.dispose();
			}
			return;
		}

		// The session might have been closed while opening the channel.
		if (this.session.isClosed) {
			channel.dispose();
			return;
		}

		// Prevent any changes to the channel max window size after sending the value in the
		// open confirmation message.
		channel.isMaxWindowSizeLocked = true;

		this.channelMap.set(channel.channelId, channel);

		confirmationMessage = <ChannelOpenConfirmationMessage>responseMessage;
		confirmationMessage.recipientChannel = channel.remoteChannelId;
		confirmationMessage.senderChannel = channel.channelId;
		confirmationMessage.maxWindowSize = channel.maxWindowSize;
		confirmationMessage.maxPacketSize = channel.maxPacketSize;
		confirmationMessage.rewrite();

		channel.openConfirmationMessage = confirmationMessage;
		await this.session.sendMessage(confirmationMessage, cancellation);

		// Check if there are any accept operations waiting on this channel type.
		let accepted = false;
		const list = this.pendingAcceptChannels.get(channel.channelType);
		while (list && list.length > 0) {
			const acceptCompletionSource = list.shift();
			acceptCompletionSource!.resolve(channel);
			accepted = true;
			break;
		}

		if (!accepted) {
			this.nonAcceptedChannels.set(channel.channelId, channel);
		}

		this.onChannelOpenCompleted(channel.channelId, channel);
		channel.enableSending();
	}

	private handleCloseMessage(message: ChannelCloseMessage): void {
		const channel = this.findChannelById(message.recipientChannel!);
		if (channel) {
			channel.handleClose();
		}
	}

	private async handleOpenConfirmationMessage(
		message: ChannelOpenConfirmationMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		let completionSource: PromiseCompletionSource<SshChannel> | null = null;

		let openMessage: ChannelOpenMessage;
		const pendingChannel = this.pendingChannels.get(message.recipientChannel!);
		if (pendingChannel) {
			openMessage = pendingChannel.openMessage;
			completionSource = pendingChannel.completionSource;
			if (pendingChannel.cancellationRegistration) {
				pendingChannel.cancellationRegistration.dispose();
			}
			this.pendingChannels.delete(message.recipientChannel!);
		} else if (this.channelMap.has(message.recipientChannel!)) {
			throw new Error('Duplicate channel ID.');
		} else {
			throw new Error('Channel confirmation was not requested.');
		}

		// Save a copy of the message because its buffer will be overwitten by the next receive.
		message = message.convertTo(new ChannelOpenConfirmationMessage(), true);

		const channel = new SshChannel(
			this,
			openMessage.channelType || SshChannel.sessionChannelType,
			message.recipientChannel!,
			message.senderChannel!,
			message.maxWindowSize!,
			message.maxPacketSize!,
			openMessage,
			message,
		);

		// Set the channel max window size property to match the value sent in the open message,
		// (if specified) and lock it to prevent any further changes.
		if (typeof openMessage.maxWindowSize === 'number') {
			channel.maxWindowSize = openMessage.maxWindowSize;
		}
		channel.isMaxWindowSizeLocked = true;

		this.channelMap.set(channel.channelId, channel);

		const args = new SshChannelOpeningEventArgs(openMessage, channel, false);
		await this.session.handleChannelOpening(args, cancellation);

		if (completionSource) {
			if (args.failureReason === SshChannelOpenFailureReason.none) {
				completionSource.resolve(channel);
			} else {
				completionSource.reject(
					new SshChannelError(
						args.failureDescription ?? 'Channel open failure.',
						args.failureReason,
					),
				);
				return;
			}
		} else {
			this.onChannelOpenCompleted(channel.channelId, channel);
		}

		channel.enableSending();
	}

	private handleOpenFailureMessage(message: ChannelOpenFailureMessage): void {
		let completionSource: PromiseCompletionSource<SshChannel> | null = null;

		const pendingChannel = this.pendingChannels.get(message.recipientChannel!);
		if (pendingChannel) {
			completionSource = pendingChannel.completionSource;
			if (pendingChannel.cancellationRegistration) {
				pendingChannel.cancellationRegistration.dispose();
			}
			this.pendingChannels.delete(message.recipientChannel!);
		}

		if (completionSource != null) {
			completionSource.reject(
				new SshChannelError(
					message.description || 'Channel open rejected.',
					message.reasonCode,
				),
			);
		} else {
			this.onChannelOpenCompleted(message.recipientChannel!, null);
		}
	}

	private async handleRequestMessage(
		message: ChannelRequestMessage,
		cancellation?: CancellationToken,
	): Promise<void> {
		const channel = this.tryGetChannelForMessage(message);
		if (!channel) return;

		await channel.handleRequest(message, cancellation);
	}

	private handleSuccessMessage(message: ChannelSuccessMessage) {
		const channel = this.tryGetChannelForMessage(message);
		channel?.handleResponse(true);
	}

	private handleFailureMessage(message: ChannelFailureMessage) {
		const channel = this.tryGetChannelForMessage(message);
		channel?.handleResponse(false);
	}

	private handleDataMessage(message: ChannelDataMessage): void {
		const channel = this.tryGetChannelForMessage(message);
		channel?.handleDataReceived(message.data!);
	}

	private handleExtendedDataMessage(message: ChannelExtendedDataMessage): void {
		const channel = this.tryGetChannelForMessage(message);
		channel?.handleExtendedDataReceived(new SshExtendedDataEventArgs(message.dataTypeCode!, message.data!));
	}

	private handleAdjustWindowMessage(message: ChannelWindowAdjustMessage): void {
		const channel = this.tryGetChannelForMessage(message);
		channel?.adjustRemoteWindow(message.bytesToAdd!);
	}

	private handleEofMessage(message: ChannelEofMessage): void {
		const channel = this.findChannelById(message.recipientChannel!);
		channel?.handleEof();
	}

	private onChannelOpenCompleted(channelId: number, channel: SshChannel | null) {
		if (channel) {
			this.trace(
				TraceLevel.Info,
				SshTraceEventIds.channelOpened,
				`${this.session} ChannelOpenCompleted(${channel})`,
			);
		} else {
			this.trace(
				TraceLevel.Warning,
				SshTraceEventIds.channelOpenFailed,
				`${this.session} ChannelOpenCompleted(${channelId} failed)`,
			);
		}
	}

	/**
	 * Gets the channel object based on the message `recipientChannel` property.
	 * Logs a warning if the channel was not found.
	 */
	private tryGetChannelForMessage(channelMessage: ChannelMessage): SshChannel | null {
		const channel = this.findChannelById(channelMessage.recipientChannel!);
		if (!channel) {
			const messageString =
				channelMessage instanceof ChannelDataMessage
					? 'channel data message'
					: channelMessage.toString();
			this.trace(
				TraceLevel.Warning,
				SshTraceEventIds.channelRequestFailed,
				`Invalid channel ID ${channelMessage.recipientChannel} in ${messageString}.`,
			);
		}
		return channel;
	}

	private findChannelById(id: number): SshChannel | null {
		const channel = this.channelMap.get(id) ?? null;
		return channel;
	}

	/* @internal */
	public removeChannel(channel: SshChannel) {
		this.channelMap.delete(channel.channelId);
		this.pendingChannels.delete(channel.channelId);
	}
}
