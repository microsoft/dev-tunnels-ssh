//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { CancellationToken } from 'vscode-jsonrpc';
import { SshSession } from './sshSession';
import { SshChannel } from './sshChannel';
import { SshRequestEventArgs } from './events/sshRequestEventArgs';
import { SshChannelOpeningEventArgs } from './events/sshChannelOpeningEventArgs';
import { SshSessionClosedEventArgs } from './events/sshSessionClosedEventArgs';
import { SshChannelClosedEventArgs } from './events/sshChannelClosedEventArgs';
import {
	SessionRequestFailureMessage,
	SessionRequestMessage,
	SessionRequestSuccessMessage,
} from './messages/transportMessages';
import {
	ChannelFailureMessage,
	ChannelMessage,
	ChannelOpenConfirmationMessage,
	ChannelOpenFailureMessage,
	ChannelRequestMessage,
	ChannelSuccessMessage,
	SshChannelOpenFailureReason,
} from './messages/connectionMessages';
import { PromiseCompletionSource } from './util/promiseCompletionSource';
import { SshMessage } from './messages/sshMessage';
import { SshChannelError } from './errors';
import { SshTraceEventIds, TraceLevel } from './trace';

/**
 * Extension methods for piping sessions and channels.
 *
 * Note this class is not exported from the package. Instead, the piping APIs are exposed via
 * public methods on the `SshSession` and `SshChannel` classes. See those respective methods
 * for API documentation.
 */
export class PipeExtensions {
	public static async pipeSession(session: SshSession, toSession: SshSession): Promise<void> {
		if (!session) throw new TypeError('Session is required.');
		if (!toSession) throw new TypeError('Target session is required');

		const endCompletion = new PromiseCompletionSource<Promise<void>>();

		session.onRequest((e) => {
			e.responsePromise = PipeExtensions.forwardSessionRequest(e, toSession, e.cancellation);
		});
		toSession.onRequest((e) => {
			e.responsePromise = PipeExtensions.forwardSessionRequest(e, session, e.cancellation);
		});

		session.onChannelOpening((e) => {
			if (e.isRemoteRequest) {
				e.openingPromise = PipeExtensions.forwardChannel(e, toSession, e.cancellation);
			}
		});
		toSession.onChannelOpening((e) => {
			if (e.isRemoteRequest) {
				e.openingPromise = PipeExtensions.forwardChannel(e, session, e.cancellation);
			}
		});

		session.onClosed((e) => {
			endCompletion.resolve(PipeExtensions.forwardSessionClose(toSession, e));
		});
		toSession.onClosed((e) => {
			endCompletion.resolve(PipeExtensions.forwardSessionClose(session, e));
		});

		const endPromise = await endCompletion.promise;
		await endPromise;
	}

	public static async pipeChannel(channel: SshChannel, toChannel: SshChannel): Promise<void> {
		if (!channel) throw new TypeError('Channel is required.');
		if (!toChannel) throw new TypeError('Target channel is required');

		const endCompletion = new PromiseCompletionSource<Promise<void>>();
		let closed = false;

		channel.onRequest((e) => {
			e.responsePromise = PipeExtensions.forwardChannelRequest(e, toChannel, e.cancellation);
		});
		toChannel.onRequest((e) => {
			e.responsePromise = PipeExtensions.forwardChannelRequest(e, channel, e.cancellation);
		});

		channel.onDataReceived((data) => {
			void PipeExtensions.forwardData(channel, toChannel, data).catch();
		});
		toChannel.onDataReceived((data) => {
			void PipeExtensions.forwardData(toChannel, channel, data).catch();
		});

		channel.onEof(() => {
			void PipeExtensions.forwardData(channel, toChannel, Buffer.alloc(0)).catch();
		});
		toChannel.onEof(() => {
			void PipeExtensions.forwardData(toChannel, channel, Buffer.alloc(0)).catch();
		});

		channel.onExtendedDataReceived((data) => {
			void PipeExtensions.forwardExtendedData(channel, toChannel, data).catch();
		});
		toChannel.onExtendedDataReceived((data) => {
			void PipeExtensions.forwardExtendedData(toChannel, channel, data).catch();
		});

		channel.onClosed((e) => {
			if (!closed) {
				closed = true;
				endCompletion.resolve(PipeExtensions.forwardChannelClose(channel, toChannel, e));
			}
		});
		toChannel.onClosed((e) => {
			if (!closed) {
				closed = true;
				endCompletion.resolve(PipeExtensions.forwardChannelClose(toChannel, channel, e));
			}
		});

		const endTask = await endCompletion.promise;
		await endTask;
	}

	private static async forwardSessionRequest(
		e: SshRequestEventArgs<SessionRequestMessage>,
		toSession: SshSession,
		cancellation?: CancellationToken,
	): Promise<SshMessage> {
		// `SshSession.requestResponse()` always set `wantReply` to `true` internally and waits for a
		// response, but since the message buffer is cached the updated `wantReply` value is not sent.
		// Anyway, it's better to forward a no-reply message as another no-reply message, using
		// `SshSession.request()` instead.
		if (!e.request.wantReply) {
			return toSession
				.request(e.request, cancellation)
				.then(() => new SessionRequestSuccessMessage());
		}
		return toSession.requestResponse(
			e.request,
			SessionRequestSuccessMessage,
			SessionRequestFailureMessage,
			cancellation,
		);
	}

	private static async forwardChannel(
		e: SshChannelOpeningEventArgs,
		toSession: SshSession,
		cancellation?: CancellationToken,
	): Promise<ChannelMessage> {
		try {
			const toChannel = await toSession.openChannel(e.request, null, cancellation);
			void PipeExtensions.pipeChannel(e.channel, toChannel).catch();
			return new ChannelOpenConfirmationMessage();
		} catch (err) {
			if (!(err instanceof Error)) throw err;

			const failureMessage = new ChannelOpenFailureMessage();
			if (err instanceof SshChannelError) {
				failureMessage.reasonCode = err.reason ?? SshChannelOpenFailureReason.connectFailed;
			} else {
				failureMessage.reasonCode = SshChannelOpenFailureReason.connectFailed;
			}

			failureMessage.description = err.message;
			return failureMessage;
		}
	}

	private static async forwardChannelRequest(
		e: SshRequestEventArgs<ChannelRequestMessage>,
		toChannel: SshChannel,
		cancellation?: CancellationToken,
	): Promise<SshMessage> {
		e.request.recipientChannel = toChannel.remoteChannelId;
		const result = await toChannel.request(e.request, cancellation);
		return result ? new ChannelSuccessMessage() : new ChannelFailureMessage();
	}

	private static async forwardSessionClose(
		session: SshSession,
		e: SshSessionClosedEventArgs,
	): Promise<void> {
		return session.close(e.reason, e.message, e.error ?? undefined);
	}

	private static async forwardData(
		channel: SshChannel,
		toChannel: SshChannel,
		data: Buffer,
	): Promise<void> {
		// Make a copy of the buffer before sending because SshChannel.send() is an async operation
		// (it may need to wait for the window to open), while the buffer will be re-used for the
		// next message as sson as this task yields.
		const buffer = Buffer.alloc(data.length);
		data.copy(buffer);
		const promise = toChannel.send(buffer, CancellationToken.None);
		channel.adjustWindow(buffer.length);
		return promise;
	}

	private static async forwardExtendedData(
		channel: SshChannel,
		toChannel: SshChannel,
		data: Buffer,
	): Promise<void> {
		// Make a copy of the buffer before sending because SshChannel.send() is an async operation
		// (it may need to wait for the window to open), while the buffer will be re-used for the
		// next message as sson as this task yields.
		const buffer = Buffer.alloc(data.length);
		data.copy(buffer);
		const promise = toChannel.sendStderr(buffer, CancellationToken.None);
		// channel.adjustWindow(buffer.length);
		return promise;
	}

	private static async forwardChannelClose(
		fromChannel: SshChannel,
		toChannel: SshChannel,
		e: SshChannelClosedEventArgs,
	): Promise<void> {
		const message =
			`Piping channel closure.\n` +
			`Source: ${fromChannel.session} ${fromChannel}\n` +
			`Destination: ${toChannel.session} ${toChannel}\n`;
		toChannel.session.trace(TraceLevel.Verbose, SshTraceEventIds.channelClosed, message);

		if (e.error) {
			toChannel.close(e.error);
			return Promise.resolve();
		} else if (e.exitSignal) {
			return toChannel.close(e.exitSignal, e.errorMessage);
		} else if (typeof e.exitStatus === 'number') {
			return toChannel.close(e.exitStatus);
		} else {
			return toChannel.close();
		}
	}
}
