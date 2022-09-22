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
	ChannelRequestMessage,
	ChannelSuccessMessage,
	SshChannelOpenFailureReason,
} from './messages/connectionMessages';
import { PromiseCompletionSource } from './util/promiseCompletionSource';
import { SshMessage } from './messages/sshMessage';
import { SshChannelError } from './errors';

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
			const _ = PipeExtensions.forwardData(channel, toChannel, data);
		});
		toChannel.onDataReceived((data) => {
			const _ = PipeExtensions.forwardData(toChannel, channel, data);
		});

		channel.onClosed((e) => {
			if (!closed) {
				closed = true;
				endCompletion.resolve(PipeExtensions.forwardChannelClose(toChannel, e));
			}
		});
		toChannel.onClosed((e) => {
			if (!closed) {
				closed = true;
				endCompletion.resolve(PipeExtensions.forwardChannelClose(channel, e));
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
		return await toSession.requestResponse(
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
	): Promise<void> {
		try {
			const toChannel = await toSession.openChannel(e.request, null, cancellation);
			const _ = PipeExtensions.pipeChannel(e.channel, toChannel);
		} catch (err) {
			if (!(err instanceof Error)) throw err;

			if (err instanceof SshChannelError) {
				e.failureReason = err.reason ?? SshChannelOpenFailureReason.connectFailed;
			} else {
				e.failureReason = SshChannelOpenFailureReason.connectFailed;
			}

			e.failureDescription = err.message;
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
		await toChannel.send(data, CancellationToken.None);
		channel.adjustWindow(data.length);
	}

	private static async forwardChannelClose(
		channel: SshChannel,
		e: SshChannelClosedEventArgs,
	): Promise<void> {
		if (e.error) {
			channel.close(e.error);
			return Promise.resolve();
		} else if (e.exitSignal) {
			return channel.close(e.exitSignal, e.errorMessage);
		} else if (typeof e.exitStatus === 'number') {
			return channel.close(e.exitStatus);
		} else {
			return channel.close();
		}
	}
}
