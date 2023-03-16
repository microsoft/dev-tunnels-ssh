//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshChannel } from '../sshChannel';
import { ChannelMessage, ChannelOpenMessage, SshChannelOpenFailureReason } from '../messages/connectionMessages';
import { CancellationToken } from 'vscode-jsonrpc';

export class SshChannelOpeningEventArgs {
	public constructor(
		public readonly request: ChannelOpenMessage,
		public readonly channel: SshChannel,
		public readonly isRemoteRequest: boolean,
		cancellation?: CancellationToken,
	) {
		if (!request) throw new TypeError('A channel open message is required.');
		if (!channel) throw new TypeError('A channel is required.');
		this.cancellationValue = cancellation ?? CancellationToken.None;
	}

	/**
	 * Specifies a reason that the channel could not be opened.
	 *
	 * The handler of this event can optionally block the channel by setting
	 * a failure reason. If the event is not handled or the reason remains
	 * `none` then the channel is allowed to open.
	 */
	public failureReason: SshChannelOpenFailureReason = SshChannelOpenFailureReason.none;

	/**
	 * Optional message to go along with a failure reason.
	 */
	public failureDescription: string | null = null;

	/**
	 * Gets or sets an optional promise that blocks opening the channel until the promise is
	 * resolved. An event-handler may assign a promise to this property to handle the channel
	 * opening as an asynchronous operation.
	 */
	public openingPromise?: Promise<ChannelMessage>;

	/**
	 * Gets a token that is cancelled if the session ends before the request handler
	 * completes.
	 */
	public get cancellation(): CancellationToken {
		return this.cancellationValue;
	}

	/* @internal */
	public set cancellation(value: CancellationToken) {
		this.cancellationValue = value;
	}

	private cancellationValue!: CancellationToken;

	public toString() {
		return `${this.channel.toString()}${
			this.failureReason ? ' ' + SshChannelOpenFailureReason[this.failureReason] : ''
		}`;
	}
}
