//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken, Disposable, Emitter } from 'vscode-jsonrpc';
import { SshSession } from '../sshSession';
import { SshChannel } from '../sshChannel';
import { SshRequestEventArgs } from '../events/sshRequestEventArgs';
import { SshChannelOpeningEventArgs } from '../events/sshChannelOpeningEventArgs';
import { SessionRequestMessage } from '../messages/transportMessages';
import { ChannelMessage, ChannelRequestMessage } from '../messages/connectionMessages';
import { SshMessage } from '../messages/sshMessage';
import { Trace } from '../trace';

/**
 * An `SshService` subclass must provide a constructor that takes an `SshSession`
 * and optional config object.
 */
export interface SshServiceConstructor<T extends SshService = SshService> {
	new (session: SshSession, config?: any): T;
}

/**
 * Base class for SSH session services that handle incoming requests.
 *
 * Services can be on either the server side or the client side, because either side may
 * send requests to the other's services.
 *
 * Service subclasses must have one or more `serviceActivation` decorators applied to them to
 * declare the type(s) of requests that cause the service to be activated. Only one instance
 * of each service type gets activated for a session, even if there are multiple activation
 * rules. After activation, a service remains active for the duration of the session,
 * handling any additional requests, until it is disposed when the session is disposed.
 *
 * To enable activation of a service, add the service type to
 * `SshSessionConfiguration.services`. When a service is activated, the session raises a
 * `SshSession.serviceActivated` event.
 */
export class SshService implements Disposable {
	private disposed: boolean = false;

	public constructor(public readonly session: SshSession) {
		if (!(session instanceof SshSession)) {
			// Other packages provide services that inherit from SshService. When they do, they
			// reference the SshSession type from a specific version of this package. But at runtime,
			// the service may be activated with a session from a different version of this package,
			// if there are multiple instances due to version mismatches. Multiple instances of SSH
			// types causes problems, so it's best to detect the error at initialization time.
			throw new TypeError(
				'Session is not an instance of SshSession. ' +
					'(This may be due to a version mismatch between SSH packages.)',
			);
		}
	}

	protected get trace(): Trace {
		return this.session.trace;
	}

	public dispose(): void {
		if (this.disposed) return;
		this.disposed = true;
		this.disposedEmitter.fire();
	}

	private readonly disposedEmitter = new Emitter<void>();
	public readonly onDisposed = this.disposedEmitter.event;

	/**
	 * Services that are activated via session requests must override this method to handle
	 * incoming session requests.
	 *
	 * Implementations must set `SshRequestEventArgs.isAuthorized` or
	 * `SshRequestEventArgs.responsePromise` to indicate whether the request was allowed.
	 */
	protected async onSessionRequest(
		request: SshRequestEventArgs<SessionRequestMessage>,
		cancellation?: CancellationToken,
	): Promise<void> {
		this.session.raiseSessionRequest(request);
	}

	/**
	 * Services that are activated via channel types must override this method to handle
	 * incoming requests to open a channel.
	 *
	 * Implementations may set `SshChannelOpeningEventArgs.failureReason` or
	 * `SshChannelOpeningEventArgs.openingPromise` to block opening of the channel.
	 * The default behavior allows the channel to open.
	 *
	 * Requests on the opened channel will not be directed to `onChannelRequest`
	 * unless the service also declares activation on specific channel request(s). Otherwise,
	 * an implementation of this method may add any event-handlers to the
	 * `SshChannelOpeningEventArgs.channel` including a request event handler.
	 */
	protected async onChannelOpening(
		request: SshChannelOpeningEventArgs,
		cancellation?: CancellationToken,
	): Promise<ChannelMessage> {
		if (!request) throw new TypeError('Request is required.');

		return this.session.handleChannelOpening(request, cancellation, false);
	}

	/**
	 * Services that are activated via channel requests must override this method to handle
	 * incoming channel requests.
	 *
	 * Implementations must set `SshRequestEventArgs.isAuthorized` or
	 * `SshRequestEventArgs.responsePromise` to indicate whether the request was allowed.
	 */
	protected async onChannelRequest(
		channel: SshChannel,
		request: SshRequestEventArgs<ChannelRequestMessage>,
		cancellation?: CancellationToken,
	): Promise<void> {}

	/**
	 * Sends any message.
	 */
	protected async sendMessage(message: SshMessage, cancellation?: CancellationToken) {
		await this.session.sendMessage(message, cancellation);
	}
}
