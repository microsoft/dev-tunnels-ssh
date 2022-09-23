//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken } from 'vscode-jsonrpc';
import { SshMessage } from '../messages/sshMessage';

export class SshRequestEventArgs<T extends SshMessage> {
	public constructor(
		public readonly requestType: string,
		public readonly request: T,
		principal: object | null,
		cancellation?: CancellationToken,
	) {
		this.principal = principal;
		this.cancellationValue = cancellation ?? CancellationToken.None;
	}

	/**
	 * Gets the principal for the session that made the request, or null if the
	 * session is not authenticated.
	 */
	public readonly principal: object | null;

	/**
	 * An event handler sets this to true if the request is valid and authorized.
	 *
	 * For async response handling, use `responsePromise` instead.
	 */
	public isAuthorized?: boolean;

	/**
	 * Gets or sets a promise to be filled in by the event handler for async request processing.
	 */
	public responsePromise?: Promise<SshMessage>;

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

	public toString(): string {
		return `RequestType: ${this.requestType}` + this.request ? ` Request: ${this.request}` : '';
	}
}
