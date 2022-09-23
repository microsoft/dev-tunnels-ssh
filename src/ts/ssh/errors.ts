//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshDisconnectReason, SshReconnectFailureReason } from './messages/transportMessages';
import { SshChannelOpenFailureReason } from './messages/connectionMessages';
import { Disposable } from 'vscode-jsonrpc';

export class SshConnectionError extends Error {
	constructor(message?: string, public readonly reason?: SshDisconnectReason) {
		super(message);
	}
}

export class SshReconnectError extends Error {
	constructor(message?: string, public readonly reason?: SshReconnectFailureReason) {
		super(message);
	}
}

export class SshChannelError extends Error {
	constructor(message?: string, public readonly reason?: SshChannelOpenFailureReason) {
		super(message);
	}
}

export class ObjectDisposedError extends Error {
	public constructor(objectOrMessage?: Disposable | Function | string) {
		let message: string;

		if (typeof objectOrMessage === 'string') {
			// Custom message.
			message = <string>objectOrMessage;
		} else if (typeof objectOrMessage === 'function') {
			// Constructor function (class name).
			message = (<Function>objectOrMessage).name + ' disposed.';
		} else {
			// Disposable object - get its class name.
			message = (objectOrMessage?.constructor?.name ?? 'Object ') + ' disposed.';
		}

		super(message);
	}
}
