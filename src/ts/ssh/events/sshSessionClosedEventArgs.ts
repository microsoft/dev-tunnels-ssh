//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshDisconnectReason } from '../messages/transportMessages';

export class SshSessionClosedEventArgs {
	public constructor(
		public readonly reason: SshDisconnectReason,
		public readonly message: string,
		public readonly error: Error | null,
	) {
		if (!message) throw new TypeError('A disconnect message is required.');
	}

	public toString() {
		return `${SshDisconnectReason[this.reason]}: ${this.message}`;
	}
}
