//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshChannel } from '@microsoft/dev-tunnels-ssh';
import { ForwardedPort } from './forwardedPort';

export class ForwardedPortEventArgs {
	public constructor(public readonly port: ForwardedPort) {}

	public toString() {
		return this.port.toString();
	}
}

export class ForwardedPortChannelEventArgs extends ForwardedPortEventArgs {
	public constructor(public port: ForwardedPort, public readonly channel: SshChannel) {
		super(port);
	}

	public toString() {
		return `${this.port} ${this.channel}`;
	}
}
