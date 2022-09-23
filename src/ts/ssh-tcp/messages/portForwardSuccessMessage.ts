//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import {
	SessionRequestSuccessMessage,
	SshDataReader,
	SshDataWriter,
} from '@microsoft/dev-tunnels-ssh';

export class PortForwardSuccessMessage extends SessionRequestSuccessMessage {
	public port: number = 0;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		if (reader.available >= 4) {
			this.port = reader.readUInt32();
		}
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeUInt32(this.validateField(this.port, 'port'));
	}

	public toString() {
		return `${super.toString()} (port=${this.port})`;
	}
}
