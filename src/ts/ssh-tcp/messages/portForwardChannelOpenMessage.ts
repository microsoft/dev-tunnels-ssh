//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { ChannelOpenMessage, SshDataReader, SshDataWriter } from '@microsoft/dev-tunnels-ssh';

export class PortForwardChannelOpenMessage extends ChannelOpenMessage {
	public host: string = '';
	public port: number = 0;
	public originatorIPAddress: string = '';
	public originatorPort: number = 0;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		this.host = reader.readString('ascii');
		this.port = reader.readUInt32();
		this.originatorIPAddress = reader.readString('ascii');
		this.originatorPort = reader.readUInt32();
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeString(this.validateField(this.host, 'host'), 'ascii');
		writer.writeUInt32(this.validateField(this.port, 'port'));
		writer.writeString(this.originatorIPAddress || '', 'ascii');
		writer.writeUInt32(this.originatorPort || 0);
	}

	public toString() {
		return `${super.toString()} (host=${this.host} port=${this.port})`;
	}
}
