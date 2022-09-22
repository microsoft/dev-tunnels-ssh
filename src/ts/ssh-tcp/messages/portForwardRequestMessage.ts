//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SessionRequestMessage, SshDataReader, SshDataWriter } from '@microsoft/dev-tunnels-ssh';
import { PortForwardingService } from '../services/portForwardingService';

export class PortForwardRequestMessage extends SessionRequestMessage {
	public addressToBind: string = '';
	public port: number = 0;

	public constructor() {
		super();
		this.requestType = PortForwardingService.portForwardRequestType;
		this.wantReply = true;
	}

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		this.addressToBind = reader.readString('ascii');
		this.port = reader.readUInt32();
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeString(this.validateField(this.addressToBind, 'address'), 'ascii');
		writer.writeUInt32(this.validateField(this.port, 'port'));
	}

	public toString() {
		return `${super.toString()} (addressToBind=${this.addressToBind} port=${this.port})`;
	}
}
