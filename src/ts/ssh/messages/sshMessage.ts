//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { SshDataReader, SshDataWriter } from '../io/sshData';
import { SshSessionConfiguration } from '../sshSessionConfiguration';

export interface SshMessageConstructor<T extends SshMessage = SshMessage> {
	new (): T;
}

export abstract class SshMessage {
	public get messageType(): number {
		return 0;
	}

	protected rawBytes?: Buffer;

	public toBuffer(): Buffer {
		const writer = new SshDataWriter(Buffer.alloc(16));
		this.write(writer);
		return writer.toBuffer();
	}

	public read(reader: SshDataReader): void {
		this.rawBytes = reader.buffer;

		const number = reader.readByte();
		if (number !== this.messageType) {
			throw new Error(`Message type ${number} is not valid.`);
		}

		this.onRead(reader);
	}

	public write(writer: SshDataWriter): void {
		if (this.rawBytes) {
			// Piped messages are rewritten without re-serialization. This preserves any
			// unparsed extended message data. It assumes no properties of the message
			// have been modified without also updating the serialized bytes.
			writer.write(this.rawBytes);
		} else {
			writer.writeByte(this.messageType);

			this.onWrite(writer);
		}
	}

	protected onRead(reader: SshDataReader): void {
		throw new Error('Not supported.');
	}

	protected onWrite(writer: SshDataWriter): void {
		throw new Error('Not supported.');
	}

	protected validateField<T>(value: T | undefined, name: string): T {
		if (typeof value === 'undefined') {
			throw new Error(`${this.constructor.name} ${name} is required.`);
		}

		return value;
	}

	public toString() {
		return this.constructor.name;
	}

	public static readonly index = new Map<number, { new (): SshMessage }>();

	public static create(
		config: SshSessionConfiguration,
		messageType: number,
		data: Buffer,
	): SshMessage | null {
		const messageClass = config.messages.get(messageType);
		if (messageClass) {
			const message = new messageClass();
			message.read(new SshDataReader(data));
			return message;
		} else {
			return null;
		}
	}

	public convertTo<T extends SshMessage>(otherMessage: T, copy = false): T {
		const reader = new SshDataReader(copy ? Buffer.from(this.rawBytes!) : this.rawBytes!);
		otherMessage.read(reader);
		return otherMessage;
	}
}
