//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { SshMessage } from './sshMessage';
import { SshDataWriter, SshDataReader } from '../io/sshData';
import { SshAlgorithms } from '../algorithms/sshAlgorithms';

export class KeyExchangeMessage extends SshMessage {}

export class KeyExchangeInitMessage extends KeyExchangeMessage {
	public get messageType(): number {
		return 20;
	}

	public cookie?: Buffer;
	public keyExchangeAlgorithms?: string[];
	public serverHostKeyAlgorithms?: string[];
	public encryptionAlgorithmsClientToServer?: string[];
	public encryptionAlgorithmsServerToClient?: string[];
	public macAlgorithmsClientToServer?: string[];
	public macAlgorithmsServerToClient?: string[];
	public compressionAlgorithmsClientToServer?: string[];
	public compressionAlgorithmsServerToClient?: string[];
	public languagesClientToServer?: string[];
	public languagesServerToClient?: string[];
	public firstKexPacketFollows?: boolean;
	public reserved?: number;

	protected onRead(reader: SshDataReader): void {
		this.cookie = reader.read(16);
		this.keyExchangeAlgorithms = reader.readList('ascii');
		this.serverHostKeyAlgorithms = reader.readList('ascii');
		this.encryptionAlgorithmsClientToServer = reader.readList('ascii');
		this.encryptionAlgorithmsServerToClient = reader.readList('ascii');
		this.macAlgorithmsClientToServer = reader.readList('ascii');
		this.macAlgorithmsServerToClient = reader.readList('ascii');
		this.compressionAlgorithmsClientToServer = reader.readList('ascii');
		this.compressionAlgorithmsServerToClient = reader.readList('ascii');
		this.languagesClientToServer = reader.readList('ascii');
		this.languagesServerToClient = reader.readList('ascii');
		this.firstKexPacketFollows = reader.readBoolean();
		this.reserved = reader.readUInt32();
	}

	protected onWrite(writer: SshDataWriter): void {
		if (!this.cookie) {
			this.cookie = Buffer.alloc(16);
			SshAlgorithms.random.getBytes(this.cookie);
		}

		writer.write(this.cookie);
		writer.writeList(this.keyExchangeAlgorithms || [], 'ascii');
		writer.writeList(this.serverHostKeyAlgorithms || [], 'ascii');
		writer.writeList(this.encryptionAlgorithmsClientToServer || [], 'ascii');
		writer.writeList(this.encryptionAlgorithmsServerToClient || [], 'ascii');
		writer.writeList(this.macAlgorithmsClientToServer || [], 'ascii');
		writer.writeList(this.macAlgorithmsServerToClient || [], 'ascii');
		writer.writeList(this.compressionAlgorithmsClientToServer || [], 'ascii');
		writer.writeList(this.compressionAlgorithmsServerToClient || [], 'ascii');
		writer.writeList(this.languagesClientToServer || [], 'ascii');
		writer.writeList(this.languagesServerToClient || [], 'ascii');
		writer.writeBoolean(
			this.validateField(this.firstKexPacketFollows, 'first KEX package follows'),
		);
		writer.writeUInt32(this.reserved || 0);
	}
}

export class KeyExchangeDhInitMessage extends KeyExchangeMessage {
	public get messageType(): number {
		return 30;
	}

	public e?: Buffer;

	protected onRead(reader: SshDataReader): void {
		this.e = reader.readBinary();
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeBinary(this.validateField(this.e, 'E'));
	}
}

export class KeyExchangeDhReplyMessage extends KeyExchangeMessage {
	public get messageType(): number {
		return 31;
	}

	public hostKey?: Buffer;
	public f?: Buffer;
	public signature?: Buffer;

	protected onRead(reader: SshDataReader): void {
		this.hostKey = reader.readBinary();
		this.f = reader.readBinary();
		this.signature = reader.readBinary();
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeBinary(this.validateField(this.hostKey, 'host key'));
		writer.writeBinary(this.validateField(this.f, 'F'));
		writer.writeBinary(this.validateField(this.signature, 'signature'));
	}
}

export class NewKeysMessage extends KeyExchangeMessage {
	public get messageType(): number {
		return 21;
	}

	protected onRead(reader: SshDataReader): void {}
	protected onWrite(writer: SshDataWriter): void {}
}

SshMessage.index.set(20, KeyExchangeInitMessage);
SshMessage.index.set(30, KeyExchangeDhInitMessage);
SshMessage.index.set(31, KeyExchangeDhReplyMessage);
SshMessage.index.set(21, NewKeysMessage);
