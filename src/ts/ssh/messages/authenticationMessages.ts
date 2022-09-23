//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshMessage } from './sshMessage';
import { SshDataReader, SshDataWriter } from '../io/sshData';

export const enum AuthenticationMethod {
	none = 'none',
	publicKey = 'publickey',
	password = 'password',
	hostBased = 'hostbased',
}

export class AuthenticationMessage extends SshMessage {}

export class AuthenticationRequestMessage extends AuthenticationMessage {
	public get messageType(): number {
		return 50;
	}

	public username?: string;
	public serviceName?: string;
	public methodName?: AuthenticationMethod;

	protected onRead(reader: SshDataReader): void {
		this.username = reader.readString('utf8');
		this.serviceName = reader.readString('ascii');
		this.methodName = reader.readString('ascii') as AuthenticationMethod;
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeString(this.username || '', 'utf8');
		writer.writeString(this.serviceName || '', 'ascii');
		writer.writeString(this.validateField(this.methodName, 'method name'), 'ascii');
	}
}

export class PublicKeyRequestMessage extends AuthenticationRequestMessage {
	public keyAlgorithmName?: string;
	public publicKey?: Buffer;
	public clientHostname?: string;
	public clientUsername?: string;
	public signature?: Buffer;

	public payloadWithoutSignature?: Buffer;

	public constructor() {
		super();
		this.methodName = AuthenticationMethod.publicKey;
	}

	public get hasSignature(): boolean {
		return this.signature && this.signature.length > 0 ? true : false;
	}

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		const hasSignature = reader.readBoolean();
		this.keyAlgorithmName = reader.readString('ascii');
		this.publicKey = reader.readBinary();

		if (hasSignature) {
			this.signature = reader.readBinary();
			this.payloadWithoutSignature = this.rawBytes!.slice(
				0,
				this.rawBytes!.length - this.signature.length - 4,
			);
		} else {
			this.signature = undefined;
		}
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		if (!this.keyAlgorithmName) throw new Error('Key algorithm name not set.');

		if (this.methodName === AuthenticationMethod.hostBased) {
			writer.writeString(this.keyAlgorithmName, 'ascii');
			writer.writeBinary(this.publicKey || Buffer.alloc(0));
			writer.writeString(this.clientHostname ?? '', 'ascii');
			writer.writeString(this.clientUsername ?? '', 'ascii');

			if (!this.hasSignature) {
				throw new Error('A signature is required for a host-based authentcation request.');
			}

			writer.writeBinary(this.signature!);
		} else {
			writer.writeBoolean(this.hasSignature);
			writer.writeString(this.keyAlgorithmName, 'ascii');
			writer.writeBinary(this.publicKey || Buffer.alloc(0));

			if (this.hasSignature) {
				writer.writeBinary(this.signature!);
			}
		}
	}
}

export class PublicKeyOKMessage extends AuthenticationMessage {
	public get messageType(): number {
		return 60;
	}

	public keyAlgorithmName?: string;
	public publicKey?: Buffer;

	protected onRead(reader: SshDataReader): void {
		this.keyAlgorithmName = reader.readString('ascii');
		this.publicKey = reader.readBinary();
	}

	protected onWrite(writer: SshDataWriter): void {
		if (!this.keyAlgorithmName) throw new Error('Key algorithm name not set.');
		if (!this.publicKey) throw new Error('Public key not set.');

		writer.writeString(this.keyAlgorithmName, 'ascii');
		writer.writeBinary(this.publicKey);
	}
}

export class PasswordRequestMessage extends AuthenticationRequestMessage {
	public password?: string | null;

	public constructor() {
		super();
		this.methodName = AuthenticationMethod.password;
	}

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		reader.readBoolean();
		this.password = reader.readString('utf8');
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeBoolean(false);
		writer.writeString(this.password || '', 'utf8');
	}
}

export class AuthenticationFailureMessage extends AuthenticationMessage {
	public get messageType(): number {
		return 51;
	}

	public methodNames?: string[];

	public partialSuccess: boolean = false;

	protected onRead(reader: SshDataReader): void {
		this.methodNames = reader.readList('ascii');
		this.partialSuccess = reader.readBoolean();
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeList(this.methodNames || [], 'ascii');
		writer.writeBoolean(this.partialSuccess);
	}
}

export class AuthenticationSuccessMessage extends AuthenticationMessage {
	public get messageType(): number {
		return 52;
	}

	protected onRead(reader: SshDataReader): void {}

	protected onWrite(writer: SshDataWriter): void {}
}

SshMessage.index.set(50, AuthenticationRequestMessage);
SshMessage.index.set(51, AuthenticationFailureMessage);
SshMessage.index.set(52, AuthenticationSuccessMessage);
