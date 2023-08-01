//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { SshMessage } from './sshMessage';
import { SshDataReader, SshDataWriter, formatBuffer } from '../io/sshData';

export abstract class ConnectionMessage extends SshMessage {}

export abstract class ChannelMessage extends ConnectionMessage {
	private recipientChannelValue?: number;

	public get recipientChannel(): number | undefined {
		return this.recipientChannelValue;
	}

	public set recipientChannel(value: number | undefined) {
		if (value !== this.recipientChannelValue) {
			this.recipientChannelValue = value;

			if (this.rawBytes) {
				// The recipientChannel can be updated without re-serializing the message.
				// This supports piping channel messages with re-mapped channel IDs.
				// The recipientChannel field follows the 1-byte message type.
				SshDataWriter.writeUInt32(this.rawBytes, 1, value ?? 0);
			}
		}
	}

	protected onRead(reader: SshDataReader): void {
		this.recipientChannel = reader.readUInt32();
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeUInt32(this.validateField(this.recipientChannel, 'recipient channel'));
	}

	public toString() {
		return `${super.toString()} (recipientChannel=${this.recipientChannel})`;
	}
}

export class ChannelOpenMessage extends ConnectionMessage {
	/* @internal */
	public static readonly defaultMaxPacketSize = 32 * 1024;
	/* @internal */
	public static readonly defaultMaxWindowSize = 1024 * 1024;

	public get messageType(): number {
		return 90;
	}

	public channelType?: string;

	private senderChannelValue?: number;

	public get senderChannel(): number | undefined {
		return this.senderChannelValue;
	}

	public set senderChannel(value: number | undefined) {
		if (value !== this.senderChannelValue) {
			this.senderChannelValue = value;

			if (this.rawBytes && this.channelType) {
				// The senderChannel can be updated without re-serializing the message.
				// This supports piping channel messages with re-mapped channel IDs.
				// The senderChannel field follows the 1-byte message type and
				// length-prefixed channelType string.
				SshDataWriter.writeUInt32(this.rawBytes, 1 + 4 + this.channelType.length, value ?? 0);
			}
		}
	}

	public maxWindowSize?: number;
	public maxPacketSize?: number;

	protected onRead(reader: SshDataReader): void {
		this.channelType = reader.readString('ascii');
		this.senderChannel = reader.readUInt32();
		this.maxWindowSize = reader.readUInt32();
		this.maxPacketSize = reader.readUInt32();
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeString(this.validateField(this.channelType, 'channel type'), 'ascii');
		writer.writeUInt32(this.validateField(this.senderChannel, 'sender channel'));
		writer.writeUInt32(this.maxWindowSize || ChannelOpenMessage.defaultMaxWindowSize);
		writer.writeUInt32(this.maxPacketSize || ChannelOpenMessage.defaultMaxPacketSize);
	}

	public toString() {
		return `${super.toString()}(channelType=${this.channelType}, senderChannel=${
			this.senderChannel
		})`;
	}
}

export class ChannelOpenConfirmationMessage extends ChannelMessage {
	public get messageType(): number {
		return 91;
	}

	public senderChannel?: number;
	public maxWindowSize?: number;
	public maxPacketSize?: number;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		this.senderChannel = reader.readUInt32();
		this.maxWindowSize = reader.readUInt32();
		this.maxPacketSize = reader.readUInt32();
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeUInt32(this.validateField(this.senderChannel, 'sender channel'));
		writer.writeUInt32(this.validateField(this.maxWindowSize, 'max window size'));
		writer.writeUInt32(this.validateField(this.maxPacketSize, 'max packet size'));
	}

	public toString() {
		return `${super.toString()}(senderChannel=${this.senderChannel})`;
	}
}

export enum SshChannelOpenFailureReason {
	none = 0, // Not used by protocol
	administrativelyProhibited = 1,
	connectFailed = 2,
	unknownChannelType = 3,
	resourceShortage = 4,
}

export class ChannelOpenFailureMessage extends ChannelMessage {
	public get messageType(): number {
		return 92;
	}

	public reasonCode?: SshChannelOpenFailureReason;
	public description?: string;
	public language?: string;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		this.reasonCode = reader.readUInt32();
		this.description = reader.readString('utf8');
		this.language = reader.readString('ascii');
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeUInt32(this.validateField(this.reasonCode, 'reason code'));
		writer.writeString(this.description || '', 'utf8');
		writer.writeString(this.language || 'en', 'ascii');
	}

	public toString() {
		return `${super.toString()} (${SshChannelOpenFailureReason[this.reasonCode || 0]}: ${
			this.description
		})`;
	}
}

export class ChannelWindowAdjustMessage extends ChannelMessage {
	public get messageType(): number {
		return 93;
	}

	public bytesToAdd?: number;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		this.bytesToAdd = reader.readUInt32();
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeUInt32(this.validateField(this.bytesToAdd, 'bytes to add'));
	}

	public toString() {
		return `${super.toString()} (bytesToAdd=${this.bytesToAdd})`;
	}
}

export class ChannelDataMessage extends ChannelMessage {
	public get messageType(): number {
		return 94;
	}

	public data?: Buffer;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		this.data = reader.readBinary();
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeBinary(this.validateField(this.data, 'data'));
	}

	public toString() {
		return this.data ? formatBuffer(this.data, '') : '[0]';
	}
}

export class ChannelExtendedDataMessage extends ChannelMessage {
	public get messageType(): number {
		return 95;
	}

	public dataTypeCode?: number;
	public data?: Buffer;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		this.dataTypeCode = reader.readUInt32();

		this.data = reader.readBinary();
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeUInt32(this.validateField(this.dataTypeCode, 'data type code'));
		writer.writeBinary(this.validateField(this.data, 'data'));
	}

	public toString() {
		return `${super.toString()} (dataTypeCode=${this.dataTypeCode}, data=${
			this.data ? formatBuffer(this.data, '') : '[0]'
		})`
	}
}

export class ChannelEofMessage extends ChannelMessage {
	public get messageType(): number {
		return 96;
	}
}

export class ChannelCloseMessage extends ChannelMessage {
	public get messageType(): number {
		return 97;
	}
}

export enum ChannelRequestType {
	command = 'exec',
	shell = 'shell',
	terminal = 'pty-req',
	signal = 'signal',
	exitSignal = 'exit-signal',
	exitStatus = 'exit-status',
}

export class ChannelRequestMessage extends ChannelMessage {
	public constructor(requestType?: ChannelRequestType | string, wantReply?: boolean) {
		super();
		this.requestType = requestType;
		this.wantReply = wantReply ?? false;
	}

	public get messageType(): number {
		return 98;
	}

	public requestType?: ChannelRequestType | string;
	public wantReply: boolean;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		this.requestType = reader.readString('ascii');
		this.wantReply = reader.readBoolean();
	}

	protected onWrite(writer: SshDataWriter): void {
		if (typeof this.recipientChannel === 'undefined') {
			// The recipient channel field may be uninitialized when sending a channel request
			// that is bundled with the channel-open request.
			this.recipientChannel = 0;
		}

		super.onWrite(writer);

		writer.writeString(this.validateField(this.requestType, 'request type'), 'ascii');
		writer.writeBoolean(this.wantReply);
	}
}

export class CommandRequestMessage extends ChannelRequestMessage {
	public command?: string;

	public constructor() {
		super();
		this.requestType = ChannelRequestType.command;
	}

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);
		this.command = reader.readString('utf8');
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);

		writer.writeString(this.validateField(this.command, 'command'), 'utf8');
	}

	public toString(): string {
		return `${super.toString()} (requestType=${this.requestType})`;
	}
}

export class ChannelSignalMessage extends ChannelRequestMessage {
	private signalValue?: string;
	private errorMessageValue?: string;
	private statusValue?: number;

	public constructor() {
		super();
	}

	public get signal(): string | undefined {
		return this.signalValue;
	}
	public set signal(value: string | undefined) {
		this.requestType = ChannelRequestType.signal;
		this.signalValue = value;
	}

	public get exitSignal(): string | undefined {
		return this.signalValue;
	}
	public set exitSignal(value: string | undefined) {
		this.requestType = ChannelRequestType.exitSignal;
		this.signalValue = value;
	}

	public get errorMessage(): string | undefined {
		return this.errorMessageValue;
	}
	public set errorMessage(value: string | undefined) {
		if (this.requestType !== ChannelRequestType.exitSignal) {
			throw new Error(
				`Error message property is only valid for ${ChannelRequestType.exitSignal} messages.`,
			);
		}

		this.errorMessageValue = value;
	}

	public get exitStatus(): number | undefined {
		return this.statusValue;
	}
	public set exitStatus(value: number | undefined) {
		this.requestType = ChannelRequestType.exitStatus;
		this.statusValue = value;
	}

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);

		switch (this.requestType) {
			case ChannelRequestType.exitStatus:
				this.exitStatus = reader.readUInt32();
				break;

			case ChannelRequestType.signal:
				this.signal = reader.readString('ascii');
				break;

			case ChannelRequestType.exitSignal:
				this.exitSignal = reader.readString('ascii');
				reader.readBoolean(); // Core dumped
				this.errorMessage = reader.readString('utf8');
				reader.readString('ascii'); // Language tag
				break;

			default:
				break;
		}
	}

	protected onWrite(writer: SshDataWriter): void {
		if (!this.requestType) {
			throw new Error('Signal message request type not set.');
		}

		this.wantReply = false;

		super.onWrite(writer);

		switch (this.requestType) {
			case ChannelRequestType.exitStatus:
				writer.writeUInt32(this.validateField(this.exitStatus, 'exit status'));
				break;

			case ChannelRequestType.signal:
				writer.writeString(this.validateField(this.signal, 'signal'), 'ascii');
				break;

			case ChannelRequestType.exitSignal:
				writer.writeString(this.validateField(this.exitSignal, 'exit signal'), 'ascii');
				writer.writeBoolean(false); // Core dumped
				writer.writeString(this.errorMessage || '', 'utf8');
				writer.writeString('', 'ascii'); // Language tag
				break;

			default:
				throw new Error(`Unknown signal message request type: ${this.requestType}`);
		}
	}
}

export class ChannelSuccessMessage extends ChannelMessage {
	public get messageType(): number {
		return 99;
	}
}

export class ChannelFailureMessage extends ChannelMessage {
	public get messageType(): number {
		return 100;
	}
}

SshMessage.index.set(90, ChannelOpenMessage);
SshMessage.index.set(91, ChannelOpenConfirmationMessage);
SshMessage.index.set(92, ChannelOpenFailureMessage);
SshMessage.index.set(93, ChannelWindowAdjustMessage);
SshMessage.index.set(94, ChannelDataMessage);
SshMessage.index.set(95, ChannelExtendedDataMessage);
SshMessage.index.set(96, ChannelEofMessage);
SshMessage.index.set(97, ChannelCloseMessage);
SshMessage.index.set(98, ChannelRequestMessage);
SshMessage.index.set(99, ChannelSuccessMessage);
SshMessage.index.set(100, ChannelFailureMessage);
