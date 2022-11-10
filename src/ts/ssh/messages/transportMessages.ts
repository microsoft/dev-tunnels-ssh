//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { SshMessage } from './sshMessage';
import { SshDataReader, SshDataWriter } from '../io/sshData';
import { ChannelRequestMessage } from './connectionMessages';

export enum SshDisconnectReason {
	none = 0, // Not used by protocol
	hostNotAllowedToConnect = 1,
	protocolError = 2,
	keyExchangeFailed = 3,
	reserved = 4,
	macError = 5,
	compressionError = 6,
	serviceNotAvailable = 7,
	protocolVersionNotSupported = 8,
	hostKeyNotVerifiable = 9,
	connectionLost = 10,
	byApplication = 11,
	tooManyConnections = 12,
	authCancelledByUser = 13,
	noMoreAuthMethodsAvailable = 14,
	illegalUserName = 15,
}

export class DisconnectMessage extends SshMessage {
	public get messageType(): number {
		return 1;
	}

	public reasonCode?: SshDisconnectReason;
	public description?: string;
	public language?: string | null;

	protected onRead(reader: SshDataReader): void {
		this.reasonCode = reader.readUInt32();
		this.description = reader.readString('utf8');

		if (reader.available >= 4) {
			this.language = reader.readString('ascii');
		} else {
			this.language = null;
		}
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeUInt32(this.validateField(this.reasonCode, 'reason code'));
		writer.writeString(this.description || '', 'utf8');
		if (this.language) {
			writer.writeString(this.language, 'ascii');
		}
	}

	public toString() {
		return `${super.toString()} (${SshDisconnectReason[this.reasonCode || 0]}: ${
			this.description
		})`;
	}
}

export class IgnoreMessage extends SshMessage {
	public get messageType(): number {
		return 2;
	}

	protected onRead(reader: SshDataReader): void {}

	protected onWrite(writer: SshDataWriter): void {}
}

export class UnimplementedMessage extends SshMessage {
	public get messageType(): number {
		return 3;
	}

	public sequenceNumber?: number;

	public unimplementedMessageType?: number;

	protected onRead(reader: SshDataReader): void {
		this.sequenceNumber = reader.readUInt32();
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeUInt32(this.validateField(this.sequenceNumber, 'sequence number'));
	}

	public toString(): string {
		return !!this.unimplementedMessageType
			? `${super.toString()} (messageType=${this.unimplementedMessageType})`
			: `${super.toString()} (sequenceNumber=${this.sequenceNumber})`;
	}
}

export class DebugMessage extends SshMessage {
	public constructor(message?: string) {
		super();
		this.message = message;
	}

	public get messageType(): number {
		return 4;
	}

	public alwaysDisplay: boolean = false;

	public message?: string;

	public language?: string;

	protected onRead(reader: SshDataReader): void {
		this.alwaysDisplay = reader.readBoolean();
		this.message = reader.readString('utf8');
		this.language = reader.readString('ascii');
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeBoolean(this.alwaysDisplay);
		writer.writeString(this.message ?? '', 'utf8');
		writer.writeString(this.language ?? '', 'ascii');
	}

	public toString(): string {
		return `${super.toString()}: ${this.message}`;
	}
}

export class ServiceRequestMessage extends SshMessage {
	public get messageType(): number {
		return 5;
	}

	public serviceName?: string;

	protected onRead(reader: SshDataReader): void {
		this.serviceName = reader.readString('ascii');
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeString(this.validateField(this.serviceName, 'service name'), 'ascii');
	}
}

export class ServiceAcceptMessage extends SshMessage {
	public get messageType(): number {
		return 6;
	}

	public serviceName?: string;

	protected onRead(reader: SshDataReader): void {
		this.serviceName = reader.readString('ascii');
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeString(this.validateField(this.serviceName, 'service name'), 'ascii');
	}
}

export class SessionRequestMessage extends SshMessage {
	public constructor(requestType?: string, wantReply?: boolean) {
		super();
		this.requestType = requestType;
		this.wantReply = wantReply ?? false;
	}

	public get messageType(): number {
		return 80;
	}

	// e.g. "tcpip-forward" or "cancel-tcpip-forward"
	public requestType?: string;

	public wantReply: boolean;

	protected onRead(reader: SshDataReader): void {
		this.requestType = reader.readString('ascii');
		this.wantReply = reader.readBoolean();
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeString(this.validateField(this.requestType, 'request type'), 'ascii');
		writer.writeBoolean(this.wantReply);
	}

	public toString(): string {
		return `${super.toString()} (requestType=${this.requestType})`;
	}
}

export class SessionRequestSuccessMessage extends SshMessage {
	public get messageType(): number {
		return 81;
	}

	protected onRead(reader: SshDataReader): void {}

	protected onWrite(writer: SshDataWriter): void {}
}

export class SessionRequestFailureMessage extends SshMessage {
	public get messageType(): number {
		return 82;
	}

	protected onRead(reader: SshDataReader): void {}

	protected onWrite(writer: SshDataWriter): void {}
}

export class ExtensionInfoMessage extends SshMessage {
	// https://tools.ietf.org/html/draft-ietf-curdle-ssh-ext-info-15

	public static readonly serverIndicator = 'ext-info-c';
	public static readonly clientIndicator = 'ext-info-c';

	public get messageType(): number {
		return 7;
	}

	public extensionInfo: { [key: string]: string } = {};

	protected onRead(reader: SshDataReader): void {
		const count = reader.readUInt32();
		this.extensionInfo = {};

		for (let i = 0; i < count; i++) {
			const key = reader.readString('ascii');
			const value = reader.readString('utf8');
			this.extensionInfo[key] = value;
		}
	}

	protected onWrite(writer: SshDataWriter): void {
		const keys = Object.keys(this.extensionInfo);
		writer.writeUInt32(keys.length);
		for (let key of keys) {
			writer.writeString(key, 'ascii');
			writer.writeString(this.extensionInfo[key] || '', 'utf8');
		}
	}

	public toString(): string {
		let extensionInfoDetails = '';

		for (const [key, value] of Object.entries(this.extensionInfo)) {
			if (extensionInfoDetails) {
				extensionInfoDetails += '; ';
			}

			extensionInfoDetails += key;

			if (value) {
				extensionInfoDetails += '=' + value;
			}
		}

		return `${super.toString()} (${extensionInfoDetails})`;
	}
}

export class SessionChannelRequestMessage extends SessionRequestMessage {
	public senderChannel?: number;
	public request?: ChannelRequestMessage;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);
		this.senderChannel = reader.readUInt32();

		const request = new ChannelRequestMessage();
		request.read(reader);
		this.request = request;
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);
		writer.writeUInt32(this.validateField(this.senderChannel, 'sender channel'));
		this.validateField(this.request, 'request message').write(writer);
	}
}

export class SessionReconnectRequestMessage extends SessionRequestMessage {
	public clientReconnectToken?: Buffer;
	public lastReceivedSequenceNumber?: number;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);
		this.clientReconnectToken = reader.readBinary();
		this.lastReceivedSequenceNumber = reader.readUInt64();
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);
		writer.writeBinary(this.validateField(this.clientReconnectToken, 'clientReconnectToken'));
		writer.writeUInt64(
			this.validateField(this.lastReceivedSequenceNumber, 'lastReceivedSequenceNumber'),
		);
	}
}

export class SessionReconnectResponseMessage extends SessionRequestSuccessMessage {
	public serverReconnectToken?: Buffer;
	public lastReceivedSequenceNumber?: number;

	protected onRead(reader: SshDataReader): void {
		super.onRead(reader);
		this.serverReconnectToken = reader.readBinary();
		this.lastReceivedSequenceNumber = reader.readUInt64();
	}

	protected onWrite(writer: SshDataWriter): void {
		super.onWrite(writer);
		writer.writeBinary(this.validateField(this.serverReconnectToken, 'serverReconnectToken'));
		writer.writeUInt64(
			this.validateField(this.lastReceivedSequenceNumber, 'lastReceivedSequenceNumber'),
		);
	}
}

export enum SshReconnectFailureReason {
	/** No reason was specified. */
	none = 0,

	/**
	 * Reconnection failed due to an unknown server-side error.
	 */
	unknownServerFailure = 1,

	/**
	 * The session ID requested by the client for reconnection was not found among
	 * the server's reconnectable sessions.
	 */
	sessionNotFound = 2,

	/**
	 * The reconnect token supplied by the client was invalid when checked by the server.
	 * The validation ensures that the client knows a secret key negotiated in the
	 * previously connected session.
	 */
	invalidClientReconnectToken = 3,

	/**
	 * The server was unable to re-send dropped messages that were requested by the client.
	 */
	serverDroppedMessages = 4,

	/**
	 * Reconnection failed due to an unknown client-side error.
	 */
	unknownClientFailure = 101,

	/**
	 * The host key supplied by the reconnected server did not match the host key from the
	 * original session; the client refused to reconnect to a different host.
	 */
	differentServerHostKey = 102,

	/**
	 * The reconnect token supplied by the server was invalid when checked by the client.
	 * The validation ensures that the server knows a secret key negotiated in the
	 * previously connected session.
	 */
	invalidServerReconnectToken = 103,

	/**
	 * The client was unable to re-send dropped messages that were requested by the server.
	 */
	clientDroppedMessages = 104,
}

export class SessionReconnectFailureMessage extends SessionRequestFailureMessage {
	public reasonCode?: SshReconnectFailureReason;
	public description?: string;
	public language?: string;

	protected onRead(reader: SshDataReader): void {
		if (reader.available > 0) {
			this.reasonCode = reader.readUInt32();
			this.description = reader.readString('utf8');
			this.language = reader.readString('ascii');
		}
	}

	protected onWrite(writer: SshDataWriter): void {
		writer.writeUInt32(this.validateField(this.reasonCode, 'reason code'));
		writer.writeString(this.description || '', 'utf8');
		writer.writeString(this.language || 'en', 'ascii');
	}

	public toString() {
		return `${super.toString()} (${SshReconnectFailureReason[this.reasonCode || 0]}: ${
			this.description
		})`;
	}
}

SshMessage.index.set(1, DisconnectMessage);
SshMessage.index.set(2, IgnoreMessage);
SshMessage.index.set(3, UnimplementedMessage);
SshMessage.index.set(5, ServiceRequestMessage);
SshMessage.index.set(6, ServiceAcceptMessage);
SshMessage.index.set(7, ExtensionInfoMessage);
SshMessage.index.set(80, SessionRequestMessage);
SshMessage.index.set(81, SessionRequestSuccessMessage);
SshMessage.index.set(82, SessionRequestFailureMessage);
