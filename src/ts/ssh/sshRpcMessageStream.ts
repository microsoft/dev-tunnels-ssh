//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as rpc from 'vscode-jsonrpc';
import { Buffer } from 'buffer';
import { SshChannel } from './sshChannel';
import { SshDataWriter } from './io/sshData';

const contentLengthHeaderPrefix = 'Content-Length: ';
const headersSeparator = '\r\n\r\n';

class SshRpcMessageReader implements rpc.MessageReader {
	private readonly errorEmitter = new rpc.Emitter<Error>();
	private readonly closeEmitter = new rpc.Emitter<void>();
	private readonly partialMessageEmitter = new rpc.Emitter<any>();
	private readonly eventRegistration: rpc.Disposable;
	private callback: rpc.DataCallback | null = null;
	private readonly messageBuffer = new SshDataWriter(Buffer.alloc(1024));
	private headersLength: number | null = null;
	private messageLength: number | null = null;

	public constructor(public channel: SshChannel) {
		this.onError = this.errorEmitter.event;
		this.onClose = this.closeEmitter.event;
		this.onPartialMessage = this.partialMessageEmitter.event;
		this.eventRegistration = this.channel.onDataReceived(this.onDataReceived.bind(this));

		this.channel.onClosed((e) => {
			if (e.error) {
				this.errorEmitter.fire(e.error);
			}

			// Note: we always want to fire a close event to avoid the rpc connection
			// to be used. After the event any usage of the rpc message connection will
			// throw an error with this code: ConnectionErrors.Closed
			this.closeEmitter.fire();
		});
	}

	public readonly onError: rpc.Event<Error>;
	public readonly onClose: rpc.Event<void>;
	public readonly onPartialMessage: rpc.Event<any>;

	public listen(callback: rpc.DataCallback): rpc.Disposable {
		this.callback = callback;
		return rpc.Disposable.create(() => {
			this.callback = null;
		});
	}

	public dispose(): void {
		if (this.eventRegistration) {
			this.eventRegistration.dispose();
		}
	}

	private onDataReceived(data: Buffer) {
		this.messageBuffer.write(data);
		this.channel.adjustWindow(data.length);

		// In case of recursion, the `data` might have already been a slice of the message buffer,
		// but it could have been invalidated by expansion during write() above.
		data = this.messageBuffer.toBuffer();

		if (this.messageLength === null) {
			const headersEnd = data.indexOf(headersSeparator);
			if (headersEnd < 0) {
				return; // Wait for more data.
			}

			const headers = data.slice(0, headersEnd).toString();
			if (!headers.startsWith(contentLengthHeaderPrefix)) {
				throw new Error(`Message does not start with JSON-RPC headers.\n${headers}`);
			}

			this.headersLength = headersEnd + headersSeparator.length;
			this.messageLength = parseInt(
				headers.substr(
					contentLengthHeaderPrefix.length,
					headersEnd - contentLengthHeaderPrefix.length,
				),
				10,
			);
		}

		const position = this.messageBuffer.position;
		const totalLength = this.headersLength! + this.messageLength;

		if (position >= totalLength) {
			if (this.callback) {
				const messageJson = data.slice(this.headersLength!, totalLength).toString();
				let message: rpc.Message;
				try {
					message = JSON.parse(messageJson);
				} catch (e) {
					if (!(e instanceof Error)) throw e;
					throw new Error(`Failed to parse JSON-RPC message: ${e.message}\n${messageJson}`);
				}
				this.callback(message);
			}

			this.messageLength = null;
			this.messageBuffer.position = 0;

			if (position > totalLength) {
				// Recursively receive the remaining data, which will cause it
				// to be copied to the beginning of the buffer;
				this.onDataReceived(data.slice(totalLength));
			}
		}
	}
}

class SshRpcMessageWriter implements rpc.MessageWriter {
	private readonly errorEmitter = new rpc.Emitter<
		[Error, rpc.Message | undefined, number | undefined]
	>();
	private readonly closeEmitter = new rpc.Emitter<void>();

	public constructor(public channel: SshChannel) {
		this.onError = this.errorEmitter.event;
		this.onClose = this.closeEmitter.event;

		this.channel.onClosed((e) => {
			if (e.error) {
				this.errorEmitter.fire([
					e.error,
					(e.errorMessage && { jsonrpc: e.errorMessage }) || undefined,
					e.exitStatus,
				]);
			}

			this.closeEmitter.fire();
		});
	}

	public onError: rpc.Event<[Error, rpc.Message | undefined, number | undefined]>;

	public onClose: rpc.Event<void>;

	public write(message: rpc.Message): Promise<void> {
		const messageJson = JSON.stringify(message);
		const messageData = Buffer.from(messageJson);
		const headerData = Buffer.from(
			contentLengthHeaderPrefix + messageData.length + headersSeparator,
		);
		const data = Buffer.alloc(headerData.length + messageData.length);
		headerData.copy(data, 0);
		messageData.copy(data, headerData.length);
		return this.channel.send(data).catch((e: Error) => {
			this.errorEmitter.fire([e, undefined, undefined]);
		});
	}

	public end(): void {}

	public dispose(): void {}
}

export class SshRpcMessageStream {
	public constructor(channel: SshChannel) {
		this.reader = new SshRpcMessageReader(channel);
		this.writer = new SshRpcMessageWriter(channel);
	}

	public readonly reader: rpc.MessageReader;
	public readonly writer: rpc.MessageWriter;
}
