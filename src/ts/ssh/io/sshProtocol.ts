//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { CancellationToken, Disposable } from 'vscode-jsonrpc';
import { Stream } from '../streams';
import { Queue } from '../util/queue';
import { Semaphore } from '../util/semaphore';
import { KeyExchangeService } from '../services/keyExchangeService';
import { SshMessage } from '../messages/sshMessage';
import { SshDataWriter, SshDataReader, formatBuffer } from '../io/sshData';
import {
	SshDisconnectReason,
	DisconnectMessage,
	UnimplementedMessage,
} from '../messages/transportMessages';
import {
	KeyExchangeInitMessage,
	KeyExchangeDhInitMessage,
	KeyExchangeMessage,
} from '../messages/kexMessages';
import { ChannelDataMessage } from '../messages/connectionMessages';
import { SessionMetrics } from '../metrics/sessionMetrics';
import { Signer, Verifier } from '../algorithms/sshAlgorithms';
import { SshConnectionError } from '../errors';
import { SshSessionAlgorithms } from '../sshSessionAlgorithms';
import { SshSessionConfiguration } from '../sshSessionConfiguration';
import { Trace, TraceLevel, SshTraceEventIds } from '../trace';

class SequencedMessage {
	public constructor(public readonly sequence: number, public readonly message: SshMessage) {}
	public sentTime!: number;
}

/**
 * Implements the base SSH protocol (sending and receiving messages) over a Stream.
 */
export class SshProtocol implements Disposable {
	private static readonly maxPacketLength = 1024 * 1024; // 1 MB
	private static readonly packetLengthSize = 4;
	private static readonly paddingLengthSize = 1;

	private stream: Stream | null;
	private readonly sessionSemaphore = new Semaphore(1);

	private inboundPacketSequence: number = 0;
	private outboundPacketSequence: number = 0;
	private inboundFlow: number = 0;
	private outboundFlow: number = 0;
	private lastIncomingTimestamp!: number;

	// Sent messages are kept for a short time, until the other side acknowledges
	// that they have been received. This enables re-sending lost messages on reconnect.
	private readonly recentSentMessages = new Queue<SequencedMessage>();

	// Initialize buffers that are re-used for each sent/received message.
	// The buffers will be automatically expanded as necessary.
	private readonly sendWriter = new SshDataWriter(Buffer.alloc(1024));
	private readonly receiveWriter = new SshDataWriter(Buffer.alloc(1024));

	public constructor(
		stream: Stream,
		private readonly config: SshSessionConfiguration,
		private readonly metrics: SessionMetrics,
		private readonly trace: Trace,
	) {
		this.stream = stream;
	}

	/* @internal */
	public traceChannelData = false;

	public extensions: Map<string, string> | null = null;

	public kexService: KeyExchangeService | null = null;

	public algorithms: SshSessionAlgorithms | null = null;

	public outgoingMessagesHaveLatencyInfo = false;
	public incomingMessagesHaveLatencyInfo = false;
	public outgoingMessagesHaveReconnectInfo = false;
	public incomingMessagesHaveReconnectInfo = false;

	public get lastIncomingSequence(): number {
		return this.inboundPacketSequence - 1;
	}

	public getSentMessages(startingSequenceNumber: number): SshMessage[] | null {
		if (startingSequenceNumber === this.outboundPacketSequence + 1) {
			// The recipient is already up-to-date.
			return [];
		}

		if (
			this.recentSentMessages.size > 0 &&
			startingSequenceNumber < this.recentSentMessages.peek()!.sequence
		) {
			// The cached recent messages do not go back as far as the requested sequence number.
			// This should never happen because messages are not dropped from this list until
			// the other side acknowledges they have been received, so they should not be
			// requested again after reconnecting.
			return null;
		}

		// Return all messages starting with the requested sequence number.
		// Exclude key exchange messages because they cannot be retransmitted; a reconnected
		// session will do key exchange separately. Also exclude any disconnect messages that
		// may have been attempted when the connection was lost.
		const messagesToRetransmit = new Array<SshMessage>();
		for (let sequencedMessage of this.recentSentMessages) {
			if (sequencedMessage.sequence >= startingSequenceNumber) {
				const message = sequencedMessage.message;
				if (!(message instanceof KeyExchangeMessage || message instanceof DisconnectMessage)) {
					messagesToRetransmit.push(message);
				}
			}
		}
		return messagesToRetransmit;
	}

	public async writeProtocolVersion(
		version: string,
		cancellation?: CancellationToken,
	): Promise<void> {
		const stream = this.stream;
		if (!stream) throw new Error('SSH session disconnected.');

		const data: Buffer = Buffer.from(version + '\r\n');
		await stream.write(data, cancellation);
		this.metrics.addMessageSent(data.length);
		return Promise.resolve();
	}

	public async readProtocolVersion(cancellation?: CancellationToken): Promise<string> {
		const stream = this.stream;
		if (!stream) throw new Error('SSH session disconnected.');

		// http://tools.ietf.org/html/rfc4253#section-4.2

		const buffer = Buffer.alloc(255);
		let lineCount = 0;
		for (let i = 0; i < buffer.length; i++) {
			const byteBuffer = await stream.read(1, cancellation);
			if (!byteBuffer) {
				break;
			}

			buffer[i] = byteBuffer[0];

			const carriageReturn = 0x0d;
			const lineFeed = 0x0a;
			if (i > 0 && buffer[i - 1] === carriageReturn && buffer[i] === lineFeed) {
				const line = buffer.toString('utf8', 0, i - 1);
				if (line.startsWith('SSH-')) {
					this.metrics.addMessageReceived(i + 1);
					return line;
				} else if (lineCount > 20) {
					// Give up if a version string was not found after 20 lines.
					break;
				} else {
					// Ignore initial lines before the version line.
					lineCount++;
					i = -1;
				}
			}
		}

		throw new SshConnectionError(
			'Failed to read the protocol version',
			SshDisconnectReason.protocolError,
		);
	}

	public async handleNewKeys(cancellation?: CancellationToken): Promise<void> {
		try {
			await this.sessionSemaphore.wait(cancellation);

			this.inboundFlow = 0;
			this.outboundFlow = 0;

			this.algorithms = this.kexService!.finishKeyExchange();
		} finally {
			this.sessionSemaphore.release();
		}
	}

	/**
	 * Attempts to read from the stream until the buffer is full.
	 * @returns True if the read succeeded, false if the stream was disposed.
	 */
	private async read(buffer: Buffer, cancellation?: CancellationToken): Promise<boolean> {
		const stream = this.stream;
		if (!stream) return false;

		let bytesRead = 0;
		do {
			let data: Buffer | null;
			try {
				data = await stream.read(buffer.length - bytesRead, cancellation);
			} catch (e) {
				if (!(e instanceof Error)) throw e;
				if (stream.isDisposed) return false;

				stream.dispose();
				this.stream = null;
				this.trace(
					TraceLevel.Error,
					SshTraceEventIds.streamReadError,
					`Error reading from stream: ${e.message}`,
					e,
				);
				throw new SshConnectionError(
					'Error reading from stream: ' + e.message,
					SshDisconnectReason.connectionLost,
				);
			}

			if (!data) return false;

			data.copy(buffer, bytesRead);
			bytesRead += data.length;
		} while (bytesRead < buffer.length);

		return true;
	}

	/**
	 * Attempts to write data to the stream.
	 * @returns True if the write succeeded, false if the stream was disposed.
	 */
	private async write(data: Buffer, cancellation?: CancellationToken): Promise<boolean> {
		const stream = this.stream;
		if (!stream) return false;

		try {
			await stream.write(data, cancellation);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			if (stream.isDisposed) return false;

			stream.dispose();
			this.stream = null;
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.streamWriteError,
				`Error writing to stream: ${e.message}`,
				e,
			);
			throw new SshConnectionError(
				'Error writing to stream: ' + e.message,
				SshDisconnectReason.connectionLost,
			);
		}

		return true;
	}

	public async considerReExchange(
		initial: boolean,
		cancellation?: CancellationToken,
	): Promise<void> {
		const kexService = this.kexService;
		if (!kexService) return;

		let kexMessage: KeyExchangeInitMessage | null = null;
		let kexGuessMessage: KeyExchangeDhInitMessage | null = null;

		if (
			!kexService.exchanging &&
			(initial || this.inboundFlow + this.outboundFlow > this.config.keyRotationThreshold)
		) {
			[kexMessage, kexGuessMessage] = await kexService.startKeyExchange(initial);
		}

		if (kexMessage) {
			await this.sendMessage(kexMessage, cancellation);

			if (kexGuessMessage) {
				await this.sendMessage(kexGuessMessage, cancellation);
			}
		}
	}

	private async computeHmac(signer: Signer, payload: Buffer, seq: number): Promise<Buffer> {
		const writer = new SshDataWriter(Buffer.alloc(4 + payload.length));
		writer.writeUInt32(seq);
		writer.write(payload);

		const result = await signer.sign(writer.toBuffer());
		return result;
	}

	private async verifyHmac(
		verifier: Verifier,
		payload: Buffer,
		seq: number,
		mac: Buffer,
	): Promise<boolean> {
		const writer = new SshDataWriter(Buffer.alloc(4 + payload.length));
		writer.writeUInt32(seq);
		writer.write(payload);

		const result = await verifier.verify(writer.toBuffer(), mac);
		return result;
	}

	private async readAndVerifyHmac(
		verifier: Verifier,
		data: Buffer,
		macBuffer: Buffer,
		cancellation?: CancellationToken,
	): Promise<boolean> {
		if (!(await this.read(macBuffer, cancellation))) {
			return false;
		}

		const verified = await this.verifyHmac(verifier, data, this.inboundPacketSequence, macBuffer);
		if (!verified) {
			throw new SshConnectionError('Invalid MAC', SshDisconnectReason.macError);
		}

		return true;
	}

	/**
	 * Attemps to write one message to the stream.
	 * @returns `true` if writing succeeded, `false` if the stream was disposed.
	 * @throws SshConnectionException if writing to the stream failed for any other reason.
	 */
	public async sendMessage(
		message: SshMessage,
		cancellation?: CancellationToken,
	): Promise<boolean> {
		const algorithms = this.algorithms;
		const compression = algorithms?.compressor;
		const encryption = algorithms?.cipher;
		const hmac = algorithms?.messageSigner;

		let result: boolean;
		await this.sessionSemaphore.wait(cancellation);
		try {
			const blockSize = encryption ? Math.max(8, encryption.blockLength) : 8;

			// Start by writing the uncompressed payload to the buffer at the correct offset.
			const payloadOffset = SshProtocol.packetLengthSize + SshProtocol.paddingLengthSize;
			this.sendWriter.position = payloadOffset;
			message.write(this.sendWriter);

			if (this.outgoingMessagesHaveReconnectInfo) {
				// Write the sequence number of the last inbound packet processed.
				this.sendWriter.writeUInt64(this.lastIncomingSequence);

				if (this.outgoingMessagesHaveLatencyInfo) {
					// Write the time (in microseconds, not ms) since last packet was received.
					const timeSinceLastReceivedMessage = Math.min(
						0xffff_ffff, // max uint32
						Math.round((this.metrics.time - this.lastIncomingTimestamp) * 1000),
					);
					this.sendWriter.writeUInt32(timeSinceLastReceivedMessage);
				}
			}

			let payload = this.sendWriter.toBuffer().slice(payloadOffset);

			if (compression != null) {
				payload = compression.compress(payload);
			}

			// The packet length is not encrypted when in EtM or AEAD mode.
			const isLengthEncrypted = !(hmac?.encryptThenMac || hmac?.authenticatedEncryption);

			// http://tools.ietf.org/html/rfc4253
			// 6.  Binary Packet Protocol
			// the total length of (packet_length || padding_length || payload || padding)
			// is a multiple of the cipher block size or 8,
			// padding length must between 4 and 255 bytes.
			let paddingLength =
				blockSize -
				(((isLengthEncrypted ? SshProtocol.packetLengthSize : 0) +
					SshProtocol.paddingLengthSize +
					payload.length) %
					blockSize);
			if (paddingLength < 4) {
				paddingLength += blockSize;
			}

			const packetLength = SshProtocol.paddingLengthSize + payload.length + paddingLength;

			this.sendWriter.position = 0;
			this.sendWriter.writeUInt32(packetLength);
			this.sendWriter.writeByte(paddingLength);

			// The uncompressed payload was already written at the correct offset.
			// When compression is enabled, rewrite the compressed payload.
			if (compression != null) {
				this.sendWriter.write(payload);
			} else {
				this.sendWriter.position += payload.length;
			}

			this.sendWriter.writeRandom(paddingLength);
			payload = this.sendWriter.toBuffer();

			let mac: Buffer | null = null;
			if (hmac?.encryptThenMac && encryption) {
				// In EtM mode, compute the MAC after encrypting. And don't encrypt the length.
				const packetWithoutLength = payload.slice(SshProtocol.packetLengthSize, payload.length);
				const encryptedPacket = await encryption!.transform(packetWithoutLength);
				encryptedPacket.copy(packetWithoutLength);
				mac = await this.computeHmac(hmac, payload, this.outboundPacketSequence);
			} else if (hmac?.authenticatedEncryption) {
				// With a GCM cipher, the packet length is not included in the plaintext.
				let packetWithoutLength = payload.slice(SshProtocol.packetLengthSize, payload.length);
				const encryptedPacket = await encryption!.transform(packetWithoutLength);
				encryptedPacket.copy(packetWithoutLength);

				// The GCM tag was already generated during the transform call above;
				// this just retrieves it.
				mac = await hmac.sign(packetWithoutLength);
			} else {
				if (hmac) {
					mac = await this.computeHmac(hmac, payload, this.outboundPacketSequence);
				}

				if (encryption) {
					payload = await encryption.transform(payload);
				}
			}

			if (!(message instanceof ChannelDataMessage)) {
				this.trace(
					TraceLevel.Verbose,
					SshTraceEventIds.sendingMessage,
					`Sending #${this.outboundPacketSequence} ${message}`,
				);
			} else if (this.traceChannelData) {
				this.trace(
					TraceLevel.Verbose,
					SshTraceEventIds.sendingChannelData,
					`Sending #${this.outboundPacketSequence} ${message}`,
				);
			}

			if (this.incomingMessagesHaveReconnectInfo) {
				// Save sent messages in case they need to be re-sent after reconnect.
				// They'll be discarded soon, after the other side acknowledges them.
				const sequencedMessage = new SequencedMessage(this.outboundPacketSequence, message);
				sequencedMessage.sentTime = this.metrics.time;
				this.recentSentMessages.enqueue(sequencedMessage);
			}

			this.outboundPacketSequence++;
			this.outboundFlow += packetLength;

			if (mac) {
				const packet = Buffer.concat([payload, mac], payload.length + mac.length);
				result = await this.write(packet, cancellation);
			} else {
				result = await this.write(payload, cancellation);
			}

			this.metrics.addMessageSent(
				SshProtocol.packetLengthSize + packetLength + (hmac?.digestLength ?? 0),
			);
		} finally {
			this.sessionSemaphore.release();
		}

		await this.considerReExchange(false, cancellation);
		return result;
	}

	/**
	 * Attemps to read one message from the stream.
	 * @returns The message, or `null` if the stream was disposed.
	 * @throws SshConnectionError if reading from the stream failed for any other reason.
	 */
	public async receiveMessage(cancellation?: CancellationToken): Promise<SshMessage | null> {
		const algorithms = this.algorithms;
		const encryption = algorithms?.decipher;
		const hmac = algorithms?.messageVerifier;
		const compression = algorithms?.decompressor;

		// The packet length is not encrypted when in EtM or AEAD mode.
		// So read only the length bytes first, separate from the remaining payload.
		const isLengthEncrypted = !(hmac?.encryptThenMac || hmac?.authenticatedEncryption);

		const firstBlockSize = !isLengthEncrypted
			? SshProtocol.packetLengthSize
			: encryption
			? Math.max(8, encryption.blockLength)
			: 8;

		this.receiveWriter.position = firstBlockSize;
		let firstBlock = this.receiveWriter.toBuffer();
		if (!(await this.read(firstBlock, cancellation))) {
			return null;
		}

		this.lastIncomingTimestamp = this.metrics.time;

		// Decrypt the first block to get the packet length.
		if (encryption && isLengthEncrypted) {
			firstBlock = await encryption.transform(firstBlock);
			this.receiveWriter.position = 0;
			this.receiveWriter.write(firstBlock);
		}

		const receiveReader = new SshDataReader(firstBlock);
		const packetLength = receiveReader.readUInt32();

		if (packetLength > SshProtocol.maxPacketLength) {
			throw new SshConnectionError('Invalid packet length.', SshDisconnectReason.protocolError);
		}

		const packetBufferSize = SshProtocol.packetLengthSize + packetLength;
		if (packetBufferSize > firstBlockSize) {
			this.receiveWriter.skip(packetBufferSize - firstBlockSize);
		}

		if (hmac) {
			// Ensure the receive buffer is large enough to also hold the mac without expanding.
			this.receiveWriter.skip(hmac.digestLength);
		}

		const receiveBuffer = this.receiveWriter.toBuffer();
		const packetBuffer = receiveBuffer.slice(0, packetBufferSize);
		const macBuffer = receiveBuffer.slice(packetBufferSize);

		let followingBlocks = packetBuffer.slice(firstBlockSize, packetBufferSize);
		if (followingBlocks.length > 0) {
			if (!(await this.read(followingBlocks, cancellation))) {
				return null;
			}

			if (hmac?.encryptThenMac) {
				// In EtM mode, read and verify the MAC before decrypting.
				///const packetWithoutLength = packet.slice(SshProtocol.packetLengthSize);
				if (!(await this.readAndVerifyHmac(hmac, packetBuffer, macBuffer, cancellation))) {
					return null;
				}
			}

			if (encryption) {
				if (hmac?.authenticatedEncryption) {
					// With a GCM cipher, the MAC is required for decryption.
					if (!(await this.read(macBuffer, cancellation))) {
						return null;
					}

					// This doesn't actually verify anything yet (hence the return value is not checked);
					// it sets the tag to be used for verification in the following transform call.
					await hmac.verify(followingBlocks, macBuffer);
				}

				try {
					followingBlocks = await encryption.transform(followingBlocks);
				} catch (e) {
					if (hmac?.authenticatedEncryption) {
						// GCM decryption failed to verify data + tag.
						throw new SshConnectionError('Invalid MAC', SshDisconnectReason.macError);
					} else {
						throw e;
					}
				}

				this.receiveWriter.position = firstBlockSize;
				this.receiveWriter.write(followingBlocks);
			}
		}

		if (hmac && !hmac.encryptThenMac && !hmac.authenticatedEncryption) {
			if (!(await this.readAndVerifyHmac(hmac, packetBuffer, macBuffer, cancellation))) {
				return null;
			}
		}

		const paddingLength = packetBuffer[SshProtocol.packetLengthSize];
		let payload = packetBuffer.slice(
			SshProtocol.packetLengthSize + SshProtocol.paddingLengthSize,
			SshProtocol.packetLengthSize + (packetLength - paddingLength),
		);

		if (compression) {
			payload = compression.decompress(payload);
		}

		if (this.incomingMessagesHaveReconnectInfo) {
			// Read the extension info from the end of the payload.
			let lastSequenceSeenByRemote: number;
			let remoteTimeSinceLastReceived: number;

			if (this.incomingMessagesHaveLatencyInfo) {
				const reader = new SshDataReader(payload.slice(payload.length - 12, payload.length));
				lastSequenceSeenByRemote = reader.readUInt64();
				remoteTimeSinceLastReceived = reader.readUInt32() / 1000; // microseconds to ms
				payload = payload.slice(0, payload.length - 12);
			} else {
				const reader = new SshDataReader(payload.slice(payload.length - 8, payload.length));
				lastSequenceSeenByRemote = reader.readUInt64();
				remoteTimeSinceLastReceived = 0;
				payload = payload.slice(0, payload.length - 8);
			}

			// Discard any recently sent messages that were acknowledged.
			while (this.recentSentMessages.size > 0) {
				const oldestSequenceMessage = this.recentSentMessages.peek()!;
				if (oldestSequenceMessage.sequence > lastSequenceSeenByRemote) {
					break;
				}

				if (
					this.stream &&
					this.incomingMessagesHaveLatencyInfo &&
					oldestSequenceMessage.sequence === lastSequenceSeenByRemote
				) {
					// Compute the time since the message with the last-seen sequence was sent.
					// Subtract the time between when the remote side received the message with the
					// last-seen sequence and sent the current message.
					const timeSinceSent = this.lastIncomingTimestamp - oldestSequenceMessage.sentTime;
					const roundTripLatency = timeSinceSent - remoteTimeSinceLastReceived;
					this.metrics.updateLatency(roundTripLatency);
				}

				this.recentSentMessages.dequeue();
			}
		}

		const messageType = payload[0];
		let message = SshMessage.create(this.config, messageType, payload);

		if (!message) {
			const unimplementedMessage = new UnimplementedMessage();
			unimplementedMessage.sequenceNumber = this.inboundPacketSequence;
			unimplementedMessage.unimplementedMessageType = messageType;
			message = unimplementedMessage;
		}

		if (!(message instanceof ChannelDataMessage)) {
			this.trace(
				TraceLevel.Verbose,
				SshTraceEventIds.receivingMessage,
				`Receiving #${this.inboundPacketSequence} ${message}`,
			);
		} else if (this.traceChannelData) {
			this.trace(
				TraceLevel.Verbose,
				SshTraceEventIds.receivingChannelData,
				`Receiving #${this.inboundPacketSequence} ${message}`,
			);
		}

		await this.sessionSemaphore.wait(cancellation);
		this.inboundPacketSequence++;
		this.inboundFlow += packetLength;
		this.sessionSemaphore.release();

		this.metrics.addMessageReceived(
			SshProtocol.packetLengthSize + packetLength + (hmac?.digestLength ?? 0),
		);

		await this.considerReExchange(false, cancellation);

		return message;
	}

	public dispose(): void {
		try {
			if (this.stream)
				this.stream.close().catch((e) => {
					this.trace(
						TraceLevel.Error,
						SshTraceEventIds.streamCloseError,
						`Error closing stream: ${e.message}`,
						e,
					);
				});
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			this.trace(
				TraceLevel.Error,
				SshTraceEventIds.streamCloseError,
				`Error closing stream: ${e.message}`,
				e,
			);
		}

		this.stream = null;
		this.metrics.updateLatency(0);

		if (this.algorithms) this.algorithms.dispose();
	}
}
