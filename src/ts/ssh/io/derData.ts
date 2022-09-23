//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { BigInt } from './bigInt';

export const enum DerType {
	Integer = 0x02,
	BitString = 0x03,
	OctetString = 0x04,
	Null = 0x05,
	ObjectIdentifier = 0x06,
	Sequence = 0x10,
	Set = 0x11,
	Constructed = 0x20,
	Tagged = 0xa0,
}

/**
 * Reads data in DER (Distinguished Encoding Rules) format.
 *
 * Enables importing and exporting key files, which are commonly DER-encoded.
 */
export class DerReader {
	private position: number;

	public constructor(
		private readonly buffer: Buffer,
		dataType: DerType = DerType.Constructed | DerType.Sequence,
	) {
		this.position = 0;

		this.readType(dataType);

		const length = this.readLength();
		if (length > this.buffer.length - this.position) {
			throw new Error('Read out of bounds.');
		}

		this.buffer = this.buffer.slice(0, this.position + length);
	}

	public get available(): number {
		return this.buffer.length - this.position;
	}

	public readNull(): void {
		this.readType(DerType.Null);
		if (this.readByte() !== 0) {
			throw new Error('Expected a 0 after Null type.');
		}
	}

	public readInteger(): BigInt {
		this.readType(DerType.Integer);
		const length = this.readLength();
		const bytes = this.readBytes(length);
		const result = new BigInt(bytes);
		return result;
	}

	public readOctetString(): Buffer {
		this.readType(DerType.OctetString);
		const length = this.readLength();
		const result = this.readBytes(length);
		return result;
	}

	public readBitString(): Buffer {
		this.readType(DerType.BitString);
		const length = this.readLength();

		const padding = this.readByte();
		if (padding !== 0) {
			throw new Error('Padded bit strings are not supported.');
		}

		const result = this.readBytes(length - 1);
		return result;
	}

	public readObjectIdentifier(expected?: string): string {
		this.readType(DerType.ObjectIdentifier);

		const length = this.readLength();
		const end = this.position + length;

		const values: number[] = [];

		const first = this.readByte();
		values.push(Math.trunc(first / 40));
		values.push(first % 40);

		let next = 0;
		while (this.position < end) {
			const b = this.readByte();
			if ((b & 0x80) !== 0) {
				next = next * 128 + (b & 0x7f);
			} else {
				next = next * 128 + b;
				values.push(next);
				next = 0;
			}
		}

		if (next !== 0) {
			throw new Error('Invalid OID format.');
		}

		const result = values.join('.');
		if (expected && result !== expected) {
			throw new Error(`Expected OID ${expected}, found: ${result}`);
		}

		return result;
	}

	public readSequence(): DerReader {
		const start = this.position;
		this.readType(DerType.Constructed | DerType.Sequence);

		const length = this.readLength();
		this.position += length;
		return new DerReader(this.buffer.slice(start, this.position));
	}

	public tryReadTagged(tagId: number): DerReader | null {
		if (this.position >= this.buffer.length) {
			return null;
		}

		const type = <DerType>this.buffer[this.position];
		if ((type & DerType.Tagged) === 0 || (type & ~DerType.Tagged) !== tagId) {
			return null;
		}

		const start = this.position;
		this.position++;
		const length = this.readLength();
		this.position += length;
		const taggedData = new DerReader(this.buffer.slice(start, this.position), type);
		return taggedData;
	}

	/** Reads the type of the next value in the sequence WITHOUT advancing the reader position. */
	public peek(): DerType {
		if (this.position >= this.buffer.length) {
			throw new Error('Read out of bounds.');
		}

		return <DerType>this.buffer[this.position];
	}

	private readLength(): number {
		let length = this.readByte();

		if (length === 0x80) {
			throw new Error('Indefinite-length encoding is not supported.');
		}

		if (length > 127) {
			const size = length & 0x7f;

			if (size > 4) {
				throw new Error(`DER length size is ${size} and cannot be more than 4 bytes.`);
			}

			length = 0;
			for (let i = 0; i < size; i++) {
				const next = this.readByte();
				length = (length << 8) + next;
			}

			if (length < 0) {
				throw new Error('Corrupted data - negative length found');
			}
		}

		return length;
	}

	private readByte(): number {
		if (this.position >= this.buffer.length) {
			throw new Error('Read out of bounds.');
		}

		return this.buffer[this.position++];
	}

	private readBytes(length: number): Buffer {
		if (this.position + length > this.buffer.length) {
			throw new Error('Read out of bounds.');
		}

		const result = this.buffer.slice(this.position, this.position + length);
		this.position += length;
		return result;
	}

	private readType(expectedType: DerType): void {
		const type = <DerType>this.readByte();
		if (type !== expectedType) {
			throw new Error(`Expected ${expectedType} data type, found : ${type}`);
		}
	}
}

/**
 * Writes data in DER (Distinguished Encoding Rules) format.
 *
 * Enables importing and exporting key files, which are commonly DER-encoded.
 */
export class DerWriter {
	private static lengthBuffer = Buffer.alloc(10);
	private position: number;

	public constructor(
		private buffer: Buffer,
		private readonly dataType: DerType = DerType.Constructed | DerType.Sequence,
	) {
		this.position = 0;
		this.buffer = buffer;
	}

	public toBuffer(): Buffer {
		// Move the data over to make space for the type + length prefix.
		const length = this.position;
		const lengthBytes = DerWriter.getLength(length);
		this.ensureCapacity(1 + lengthBytes.length + length);
		const result = this.buffer.slice(0, 1 + lengthBytes.length + length);
		this.buffer.copy(result, 1 + lengthBytes.length);

		// Write the type + length prefix.
		result[0] = this.dataType;
		lengthBytes.copy(result, 1, 0);

		// Restore the writer buffer to its previous state (without the type + length prefix).
		this.buffer = this.buffer.slice(1 + lengthBytes.length, result.length);
		this.position = length;

		return result;
	}

	public writeSequence(data: DerWriter): void {
		this.writeBytes(data.toBuffer());
	}

	public writeTagged(tagId: number, data: DerWriter): void {
		if (tagId > 0xf) throw new Error('Invalid DER tag.');
		this.writeByte(DerType.Tagged | tagId);
		const lengthBytes = DerWriter.getLength(data.position);
		this.writeBytes(lengthBytes);
		this.writeBytes(data.buffer.slice(0, data.position));
	}

	public writeNull(): void {
		this.writeByte(DerType.Null);
		this.writeByte(0);
	}

	public writeInteger(value: BigInt): void {
		this.writeByte(DerType.Integer);
		const integerBytes = value.toBytes();
		const lengthBytes = DerWriter.getLength(integerBytes.length);
		this.writeBytes(lengthBytes);
		this.writeBytes(integerBytes);
	}

	public writeOctetString(data: Buffer): void {
		this.writeByte(DerType.OctetString);
		const lengthBytes = DerWriter.getLength(data.length);
		this.writeBytes(lengthBytes);
		this.writeBytes(data);
	}

	public writeBitString(data: Buffer): void {
		this.writeByte(DerType.BitString);
		const lengthBytes = DerWriter.getLength(1 + data.length);
		this.writeBytes(lengthBytes);
		this.writeByte(0);
		this.writeBytes(data);
	}

	public writeObjectIdentifier(oid: string): void {
		if (!oid) throw new TypeError('OID value is null or empty.');

		const values = oid.split('.').map(Number);
		if (values.length < 2 || values[0] > 3 || values[1] >= 40) {
			throw new Error(`Invalid OID: ${oid}`);
		}

		this.writeByte(DerType.ObjectIdentifier);

		let length = values.length - 1;
		for (let i = 2; i < values.length; i++) {
			let value = values[i];
			while (value > 128) {
				length++;
				value /= 128;
			}
		}

		const lengthBytes = DerWriter.getLength(length);
		this.writeBytes(lengthBytes);
		this.writeByte(values[0] * 40 + values[1]);

		for (let i = 2; i < values.length; i++) {
			let value = values[i];
			if (value >= 128) {
				let bytes: number[] = [];
				bytes.push(value & 0x7f);

				while (value >= 128) {
					value /= 128;
					bytes.push(0x80 | (value & 0x7f));
				}

				while (bytes.length > 0) {
					this.writeByte(bytes.pop()!);
				}
			} else {
				this.writeByte(value);
			}
		}
	}

	private static getLength(length: number): Buffer {
		if (length > 127) {
			let size = 1;
			for (let val = length >> 8; val !== 0; val >>= 8) {
				size++;
			}

			const lengthBytes = DerWriter.lengthBuffer.slice(0, size + 1);
			lengthBytes[0] = size | 0x80;

			for (let i = (size - 1) * 8, j = 1; i >= 0; i -= 8, j++) {
				lengthBytes[j] = length >> i;
			}

			return lengthBytes;
		} else {
			const lengthBytes = DerWriter.lengthBuffer.slice(0, 1);
			lengthBytes[0] = length;
			return lengthBytes;
		}
	}

	private writeByte(value: number): void {
		this.ensureCapacity(this.position + 1);
		this.buffer[this.position++] = value;
	}

	private writeBytes(value: Buffer): void {
		this.ensureCapacity(this.position + value.length);
		value.copy(this.buffer, this.position);
		this.position += value.length;
	}

	private ensureCapacity(capacity: number): void {
		if (this.buffer.length < capacity) {
			let newLength = Math.max(512, this.buffer.length * 2);
			while (newLength < capacity) newLength *= 2;

			const newBuffer = Buffer.alloc(newLength);
			this.buffer.copy(newBuffer, 0, 0, this.position);
			this.buffer = newBuffer;
		}
	}
}
