//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer, TranscodeEncoding } from 'buffer';
import { SshAlgorithms } from '../algorithms/sshAlgorithms';
import { BigInt } from './bigInt';

export class SshDataReader {
	private static readonly mpintZero = Buffer.alloc(1);

	public position: number = 0;

	public constructor(public readonly buffer: Buffer) {}

	public get available(): number {
		return this.buffer.length - this.position;
	}

	public read(length: number): Buffer {
		if (this.available < length) {
			throw new Error('Attempted to read past end of buffer.');
		}

		const data = this.buffer.slice(this.position, this.position + length);
		this.position += length;
		return data;
	}

	public readByte(): number {
		if (this.available === 0) {
			throw new Error('Attempted to read past end of buffer.');
		}

		const value = this.buffer[this.position];
		this.position++;
		return value;
	}

	public readBinary(): Buffer {
		const length = this.readUInt32();

		if (this.available < length) {
			throw new Error('Attempted to read past end of buffer.');
		}

		const data = this.buffer.slice(this.position, this.position + length);
		this.position += length;
		return data;
	}

	public readString(encoding: TranscodeEncoding): string {
		const bytes = this.readBinary();
		return bytes.toString();
	}

	public readList(encoding: TranscodeEncoding): string[] {
		const stringList = this.readString(encoding);
		return stringList.length === 0 ? [] : stringList.split(',');
	}

	public readBoolean(): boolean {
		return this.readByte() !== 0;
	}

	public readUInt32(): number {
		if (this.available < 4) {
			throw new Error('Attempted to read past end of buffer.');
		}

		// Big-endian encoding
		const value0 = this.buffer[this.position + 0];
		const value1 = this.buffer[this.position + 1];
		const value2 = this.buffer[this.position + 2];
		const value3 = this.buffer[this.position + 3];
		this.position += 4;

		const value = ((value0 << 24) | (value1 << 16) | (value2 << 8) | value3) >>> 0;
		return value;
	}

	public readUInt64(): number {
		if (this.available < 8) {
			throw new Error('Attempted to read past end of buffer.');
		}

		// Big-endian encoding
		const value0 = this.buffer[this.position + 0];
		const value1 = this.buffer[this.position + 1];
		const value2 = this.buffer[this.position + 2];
		const value3 = this.buffer[this.position + 3];
		const value4 = this.buffer[this.position + 4];
		const value5 = this.buffer[this.position + 5];
		const value6 = this.buffer[this.position + 6];
		const value7 = this.buffer[this.position + 7];
		this.position += 8;

		const high = ((value0 << 24) | (value1 << 16) | (value2 << 8) | value3) >>> 0;
		const low = ((value4 << 24) | (value5 << 16) | (value6 << 8) | value7) >>> 0;
		return high * 0x100000000 + low;
	}

	public readBigInt(): BigInt {
		const data = this.readBinary();

		if (data.length === 0) {
			return BigInt.zero;
		}

		return BigInt.fromBytes(data);
	}
}

export class SshDataWriter {
	public position: number = 0;

	public constructor(private buffer: Buffer) {}

	public write(data: Buffer) {
		this.ensureCapacity(this.position + data.length);

		data.copy(this.buffer, this.position);
		this.position += data.length;
	}

	public writeByte(value: number): void {
		this.ensureCapacity(this.position + 1);

		this.buffer[this.position] = value;
		this.position++;
	}

	public writeBinary(data: Buffer): void {
		this.ensureCapacity(this.position + 4 + data.length);
		this.writeUInt32(data.length);
		data.copy(this.buffer, this.position);
		this.position += data.length;
	}

	public writeString(value: string, encoding: TranscodeEncoding): void {
		this.writeBinary(Buffer.from(value));
	}

	public writeList(value: string[], encoding: TranscodeEncoding) {
		this.writeString(value ? value.join(',') : '', encoding);
	}

	public writeBoolean(value: boolean): void {
		this.writeByte(value ? 1 : 0);
	}

	public writeUInt32(value: number): void {
		this.ensureCapacity(this.position + 4);

		// Big-endian encoding
		this.buffer[this.position + 0] = value >>> 24;
		this.buffer[this.position + 1] = value >>> 16;
		this.buffer[this.position + 2] = value >>> 8;
		this.buffer[this.position + 3] = value >>> 0;
		this.position += 4;
	}

	/* @internal */
	public static writeUInt32(buffer: Buffer, offset: number, value: number): void {
		buffer[offset + 0] = value >>> 24;
		buffer[offset + 1] = value >>> 16;
		buffer[offset + 2] = value >>> 8;
		buffer[offset + 3] = value >>> 0;
	}

	public writeUInt64(value: number): void {
		this.ensureCapacity(this.position + 8);

		const low = value & 0xffffffff;
		const high = (value - low) / 0x100000000;

		// Big-endian encoding
		this.buffer[this.position + 0] = high >>> 24;
		this.buffer[this.position + 1] = high >>> 16;
		this.buffer[this.position + 2] = high >>> 8;
		this.buffer[this.position + 3] = high >>> 0;
		this.buffer[this.position + 4] = low >>> 24;
		this.buffer[this.position + 5] = low >>> 16;
		this.buffer[this.position + 6] = low >>> 8;
		this.buffer[this.position + 7] = low >>> 0;
		this.position += 8;
	}

	public writeBigInt(value: BigInt): void {
		const data = value.toBytes();
		if (data.length === 1 && data[0] === 0) {
			this.writeUInt32(0);
		} else {
			this.writeBinary(data);
		}
	}

	public writeRandom(length: number): void {
		this.ensureCapacity(this.position + length);

		const randomBuffer = this.buffer.slice(this.position, this.position + length);
		SshAlgorithms.random.getBytes(randomBuffer);
		this.position += length;
	}

	public skip(length: number): void {
		this.ensureCapacity(this.position + length);
		this.position += length;
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

	public toBuffer(): Buffer {
		return this.buffer.slice(0, this.position);
	}
}

function makeCrcTable(): number[] {
	let c;
	const table = [];
	for (let n = 0; n < 256; n++) {
		c = n;
		for (let k = 0; k < 8; k++) {
			c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		}
		table[n] = c;
	}
	return table;
}

let crcTable: number[];

function crc32(data: Buffer): string {
	if (!crcTable) {
		crcTable = makeCrcTable();
	}

	let crc = 0 ^ -1;

	for (let i = 0; i < data.length; i++) {
		crc = (crc >>> 8) ^ crcTable[(crc ^ data[i]) & 0xff];
	}

	const result = (crc ^ -1) >>> 0;
	return (result + 0x100000000)
		.toString(16)
		.substr(-8)
		.toUpperCase();
}

/**
 * Formats a byte buffer using the same format as OpenSSH,
 * useful for debugging and comparison in logs.
 */
export function formatBuffer(data: Buffer, name?: string, formatData?: boolean): string {
	let s = `${name === undefined ? 'Buffer' : name}[${data.length}] (${crc32(data)})\n`;

	if (formatData === false) {
		return s;
	}

	const max = Math.min(2048, data.length);

	for (let lineOffset = 0; lineOffset < max; lineOffset += 16) {
		if (lineOffset < 1000) s += '0';
		if (lineOffset < 100) s += '0';
		if (lineOffset < 10) s += '0';
		s += lineOffset + ':';

		for (let i = lineOffset; i < lineOffset + 16; i++) {
			if (i < max) {
				s += ' ' + data.slice(i, i + 1).toString('hex');
			} else {
				s += '   ';
			}
		}

		s += '  ';
		for (let i = lineOffset; i < lineOffset + 16; i++) {
			if (i < max) {
				const c = data[i];
				s += c > 32 && c <= 127 ? data.slice(i, i + 1).toString() : '.';
			} else {
				s += ' ';
			}
		}

		s += '\n';
	}

	if (max < data.length) {
		s += '...\n';
	}

	return s;
}
