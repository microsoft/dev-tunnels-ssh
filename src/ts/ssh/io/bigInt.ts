//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { formatBuffer } from './sshData';

/**
 * Represents a large signed integer as a byte byffer.
 */
export class BigInt {
	public static readonly zero = new BigInt(Buffer.alloc(1));

	/**
	 * Creates a new BigInt instance from a buffer of signed bytes.
	 *
	 * The first (high) bit of the first (high) byte is the sign bit. Therefore if the
	 * highest byte of an unsigned integer is greater than 127, the bytes must include
	 * a leading zero byte to prevent interpretation as a negative value.
	 */
	public constructor(private readonly buffer: Buffer) {
		if (buffer.length === 0) {
			throw new Error('BigInt buffer length must be greater than zero.');
		}
	}

	/**
	 * Gets a value that indicates the sign of the big integer:
	 * 1 for positive, 0 for zero, -1 for negative.
	 */
	public get sign(): number {
		const highByte = this.buffer[0];
		if (highByte === 0) {
			return this.buffer.length > 1 ? 1 : 0;
		} else {
			return (highByte & 0x80) === 0 ? 1 : -1;
		}
	}

	public static fromInt32(value: number): BigInt {
		if (value === 0) {
			return BigInt.zero;
		}

		let isNegative = false;
		if (value < 0) {
			isNegative = true;
			value = -value;
		}

		const bytes: number[] = [];

		for (let bit = 24; bit >= 0; bit -= 8) {
			if (value >= 1 << bit || bytes.length > 0) {
				bytes.push(value >> bit);
				value = value & ~((1 << bit) - 1);
			}
		}

		if (isNegative) {
			if ((bytes[0] & 0x80) === 0) {
				bytes[0] |= 0x80;
			} else {
				bytes.splice(0, 0, 0x80);
			}
		}

		return new BigInt(Buffer.from(new Uint8Array(bytes)));
	}

	public toInt32(): number {
		if (this.buffer.length > 4) {
			throw new TypeError('BigInt value cannot be converted to a 32-bit signed integer.');
		}

		let value = this.buffer[0];
		if (this.sign < 0) {
			value &= 0x7f;
		}

		for (let i = 1; i < this.buffer.length; i++) {
			value = (value << 8) + this.buffer[i];
		}

		if (this.sign < 0) {
			value = -value;
		}

		return value;
	}

	/**
	 * Creates a new BigInt instance from a byte buffer.
	 * @param bytes Source byte buffer.
	 * @param options.unsigned True if the bytes should be interpreted as unsigned. If false,
	 * the high bit of the high byte is the sign bit. The default is false.
	 */
	public static fromBytes(
		bytes: Buffer,
		options?: {
			unsigned?: boolean;
		},
	): BigInt {
		if (!Buffer.isBuffer(bytes)) {
			throw new TypeError('Buffer expected.');
		} else if (bytes.length === 0) {
			throw new Error('BigInt buffer length must be greater than zero.');
		}

		options = options ?? {};

		const highBit = (bytes[0] & 0x80) !== 0;
		const prependZeroCount = options.unsigned && highBit ? 1 : 0;
		let skipZeroCount = 0;

		// Skip non-significant zeroes at the big end.
		for (let i = 0; i < bytes.length - 1 && bytes[i] === 0; i++) {
			if ((bytes[i + 1] & 0x80) === 0) {
				skipZeroCount++;
			}
		}

		const newBytes = Buffer.alloc(bytes.length + prependZeroCount - skipZeroCount);
		bytes.copy(newBytes, prependZeroCount, skipZeroCount, bytes.length);

		return new BigInt(newBytes);
	}

	/**
	 * Converts a BigInt instance to a byte buffer.
	 *
	 * @param options.unsigned True if the returned bytes will be interprted as unsigned.
	 * If false, a positive integer may have a leading zero to prevent it from being
	 * interpreted as negative.
	 * @param options.length Desired length of the resulting buffer. The value will be zero-
	 * padded to fill the length. Only applies when `options.unsigned` is true.
	 */
	public toBytes(options?: { unsigned?: boolean; length?: number }): Buffer {
		options = options ?? {};

		let bytes = this.buffer;
		if (options.unsigned) {
			if (this.sign < 0) {
				throw new TypeError('Cannot format a negative BigInt as unsigned.');
			} else if (bytes[0] === 0 && bytes.length > 1) {
				bytes = bytes.slice(1, bytes.length);
			}

			if (options.length !== undefined) {
				if (bytes.length > options.length) {
					throw new Error(
						`BigInt (${bytes.length} bytes) is too large for length ${options.length}.`,
					);
				} else if (bytes.length < options.length) {
					const padded = Buffer.alloc(options.length);
					bytes.copy(padded, options.length - bytes.length);
					return padded;
				}
			}
		}

		const newBytes = Buffer.alloc(bytes.length);
		bytes.copy(newBytes, 0, 0, bytes.length);
		return newBytes;
	}

	public copyTo(buffer: Buffer, offset = 0): void {
		this.buffer.copy(buffer, offset, 0, this.buffer.length);
	}

	public equals(other: BigInt): boolean {
		return other instanceof BigInt && this.buffer.equals(other.buffer);
	}

	public toString(name?: string): string {
		return formatBuffer(this.buffer, name ?? 'BigInt');
	}
}
