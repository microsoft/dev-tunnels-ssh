//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';

import { EncryptionAlgorithm, Cipher } from '../encryptionAlgorithm';
import { MessageSigner, MessageVerifier } from '../sshAlgorithms';

export class WebEncryption extends EncryptionAlgorithm {
	public constructor(
		name: string,
		public readonly algorithmName: string,
		public readonly cipherMode: string | null,
		public readonly keySizeInBits: number,
	) {
		super(name);
		this.blockSizeInBits = WebEncryption.getBlockSize(algorithmName);
	}

	public readonly blockSizeInBits: number;

	public get keyLength() {
		return this.keySizeInBits / 8;
	}
	public get blockLength() {
		return this.blockSizeInBits / 8;
	}

	public async createCipher(isEncryption: boolean, key: Buffer, iv: Buffer): Promise<Cipher> {
		const cipher = new WebCipher(
			isEncryption,
			this.algorithmName,
			this.cipherMode,
			this.keySizeInBits,
			this.blockSizeInBits,
		);
		await cipher.init(key, iv);
		return cipher;
	}

	private static getBlockSize(algorithmName: string): number {
		if (algorithmName === 'AES') {
			return 128;
		} else {
			throw new Error(`Unsupported encryption algorithm: ${algorithmName}`);
		}
	}
}

class WebCipher implements Cipher, MessageSigner, MessageVerifier {
	private key!: CryptoKey;
	private iv!: Buffer;
	private readonly associatedData!: Buffer;
	private tag: Buffer | null = null;
	private decryptBuffer!: Buffer;

	public get blockLength() {
		return this.blockSizeInBits / 8;
	}

	public constructor(
		public readonly isEncryption: boolean,
		public readonly algorithmName: string,
		public readonly cipherMode: string | null,
		public readonly keySizeInBits: number,
		public readonly blockSizeInBits: number,
	) {
		if (this.algorithmName === 'AES' && this.cipherMode === 'CTR') {
			this.transform = this.aesCtr.bind(this, isEncryption);
		} else if (this.algorithmName === 'AES' && this.cipherMode === 'CBC') {
			this.transform = this.aesCbc.bind(this, isEncryption);
		} else if (this.algorithmName === 'AES' && this.cipherMode === 'GCM') {
			this.transform = this.aesGcm.bind(this, isEncryption);
			this.associatedData = Buffer.alloc(4);
			this.decryptBuffer = Buffer.alloc(this.blockLength * 4);
		} else {
			throw new Error(
				`Unsupported encryption algorithm: ${this.algorithmName}-${this.cipherMode}`,
			);
		}
	}

	public async init(key: Buffer, iv: Buffer): Promise<void> {
		try {
			const name = `${this.algorithmName}-${this.cipherMode}`;
			this.key = await crypto.subtle.importKey(
				'raw',
				key,
				<AesKeyAlgorithm>{ name, length: this.keySizeInBits },
				false,
				this.isEncryption ? ['encrypt'] : ['decrypt'],
			);
		} catch (e) {
			throw new Error('Failed to initialize AES: ' + e);
		}

		if (this.cipherMode === 'GCM') {
			this.iv = Buffer.from(iv.slice(0, 12));
		} else {
			this.iv = Buffer.from(iv);
		}
	}

	public readonly transform: (data: Buffer) => Promise<Buffer>;

	private async aesCtr(isEncryption: boolean, data: Buffer): Promise<Buffer> {
		if (data.length % this.blockLength !== 0) {
			const message =
				'Encrypt/decrypt input has invalid length ' +
				`${data.length}, not a multiple of block size ${this.blockLength}.`;
			throw new Error(message);
		}

		let result: Buffer;
		if (isEncryption) {
			result = Buffer.from(
				await crypto.subtle.encrypt(
					{ name: 'AES-CTR', counter: this.iv, length: this.blockSizeInBits },
					this.key,
					data,
				),
			);
		} else {
			result = Buffer.from(
				await crypto.subtle.decrypt(
					{ name: 'AES-CTR', counter: this.iv, length: this.blockSizeInBits },
					this.key,
					data,
				),
			);
		}

		if (result.length !== data.length) {
			const message =
				'Result from encrypt/decrypt has invalid length ' +
				`${result.length}, expected ${data.length}.`;
			throw new Error(message);
		}

		// A single call to encrypt() or decrypt() internally increments the counter.
		// This code ensures those increments get preserved across multiple calls.
		const incrementCount = data.length / this.blockLength;
		for (let i = 0; i < incrementCount; i++) {
			// Increment the counter that is combined with the IV as a big-endian integer.
			// First increment the last byte, and if it reaches 0 then increment the
			// next-to-last byte, and so on.
			for (let k = this.iv.length - 1; k >= 0; k--) {
				this.iv[k] = this.iv[k] + 1;
				if (this.iv[k]) break;
			}
		}

		return result;
	}

	private async aesCbc(isEncryption: boolean, data: Buffer): Promise<Buffer> {
		// TODO: Fix padding. Web crypto's AES-CBC uses padding by default,
		// which isn't compatible with SSH.
		if (isEncryption) {
			let result = Buffer.from(
				await crypto.subtle.encrypt({ name: 'AES-CBC', iv: this.iv }, this.key, data),
			);
			result = result.slice(0, data.length);
			return result;
		} else {
			return Buffer.from(
				await crypto.subtle.decrypt({ name: 'AES-CBC', iv: this.iv }, this.key, data),
			);
		}
	}

	private async aesGcm(isEncryption: boolean, data: Buffer): Promise<Buffer> {
		if (data.length % this.blockLength !== 0) {
			const message =
				'Encrypt/decrypt input has invalid length ' +
				`${data.length}, not a multiple of block size ${this.blockLength}.`;
			throw new Error(message);
		}

		// Associated data is the 32-bit packet length.
		const packetLength = data.length;
		this.associatedData[0] = packetLength >>> 24;
		this.associatedData[1] = packetLength >>> 16;
		this.associatedData[2] = packetLength >>> 8;
		this.associatedData[3] = packetLength;

		let result: Buffer;
		if (isEncryption) {
			result = Buffer.from(
				await crypto.subtle.encrypt(
					{
						name: 'AES-GCM',
						iv: this.iv,
						additionalData: this.associatedData,
						tagLength: this.digestLength * 8, // tagLength is in bits, not bytes
					},
					this.key,
					data,
				),
			);

			this.tag = result.slice(result.length - this.digestLength);
			result = result.slice(0, result.length - this.digestLength);
		} else {
			if (!this.tag) {
				throw new Error('AES-GCM tag was not set before decrypting.');
			}

			// The AES-GCM decrypt API expects the ciphertext and tag to be in a contiguous buffer.
			// Re-use a temporary buffer for that purpose, expanding it as needed.
			const inputLength = data.length + this.digestLength;
			if (this.decryptBuffer.length < inputLength) {
				let newLength = this.decryptBuffer.length * 2;
				while (newLength < inputLength) newLength *= 2;
				this.decryptBuffer = Buffer.alloc(newLength);
			}

			const input = this.decryptBuffer.slice(0, inputLength);
			data.copy(input, 0);
			this.tag.copy(input, data.length);

			result = Buffer.from(
				await crypto.subtle.decrypt(
					{
						name: 'AES-GCM',
						iv: this.iv,
						additionalData: this.associatedData,
						tagLength: this.digestLength * 8, // tagLength is in bits, not bytes
					},
					this.key,
					input,
				),
			);
		}

		if (result.length !== data.length) {
			const message =
				'Result from encrypt/decrypt has invalid length ' +
				`${result.length}, expected ${data.length}.`;
			throw new Error(message);
		}

		// Increment the counter (last 8 bytes of the iv/nonce) as a big-endian integer.
		// First increment the last byte, and if it reaches 0 then increment the
		// next-to-last byte, and so on.
		let k = 12;
		while (--k >= 4) {
			this.iv[k]++;
			if (this.iv[k] !== 0) {
				break;
			}
		}

		return result;
	}

	public get digestLength(): number {
		return 16;
	}

	public get authenticatedEncryption(): boolean {
		return this.cipherMode === 'GCM';
	}

	public async sign(data: Buffer): Promise<Buffer> {
		if (!this.tag) {
			throw new Error('AES-GCM tag was not obtained by encrypting.');
		}

		return this.tag;
	}

	public async verify(data: Buffer, signature: Buffer): Promise<boolean> {
		if (signature.length !== this.digestLength) {
			throw new Error('Incorrect AES-GCM tag length.');
		}

		this.tag = signature;
		return true;
	}

	public dispose(): void {}
}
