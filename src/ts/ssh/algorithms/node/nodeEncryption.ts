//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as crypto from 'crypto';
import { Buffer } from 'buffer';

import { EncryptionAlgorithm, Cipher } from '../encryptionAlgorithm';
import { MessageSigner, MessageVerifier } from '../hmacAlgorithm';

export class NodeEncryption extends EncryptionAlgorithm {
	public constructor(
		name: string,
		public readonly algorithmName: string,
		public readonly cipherMode: string | null,
		public readonly keySizeInBits: number,
	) {
		super(name);

		if (algorithmName !== 'AES') {
			throw new Error(`Unsupported encryption algorithm: ${algorithmName}`);
		}

		this.blockSizeInBits = NodeEncryption.getBlockSize(algorithmName);
	}

	public readonly blockSizeInBits: number;

	public get keyLength() {
		return this.keySizeInBits / 8;
	}
	public get blockLength() {
		return this.blockSizeInBits / 8;
	}

	public async createCipher(isEncryption: boolean, key: Buffer, iv: Buffer): Promise<Cipher> {
		let cipher: NodeAesCipher | NodeAesGcmCipher;

		if (this.cipherMode === 'CTR' || this.cipherMode === 'CBC') {
			cipher = new NodeAesCipher(
				isEncryption,
				this.keySizeInBits,
				this.blockSizeInBits,
				key,
				iv,
				this.cipherMode,
			);
		} else if (this.cipherMode === 'GCM') {
			cipher = new NodeAesGcmCipher(
				isEncryption,
				this.keySizeInBits,
				this.blockSizeInBits,
				key,
				iv,
			);
		} else {
			throw new Error(`Unsupported cipher mode: ${this.cipherMode}`);
		}

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

class NodeAesCipher implements Cipher {
	private cipher!: crypto.Cipher | crypto.Decipher;

	public constructor(
		public readonly isEncryption: boolean,
		private readonly keySizeInBits: number,
		private readonly blockSizeInBits: number,
		key: Buffer,
		iv: Buffer,
		cipherMode: 'CTR' | 'CBC',
	) {
		const nodeAlgorithm = `AES-${this.keySizeInBits}-${cipherMode}`;
		this.cipher = this.isEncryption
			? crypto.createCipheriv(nodeAlgorithm, key, iv)
			: crypto.createDecipheriv(nodeAlgorithm, key, iv);
		this.cipher.setAutoPadding(false);
	}

	public get blockLength() {
		return this.blockSizeInBits / 8;
	}

	public transform(data: Buffer): Promise<Buffer> {
		const result: Buffer = this.cipher.update(data);

		if (result.length !== data.length) {
			const message =
				'Result from encrypt/decrypt has invalid length ' +
				`${result.length}, expected ${data.length}.`;
			throw new Error(message);
		}

		return Promise.resolve(result);
	}

	public dispose(): void {}
}

class NodeAesGcmCipher implements Cipher, MessageSigner, MessageVerifier {
	private readonly algorithmName: crypto.CipherGCMTypes;
	private key!: Buffer;
	private nonce!: Buffer;
	private readonly associatedData: Buffer;
	private tag: Buffer | null = null;

	public constructor(
		public readonly isEncryption: boolean,
		private readonly keySizeInBits: number,
		private readonly blockSizeInBits: number,
		key: Buffer,
		iv: Buffer,
	) {
		this.algorithmName = <crypto.CipherGCMTypes>`aes-${this.keySizeInBits}-gcm`;

		this.key = Buffer.alloc(key.length);
		key.copy(this.key);

		// Ininitialize the nonce to the first 12 bytes of the IV. It will be incremented by each op.
		this.nonce = Buffer.alloc(12);
		iv.copy(this.nonce, 0, 0, 12);

		this.associatedData = Buffer.alloc(4);
	}

	public get blockLength() {
		return this.blockSizeInBits / 8;
	}

	public get digestLength(): number {
		return 16;
	}

	public get authenticatedEncryption(): boolean {
		return true;
	}

	public transform(data: Buffer): Promise<Buffer> {
		if (data.length % this.blockLength !== 0) {
			const message =
				'Encrypt/decrypt input has invalid length ' +
				`${data.length}, not a multiple of block size ${this.blockLength}.`;
			throw new Error(message);
		}

		const cipher = this.isEncryption
			? crypto.createCipheriv(this.algorithmName, this.key, this.nonce)
			: crypto.createDecipheriv(this.algorithmName, this.key, this.nonce);

		// Associated data is the 32-bit packet length.
		const packetLength = data.length;
		this.associatedData[0] = packetLength >>> 24;
		this.associatedData[1] = packetLength >>> 16;
		this.associatedData[2] = packetLength >>> 8;
		this.associatedData[3] = packetLength;
		cipher.setAAD(this.associatedData);

		if (!this.isEncryption) {
			if (!this.tag) {
				throw new Error('AES-GCM tag was not set before decrypting.');
			}

			(<crypto.DecipherGCM>cipher).setAuthTag(this.tag);
		}

		const result: Buffer = cipher.update(data);
		if (result.length !== data.length) {
			const message =
				'Result from encrypt/decrypt has invalid length ' +
				`${result.length}, expected ${data.length}.`;
			throw new Error(message);
		}

		cipher.final();

		if (this.isEncryption) {
			this.tag = (<crypto.CipherGCM>cipher).getAuthTag();
		} else {
			this.tag = null;
		}

		// Increment the counter (last 8 bytes of the nonce) as a big-endian integer.
		// First increment the last byte, and if it reaches 0 then increment the
		// next-to-last byte, and so on.
		let k = 12;
		while (--k >= 4) {
			this.nonce[k]++;
			if (this.nonce[k] !== 0) {
				break;
			}
		}

		return Promise.resolve(result);
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
