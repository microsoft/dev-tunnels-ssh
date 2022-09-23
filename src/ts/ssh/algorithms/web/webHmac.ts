//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { HmacAlgorithm, MessageSigner, MessageVerifier } from '../hmacAlgorithm';

export class WebHmac extends HmacAlgorithm {
	public constructor(
		name: string,
		algorithmName: string,
		public readonly encryptThenMac: boolean = false,
	) {
		super(
			name,
			algorithmName,
			WebHmac.getHashKeyLength(algorithmName),
			WebHmac.getHashDigestLength(algorithmName),
		);
	}

	public async createSigner(key: Buffer): Promise<MessageSigner> {
		const hmac = new WebSignerVerifier(
			this.algorithmName,
			true,
			this.digestLength,
			this.encryptThenMac,
		);
		await hmac.init(key);
		return hmac;
	}

	public async createVerifier(key: Buffer): Promise<MessageVerifier> {
		const hmac = new WebSignerVerifier(
			this.algorithmName,
			false,
			this.digestLength,
			this.encryptThenMac,
		);
		await hmac.init(key);
		return hmac;
	}

	public static getHashKeyLength(hashAlgorithmName: string): number {
		if (hashAlgorithmName === 'SHA2-512') return 512 / 8;
		if (hashAlgorithmName === 'SHA2-384') return 384 / 8;
		if (hashAlgorithmName === 'SHA2-256') return 256 / 8;
		throw new Error(`Unsupported hash algorithm: ${hashAlgorithmName}`);
	}

	public static getHashDigestLength(hashAlgorithmName: string): number {
		return this.getHashKeyLength(hashAlgorithmName);
	}

	public static getWebHashAlgorithmName(hashAlgorithmName: string): string {
		if (hashAlgorithmName === 'SHA2-512') return 'SHA-512';
		if (hashAlgorithmName === 'SHA2-384') return 'SHA-384';
		if (hashAlgorithmName === 'SHA2-256') return 'SHA-256';
		throw new Error(`Unsupported hash algorithm: ${hashAlgorithmName}`);
	}
}

class WebSignerVerifier implements MessageSigner, MessageVerifier {
	private key!: CryptoKey;

	public constructor(
		public readonly algorithmName: string,
		public readonly isSigning: boolean,
		public readonly digestLength: number,
		public readonly encryptThenMac: boolean,
	) {}

	public async init(key: Buffer): Promise<void> {
		try {
			const name = this.algorithmName.replace('SHA2-', 'SHA-');
			this.key = await crypto.subtle.importKey(
				'raw',
				key,
				{ name: 'HMAC', hash: { name } },
				false,
				this.isSigning ? ['sign'] : ['verify'],
			);
		} catch (e) {
			throw new Error('Failed to initialize HMAC: ' + e);
		}
	}

	public async sign(data: Buffer): Promise<Buffer> {
		return Buffer.from(
			await crypto.subtle.sign(
				{ name: 'HMAC', hash: { name: this.algorithmName } },
				this.key,
				data,
			),
		);
	}

	public async verify(data: Buffer, signature: Buffer): Promise<boolean> {
		return await crypto.subtle.verify(
			{ name: 'HMAC', hash: { name: this.algorithmName } },
			this.key,
			signature,
			data,
		);
	}

	public dispose(): void {}
}
