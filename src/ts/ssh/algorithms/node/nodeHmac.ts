//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as crypto from 'crypto';
import { Buffer } from 'buffer';
import { HmacAlgorithm, MessageSigner, MessageVerifier } from '../hmacAlgorithm';

export class NodeHmac extends HmacAlgorithm {
	public constructor(
		name: string,
		algorithmName: string,
		public readonly encryptThenMac: boolean = false,
	) {
		super(
			name,
			algorithmName,
			NodeHmac.getHashKeyLength(algorithmName),
			NodeHmac.getHashDigestLength(algorithmName),
		);
	}

	public async createSigner(key: Buffer): Promise<MessageSigner> {
		const hmac = new NodeSignerVerifier(
			NodeHmac.getNodeHashAlgorithmName(this.algorithmName),
			this.digestLength,
			this.encryptThenMac,
			key,
		);
		return hmac;
	}

	public async createVerifier(key: Buffer): Promise<MessageVerifier> {
		const hmac = new NodeSignerVerifier(
			NodeHmac.getNodeHashAlgorithmName(this.algorithmName),
			this.digestLength,
			this.encryptThenMac,
			key,
		);
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

	public static getNodeHashAlgorithmName(hashAlgorithmName: string): string {
		if (hashAlgorithmName === 'SHA2-512') return 'sha512';
		if (hashAlgorithmName === 'SHA2-384') return 'sha384';
		if (hashAlgorithmName === 'SHA2-256') return 'sha256';
		throw new Error(`Unsupported hash algorithm: ${hashAlgorithmName}`);
	}
}

class NodeSignerVerifier implements MessageSigner, MessageVerifier {
	private readonly key: crypto.KeyObject | Buffer;

	public constructor(
		public readonly algorithmName: string,
		public readonly digestLength: number,
		public readonly encryptThenMac: boolean,
		key: Buffer,
	) {
		// crypto.createSecretKey is only available on node >= 11.6.
		this.key = crypto.createSecretKey ? crypto.createSecretKey(key) : Buffer.from(key);
	}

	public async sign(data: Buffer): Promise<Buffer> {
		const signer = crypto.createHmac(this.algorithmName, <any>this.key);
		signer.update(data);
		const hmac = signer.digest();
		return hmac;
	}

	public async verify(data: Buffer, signature: Buffer): Promise<boolean> {
		const verifier = crypto.createHmac(this.algorithmName, <any>this.key);
		verifier.update(data);
		const hmac = verifier.digest();
		const result = hmac.equals(signature);
		return result;
	}

	public dispose(): void {}
}
