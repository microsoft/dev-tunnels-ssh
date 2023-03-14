//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as crypto from 'crypto';
import { Buffer } from 'buffer';
import { KeyExchangeAlgorithm, KeyExchange } from '../keyExchangeAlgorithm';
import { NodeHmac } from './nodeHmac';
import { BigInt } from '../../io/bigInt';

export class NodeDiffieHellman extends KeyExchangeAlgorithm {
	public constructor(name: string, keySizeInBits: number, hashAlgorithmName: string) {
		super(
			name,
			keySizeInBits,
			hashAlgorithmName,
			NodeHmac.getHashDigestLength(hashAlgorithmName),
		);
	}

	public createKeyExchange(): KeyExchange {
		return new NodeDiffieHellmanKex(
			this.keySizeInBits,
			NodeHmac.getNodeHashAlgorithmName(this.hashAlgorithmName),
			this.hashDigestLength,
		);
	}
}

class NodeDiffieHellmanKex implements KeyExchange {
	private dh: crypto.DiffieHellmanGroup;

	public constructor(
		bitLength: number,
		private readonly hashAlgorithmName: string,
		public readonly digestLength: number,
	) {
		switch (bitLength) {
			case 1024:
				this.dh = crypto.getDiffieHellman('modp2');
				break;
			case 2048:
				this.dh = crypto.getDiffieHellman('modp14');
				break;
			case 4096:
				this.dh = crypto.getDiffieHellman('modp16');
				break;
			default:
				throw new Error('Invalid DH bit length.');
		}
	}

	public startKeyExchange(): Promise<Buffer> {
		const exchangeValueKeys: Buffer = this.dh.generateKeys();
		const exchangeValue = BigInt.fromBytes(exchangeValueKeys, { unsigned: true }).toBytes();
		return Promise.resolve(exchangeValue);
	}

	public decryptKeyExchange(exchangeValue: Buffer): Promise<Buffer> {
		const key = this.dh.computeSecret(exchangeValue);
		const sharedSecret = BigInt.fromBytes(key, { unsigned: true }).toBytes();
		return Promise.resolve(sharedSecret);
	}

	public async sign(data: Buffer): Promise<Buffer> {
		const hash = crypto.createHash(this.hashAlgorithmName);
		hash.update(data);
		return Buffer.from(hash.digest());
	}

	public dispose(): void {}
}

export class NodeECDiffieHellman extends KeyExchangeAlgorithm {
	public constructor(name: string, keySizeInBits: number, hashAlgorithmName: string) {
		super(
			name,
			keySizeInBits,
			hashAlgorithmName,
			NodeHmac.getHashDigestLength(hashAlgorithmName),
		);
	}

	public createKeyExchange(): KeyExchange {
		return new NodeECDiffieHellmanKex(
			this.keySizeInBits,
			NodeHmac.getNodeHashAlgorithmName(this.hashAlgorithmName),
			this.hashDigestLength,
		);
	}
}

class NodeECDiffieHellmanKex implements KeyExchange {
	private ecdh: crypto.ECDH;

	public constructor(
		bitLength: number,
		private readonly hashAlgorithmName: string,
		public readonly digestLength: number,
	) {
		switch (bitLength) {
			case 256:
				this.ecdh = crypto.createECDH('prime256v1');
				break;
			case 384:
				this.ecdh = crypto.createECDH('secp384r1');
				break;
			case 521:
				this.ecdh = crypto.createECDH('secp521r1');
				break;
			default:
				throw new Error('Invalid ECDH bit length.');
		}
	}

	public startKeyExchange(): Promise<Buffer> {
		const exchangeValue = this.ecdh.generateKeys();
		return Promise.resolve(exchangeValue);
	}

	public decryptKeyExchange(exchangeValue: Buffer): Promise<Buffer> {
		const sharedSecretBytes = this.ecdh.computeSecret(exchangeValue);
		const sharedSecret = BigInt.fromBytes(sharedSecretBytes, { unsigned: true }).toBytes();
		return Promise.resolve(sharedSecret);
	}

	public async sign(data: Buffer): Promise<Buffer> {
		const hash = crypto.createHash(this.hashAlgorithmName);
		hash.update(data);
		return Buffer.from(hash.digest());
	}

	public dispose(): void {}
}
