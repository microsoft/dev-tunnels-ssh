//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { getDiffieHellman } from 'diffie-hellman';
import { KeyExchangeAlgorithm, KeyExchange } from '../keyExchangeAlgorithm';
import { WebHmac } from './webHmac';
import { BigInt } from '../../io/bigInt';
import { JsonWebKeyFormatter } from './jsonWebKeyFormatter';

export class WebDiffieHellman extends KeyExchangeAlgorithm {
	public constructor(name: string, keySizeInBits: number, hashAlgorithmName: string) {
		super(name, keySizeInBits, hashAlgorithmName, WebHmac.getHashDigestLength(hashAlgorithmName));
	}

	public createKeyExchange(): KeyExchange {
		return new WebDiffieHellmanKex(
			this.keySizeInBits,
			WebHmac.getWebHashAlgorithmName(this.hashAlgorithmName),
			this.hashDigestLength,
		);
	}
}
class WebDiffieHellmanKex implements KeyExchange {
	private dh: ReturnType<typeof getDiffieHellman>;

	public constructor(
		bitLength: number,
		private readonly hashAlgorithmName: string,
		public readonly digestLength: number,
	) {
		switch (bitLength) {
			case 1024:
				this.dh = getDiffieHellman('modp2');
				break;
			case 2048:
				this.dh = getDiffieHellman('modp14');
				break;
			case 4096:
				this.dh = getDiffieHellman('modp16');
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
		const hashBuffer = await crypto.subtle.digest(this.hashAlgorithmName, data);
		return Buffer.from(hashBuffer);
	}

	public dispose(): void {}
}

export class WebECDiffieHellman extends KeyExchangeAlgorithm {
	public constructor(name: string, keySizeInBits: number, hashAlgorithmName: string) {
		super(name, keySizeInBits, hashAlgorithmName, WebHmac.getHashDigestLength(hashAlgorithmName));
	}

	public createKeyExchange(): KeyExchange {
		return new WebECDiffieHellmanKex(
			this.keySizeInBits,
			WebHmac.getWebHashAlgorithmName(this.hashAlgorithmName),
			this.hashDigestLength,
		);
	}
}
class WebECDiffieHellmanKex implements KeyExchange {
	private keyPair?: CryptoKeyPair;
	private algorithm: EcKeyGenParams | EcKeyImportParams;

	public constructor(
		private bitLength: number,
		private readonly hashAlgorithmName: string,
		public readonly digestLength: number,
	) {
		this.algorithm = {
			name: 'ECDH',
			namedCurve: 'P-' + bitLength,
		};
	}

	public async startKeyExchange(): Promise<Buffer> {
		if (!this.keyPair) {
			this.keyPair = <CryptoKeyPair>await crypto.subtle.generateKey(
				this.algorithm,
				true, // exportable
				['deriveBits'],
			);
		}

		const jwk = await crypto.subtle.exportKey('jwk', this.keyPair.publicKey!);
		const ec = JsonWebKeyFormatter.parseEC(jwk);

		const length = Math.ceil(this.bitLength / 8);
		const publicKeyBytes = Buffer.alloc(1 + length * 2);
		publicKeyBytes[0] = 4;
		ec.x.toBytes({ unsigned: true, length }).copy(publicKeyBytes, 1);
		ec.y.toBytes({ unsigned: true, length }).copy(publicKeyBytes, 1 + length);

		return Buffer.from(publicKeyBytes);
	}

	public async decryptKeyExchange(exchangeValue: Buffer): Promise<Buffer> {
		if (!this.keyPair) {
			throw new Error('Key exchange not started.');
		}

		const xy = exchangeValue;
		const jwk = JsonWebKeyFormatter.formatEC({
			curve: { name: this.algorithm.namedCurve },
			x: BigInt.fromBytes(xy.slice(1, 1 + (xy.length - 1) / 2), { unsigned: true }),
			y: BigInt.fromBytes(xy.slice(1 + (xy.length - 1) / 2), { unsigned: true }),
		});
		const otherPublicKey = await crypto.subtle.importKey('jwk', jwk, this.algorithm, false, []);

		const sharedSecretBytes = Buffer.from(
			await crypto.subtle.deriveBits(
				{
					...this.algorithm,
					public: otherPublicKey,
				},
				this.keyPair.privateKey!,
				Math.ceil(this.bitLength / 8) * 8, // Round up to next byte
			),
		);
		const sharedSecret = BigInt.fromBytes(sharedSecretBytes, { unsigned: true }).toBytes();
		return sharedSecret;
	}

	public async sign(data: Buffer): Promise<Buffer> {
		const hashBuffer = await crypto.subtle.digest(this.hashAlgorithmName, data);
		return Buffer.from(hashBuffer);
	}

	public dispose(): void {}
}
