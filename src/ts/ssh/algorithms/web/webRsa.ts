//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { PublicKeyAlgorithm, KeyPair, RsaParameters } from '../publicKeyAlgorithm';
import { WebHmac } from './webHmac';
import { SshDataReader, SshDataWriter } from '../../io/sshData';
import { Signer, Verifier } from '../hmacAlgorithm';
import { JsonWebKeyFormatter } from './jsonWebKeyFormatter';

// Note this is exposed as an inner-class property below: `WebRsa.KeyPair`.
// TypeScript requires that the class definition comes first.
class WebRsaKeyPair implements KeyPair {
	private static readonly defaultKeySize = 2048;

	/* @internal */
	public publicKey?: CryptoKey;
	/* @internal */
	public privateKey?: CryptoKey;

	/* @internal */
	public constructor(public readonly hashAlgorithm: string) {}

	public get hasPublicKey(): boolean {
		return !!this.publicKey;
	}
	public get hasPrivateKey(): boolean {
		return !!this.privateKey;
	}

	public get keyAlgorithmName(): string {
		return WebRsa.keyAlgorithmName;
	}

	public comment: string | null = null;

	public async generate(keySizeInBits?: number): Promise<void> {
		keySizeInBits = keySizeInBits ?? WebRsaKeyPair.defaultKeySize;

		try {
			const keyGenParams: RsaHashedKeyGenParams = {
				name: 'RSASSA-PKCS1-v1_5',
				modulusLength: keySizeInBits,
				publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
				hash: { name: this.hashAlgorithm },
			};
			const keyPair = <CryptoKeyPair>(
				await crypto.subtle.generateKey(keyGenParams, true, ['sign', 'verify'])
			);
			this.publicKey = keyPair.publicKey;
			this.privateKey = keyPair.privateKey;
		} catch (e) {
			throw new Error('Failed to generate RSA key pair: ' + e);
		}
	}

	public async setPublicKeyBytes(keyBytes: Buffer): Promise<void> {
		if (!keyBytes) {
			throw new TypeError('Buffer is required.');
		}

		// Read public key in SSH format.
		const reader = new SshDataReader(keyBytes);
		const algorithmName = reader.readString('ascii');
		if (
			algorithmName !== this.keyAlgorithmName &&
			algorithmName !== WebRsa.rsaWithSha256 &&
			algorithmName !== WebRsa.rsaWithSha512
		) {
			throw new Error(`Invalid RSA key algorithm: ${algorithmName}`);
		}

		const exponent = reader.readBigInt();
		const modulus = reader.readBigInt();

		// Import public key in JWK format.
		const jwk = JsonWebKeyFormatter.formatRsa({ modulus, exponent }, false);
		jwk.alg = 'RS' + this.hashAlgorithm.replace('SHA-', '');
		jwk.key_ops = ['verify'];

		try {
			const importParams: RsaHashedImportParams = {
				name: 'RSASSA-PKCS1-v1_5',
				hash: { name: this.hashAlgorithm },
			};
			this.publicKey = await crypto.subtle.importKey('jwk', jwk, importParams, true, ['verify']);
		} catch (e) {
			throw new Error('Failed to import RSA public key: ' + e);
		}
	}

	public async getPublicKeyBytes(algorithmName?: string): Promise<Buffer | null> {
		if (!this.publicKey) {
			return null;
		}

		if (!algorithmName) {
			algorithmName = this.keyAlgorithmName;
		}

		// Export public key in JWK format.
		let jwk: JsonWebKey;
		try {
			jwk = await crypto.subtle.exportKey('jwk', this.publicKey);
		} catch (e) {
			throw new Error('Failed to export RSA public key: ' + e);
		}

		const { modulus, exponent } = JsonWebKeyFormatter.parseRsa(jwk, false);

		// Write public key in SSH format.
		const keyBuffer = Buffer.alloc(512);
		const keyWriter = new SshDataWriter(keyBuffer);
		keyWriter.writeString(algorithmName, 'ascii');
		keyWriter.writeBigInt(exponent);
		keyWriter.writeBigInt(modulus);
		const keyBytes = keyWriter.toBuffer();

		return keyBytes;
	}

	public async importParameters(parameters: RsaParameters): Promise<void> {
		const privateJwk = parameters.d ? JsonWebKeyFormatter.formatRsa(parameters, true) : null;
		const publicJwk = JsonWebKeyFormatter.formatRsa(parameters, false);
		const importParams: RsaHashedImportParams = {
			name: 'RSASSA-PKCS1-v1_5',
			hash: { name: this.hashAlgorithm },
		};
		try {
			this.publicKey = await crypto.subtle.importKey('jwk', publicJwk, importParams, true, [
				'verify',
			]);
			if (privateJwk) {
				this.privateKey = await crypto.subtle.importKey('jwk', privateJwk, importParams, true, [
					'sign',
				]);
			} else {
				this.privateKey = undefined;
			}
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			throw new Error('Failed to import RSA key pair: ' + e.message);
		}
	}

	public async exportParameters(): Promise<RsaParameters> {
		if (!this.publicKey) throw new Error('Public key not set.');

		let jwk: JsonWebKey;
		try {
			jwk = await crypto.subtle.exportKey('jwk', this.privateKey ?? this.publicKey);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			throw new Error('Failed to export RSA public key: ' + e.message);
		}

		return JsonWebKeyFormatter.parseRsa(jwk, !!this.privateKey);
	}

	public dispose(): void {}
}

export class WebRsa extends PublicKeyAlgorithm {
	public static readonly keyAlgorithmName = 'ssh-rsa';

	public static readonly rsaWithSha256 = 'rsa-sha2-256';
	public static readonly rsaWithSha512 = 'rsa-sha2-512';

	public constructor(name: string, hashAlgorithmName: string) {
		super(name, WebRsa.keyAlgorithmName, hashAlgorithmName);
	}

	public createKeyPair(): KeyPair {
		const hashAlgorithm = WebRsa.convertHashAlgorithmName(this.hashAlgorithmName);
		return new WebRsaKeyPair(hashAlgorithm);
	}

	public async generateKeyPair(keySizeInBits?: number): Promise<KeyPair> {
		const hashAlgorithm = WebRsa.convertHashAlgorithmName(this.hashAlgorithmName);
		const rsaKey = new WebRsaKeyPair(hashAlgorithm);
		await rsaKey.generate(keySizeInBits);
		return rsaKey;
	}

	public createSigner(keyPair: KeyPair): Signer {
		if (!(keyPair instanceof WebRsaKeyPair)) {
			throw new TypeError('RSA key pair object expected.');
		}

		const hashAlgorithm = WebRsa.convertHashAlgorithmName(this.hashAlgorithmName);
		return new WebRsaSignerVerifier(
			keyPair,
			hashAlgorithm,
			WebHmac.getHashDigestLength(this.hashAlgorithmName),
		);
	}

	public createVerifier(keyPair: KeyPair): Verifier {
		if (!(keyPair instanceof WebRsaKeyPair)) {
			throw new TypeError('RSA key pair object expected.');
		}

		const hashAlgorithm = WebRsa.convertHashAlgorithmName(this.hashAlgorithmName);
		return new WebRsaSignerVerifier(
			keyPair,
			hashAlgorithm,
			WebHmac.getHashDigestLength(this.hashAlgorithmName),
		);
	}

	private static convertHashAlgorithmName(hashAlgorithmName: string) {
		return hashAlgorithmName.replace('SHA2-', 'SHA-');
	}

	// eslint-disable-next-line @typescript-eslint/tslint/config
	public static readonly KeyPair = WebRsaKeyPair;
}

class WebRsaSignerVerifier implements Signer, Verifier {
	public constructor(
		private keyPair: WebRsaKeyPair,
		private readonly hashAlgorithm: string,
		public readonly digestLength: number,
	) {}

	public async sign(data: Buffer): Promise<Buffer> {
		if (!this.keyPair.privateKey) {
			throw new Error('Private key not set.');
		}

		await this.convertKeyHashAlgorithm();

		const signature = Buffer.from(
			await crypto.subtle.sign('RSASSA-PKCS1-v1_5', this.keyPair.privateKey, data),
		);
		return signature;
	}

	public async verify(data: Buffer, signature: Buffer): Promise<boolean> {
		if (!this.keyPair.publicKey) {
			throw new Error('Public key not set.');
		}

		await this.convertKeyHashAlgorithm();

		const result = await crypto.subtle.verify(
			'RSASSA-PKCS1-v1_5',
			this.keyPair.publicKey,
			signature,
			data,
		);
		return result;
	}

	private async convertKeyHashAlgorithm(): Promise<void> {
		if (this.keyPair.hashAlgorithm !== this.hashAlgorithm) {
			const parameters = await this.keyPair.exportParameters();
			this.keyPair = new WebRsaKeyPair(this.hashAlgorithm);
			await this.keyPair.importParameters(parameters);
		}
	}

	public dispose(): void {}
}

export namespace WebRsa {
	// tslint:disable-next-line:no-shadowed-variable
	export type KeyPair = WebRsaKeyPair;
}
