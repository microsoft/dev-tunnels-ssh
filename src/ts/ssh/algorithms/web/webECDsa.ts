//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { PublicKeyAlgorithm, KeyPair, ECParameters } from '../publicKeyAlgorithm';
import { SshDataReader, SshDataWriter, formatBuffer } from '../../io/sshData';
import { Signer, Verifier } from '../hmacAlgorithm';
import { ECCurve, curves } from '../ecdsaCurves';
import { BigInt } from '../../io/bigInt';
import { JsonWebKeyFormatter } from './jsonWebKeyFormatter';

class WebECDsaKeyPair implements KeyPair {
	private algorithm!: string;

	/* @internal */
	public curve!: ECCurve;

	/* @internal */
	public publicKey?: CryptoKey;

	/* @internal */
	public privateKey?: CryptoKey;

	/**
	 * Constructs a new ECDSA key pair object.
	 *
	 * @param algorithmName Key pair algorithm name. If unspecified, the key pair object must be
	 * initialized before use via `importParameters()`.
	 */
	public constructor(algorithmName?: string) {
		if (algorithmName) {
			this.algorithmName = algorithmName;
		}
	}

	public get hasPublicKey() {
		return !!this.publicKey;
	}
	public get hasPrivateKey() {
		return !!this.privateKey;
	}

	public comment: string | null = null;

	public get keyAlgorithmName() {
		return this.algorithmName;
	}

	public get algorithmName() {
		return this.algorithm;
	}
	public set algorithmName(value: string) {
		const curveName = value.split('-')[2];
		this.curve = curves.find((c) => c.name === curveName)!;
		if (!this.curve) {
			throw new Error('Invalid or unsupported ECDSA algorithm: ' + value);
		}

		this.algorithm = value;
	}

	public async generate(): Promise<void> {
		try {
			const keyGenParams: EcKeyGenParams = {
				name: 'ECDSA',
				namedCurve: this.curve.shortName,
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

	public async setPublicKeyBytes(keyBytes: Buffer, algorithmName?: string): Promise<void> {
		if (!keyBytes) {
			throw new TypeError('Buffer is required.');
		}

		// Read public key in SSH format.
		const reader = new SshDataReader(keyBytes);
		const readAlgorithmName = reader.readString('ascii');
		this.algorithmName = algorithmName || readAlgorithmName;

		const curveName = reader.readString('ascii');
		if (curveName !== this.curve.name) {
			throw new Error('EC curve name does not match.');
		}

		// X and Y parameters are equal length, after a one-byte header.
		const key = reader.readBinary();
		const n = Math.ceil(this.curve.keySize / 8);
		const x = BigInt.fromBytes(key.slice(1, 1 + n), { unsigned: true });
		const y = BigInt.fromBytes(key.slice(1 + n, key.length), { unsigned: true });

		const jwk = JsonWebKeyFormatter.formatEC({
			curve: { name: this.curve.shortName, oid: this.curve.oid },
			x,
			y,
		});

		try {
			const importParams: EcKeyImportParams = {
				name: 'ECDSA',
				namedCurve: this.curve.shortName,
			};
			this.publicKey = await crypto.subtle.importKey('jwk', jwk, importParams, true, ['verify']);
		} catch (e) {
			throw new Error('Failed to import EC public key: ' + e);
		}
	}

	public async getPublicKeyBytes(algorithmName?: string | undefined): Promise<Buffer | null> {
		if (!this.publicKey) {
			return null;
		}

		// Export public key in JWK format.
		let jwk: JsonWebKey;
		try {
			jwk = await crypto.subtle.exportKey('jwk', this.publicKey);
		} catch (e) {
			throw new Error('Failed to export ECDSA public key: ' + e);
		}

		const x = Buffer.from(jwk.x!, 'base64');
		const y = Buffer.from(jwk.y!, 'base64');

		const n = Math.ceil(this.curve.keySize / 8);
		if (x.length !== n || y.length !== n) {
			throw new Error('Unexpected key length.');
		}

		// Write public key in SSH format.
		algorithmName = algorithmName || this.algorithmName || this.keyAlgorithmName;
		const keyBuffer = Buffer.alloc(algorithmName.length + x.length + y.length + 10);
		const keyWriter = new SshDataWriter(keyBuffer);
		keyWriter.writeString(algorithmName, 'ascii');
		keyWriter.writeString(this.curve.name, 'ascii');
		keyWriter.writeUInt32(1 + x.length + y.length);
		keyWriter.writeByte(4); // Indicates uncompressed curve format
		keyWriter.write(x);
		keyWriter.write(y);

		const keyBytes = keyWriter.toBuffer();
		return keyBytes;
	}

	public async importParameters(parameters: ECParameters): Promise<void> {
		if (!parameters.curve) throw new TypeError('A curve is required.');

		let curve: ECCurve | undefined;
		if (parameters.curve.oid) {
			curve = curves.find((c) => c.oid === parameters.curve.oid);
			if (!curve) {
				throw new Error(`Unsupported curve OID: ${parameters.curve.oid}`);
			}
		} else if (parameters.curve.name) {
			curve = curves.find((c) => c.name === parameters.curve.name);
			if (!curve) {
				throw new Error(`Unsupported curve: ${parameters.curve.name}`);
			}
		} else {
			throw new TypeError('A curve OID or name is required.');
		}

		this.algorithmName = 'ecdsa-sha2-' + curve.name;

		const importParams: EcKeyImportParams = {
			name: 'ECDSA',
			namedCurve: this.curve.shortName,
		};

		const jwk = JsonWebKeyFormatter.formatEC(parameters);
		jwk.crv = this.curve.shortName;

		try {
			if (jwk.d) {
				this.privateKey = await crypto.subtle.importKey('jwk', jwk, importParams, true, [
					'sign',
				]);
				jwk.d = undefined;
			} else {
				this.privateKey = undefined;
			}

			this.publicKey = await crypto.subtle.importKey('jwk', jwk, importParams, true, ['verify']);
		} catch (e) {
			throw new Error('Failed to import ECDSA key pair: ' + e);
		}
	}

	public async exportParameters(): Promise<ECParameters> {
		const exportKey = this.privateKey ?? this.publicKey;
		if (!exportKey) {
			throw new Error('Key not present.');
		}

		let jwk: JsonWebKey;
		try {
			jwk = await crypto.subtle.exportKey('jwk', exportKey);
		} catch (e) {
			throw new Error('Failed to export ECDSA key pair: ' + e);
		}

		const parameters = JsonWebKeyFormatter.parseEC(jwk);
		parameters.curve = { name: this.curve.name, oid: this.curve.oid };
		return parameters;
	}

	public dispose(): void {}
}

export class WebECDsa extends PublicKeyAlgorithm {
	public static readonly ecdsaSha2Nistp256 = 'ecdsa-sha2-nistp256';
	public static readonly ecdsaSha2Nistp384 = 'ecdsa-sha2-nistp384';
	public static readonly ecdsaSha2Nistp521 = 'ecdsa-sha2-nistp521';

	public constructor(name: string, hashAlgorithmName: string) {
		super(name, name, hashAlgorithmName);
	}

	public static curves = curves;

	public createKeyPair(): KeyPair {
		return new WebECDsaKeyPair(this.name);
	}

	public async generateKeyPair(): Promise<KeyPair> {
		const ecdsaKey = new WebECDsaKeyPair(this.name);
		await ecdsaKey.generate();
		return ecdsaKey;
	}

	public createSigner(keyPair: KeyPair): Signer {
		if (!(keyPair instanceof WebECDsaKeyPair)) {
			throw new TypeError('ECDSA key pair object expected.');
		}

		const hashAlgorithm = WebECDsa.convertHashAlgorithmName(this.hashAlgorithmName);
		return new WebECDsaSignerVerifier(keyPair, hashAlgorithm);
	}

	public createVerifier(keyPair: KeyPair): Verifier {
		if (!(keyPair instanceof WebECDsaKeyPair)) {
			throw new TypeError('ECDSA key pair object expected.');
		}

		const hashAlgorithm = WebECDsa.convertHashAlgorithmName(this.hashAlgorithmName);
		return new WebECDsaSignerVerifier(keyPair, hashAlgorithm);
	}

	private static convertHashAlgorithmName(hashAlgorithmName: string) {
		return hashAlgorithmName.replace('SHA2-', 'SHA-');
	}

	/* @internal */
	public static getSignatureLength(keySizeInBits: number) {
		// The signature is double the key size, but formatted as 2 bigints.
		// To each bigint add 4 for the length and 1 for a leading zero.
		const keySizeInBytes = Math.ceil(keySizeInBits / 8);
		return (4 + 1 + keySizeInBytes) * 2;
	}

	public static readonly KeyPair = WebECDsaKeyPair;
}

class WebECDsaSignerVerifier implements Signer, Verifier {
	public constructor(private keyPair: WebECDsaKeyPair, private readonly hashAlgorithm: string) {}

	public get digestLength(): number {
		const curve = this.keyPair.curve;
		if (!curve) {
			return 0;
		} else {
			return WebECDsa.getSignatureLength(curve.keySize);
		}
	}

	public async sign(data: Buffer): Promise<Buffer> {
		if (!this.keyPair.privateKey) {
			throw new Error('Private key not set.');
		}

		let signature = Buffer.from(
			await crypto.subtle.sign(
				{ name: 'ECDSA', hash: { name: this.hashAlgorithm } },
				this.keyPair.privateKey,
				data,
			),
		);

		const keySizeInBytes = Math.ceil(this.keyPair.curve.keySize / 8);
		if (signature.length !== 2 * keySizeInBytes) {
			throw new Error(`Unexpected signature length: ${signature.length}`);
		}

		// Reformat the signature integer bytes as required by SSH.
		const x = BigInt.fromBytes(signature.slice(0, keySizeInBytes), { unsigned: true });
		const y = BigInt.fromBytes(signature.slice(keySizeInBytes, signature.length), {
			unsigned: true,
		});
		const signatureWriter = new SshDataWriter(Buffer.alloc(this.digestLength));
		signatureWriter.writeBinary(x.toBytes({ unsigned: true, length: keySizeInBytes + 1 }));
		signatureWriter.writeBinary(y.toBytes({ unsigned: true, length: keySizeInBytes + 1 }));
		signature = signatureWriter.toBuffer();

		return signature;
	}

	public async verify(data: Buffer, signature: Buffer): Promise<boolean> {
		if (!this.keyPair.publicKey) {
			throw new Error('Public key not set.');
		}

		// Reformat the signature integer bytes as required by the web crypto API.
		const signatureReader = new SshDataReader(signature);
		const x = signatureReader.readBigInt();
		const y = signatureReader.readBigInt();
		const keySizeInBytes = Math.ceil(this.keyPair.curve.keySize / 8);
		signature = Buffer.alloc(2 * keySizeInBytes);
		x.toBytes({ unsigned: true, length: keySizeInBytes }).copy(signature, 0);
		y.toBytes({ unsigned: true, length: keySizeInBytes }).copy(signature, keySizeInBytes);

		const result = await crypto.subtle.verify(
			{ name: 'ECDSA', hash: { name: this.hashAlgorithm } },
			this.keyPair.publicKey,
			signature,
			data,
		);
		return result;
	}

	public dispose(): void {}
}

// eslint-disable-next-line no-redeclare
export namespace WebECDsa {
	// eslint-disable-next-line no-shadow, @typescript-eslint/no-shadow
	export type KeyPair = WebECDsaKeyPair;
}
