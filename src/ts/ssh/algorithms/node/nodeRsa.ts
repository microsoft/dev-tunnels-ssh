//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as crypto from 'crypto';
import { Buffer } from 'buffer';
import { PublicKeyAlgorithm, KeyPair, RsaParameters } from '../publicKeyAlgorithm';
import { SshDataReader, SshDataWriter, formatBuffer } from '../../io/sshData';
import { NodeHmac } from './nodeHmac';
import { Signer, Verifier } from '../hmacAlgorithm';
import { formatPem, parsePem, Pkcs1KeyFormatter } from './keyFormatters';

const nodeVersionParts = process.versions.node.split('.').map((v) => parseInt(v, 10));
const nodeGenerateKeyPairSupport =
	nodeVersionParts[0] > 10 || (nodeVersionParts[0] === 10 && nodeVersionParts[1] >= 12);
const nodeKeyObjectSupport =
	nodeVersionParts[0] > 11 || (nodeVersionParts[0] === 11 && nodeVersionParts[1] >= 6);

// Note this is exposed as an inner-class property below: `NodeRsa.KeyPair`.
// TypeScript requires that the class definition comes first.
class NodeRsaKeyPair implements KeyPair {
	private static readonly defaultKeySize = 2048;

	/* @internal */
	public publicKey?: crypto.KeyObject | string;
	/* @internal */
	public privateKey?: crypto.KeyObject | string;

	/* @internal */
	public constructor() {}

	public get hasPublicKey() {
		return !!this.publicKey;
	}
	public get hasPrivateKey() {
		return !!this.privateKey;
	}

	public comment: string | null = null;

	public get keyAlgorithmName(): string {
		return NodeRsa.keyAlgorithmName;
	}

	public generate(keySizeInBits?: number): Promise<void> {
		keySizeInBits = keySizeInBits ?? NodeRsaKeyPair.defaultKeySize;

		if (nodeGenerateKeyPairSupport && nodeKeyObjectSupport) {
			return this.generateNodeKeyPairObjects(keySizeInBits);
		} else if (nodeGenerateKeyPairSupport) {
			return this.generateNodeKeyPairBuffers(keySizeInBits);
		} else {
			return this.generateExternalKeyPair(keySizeInBits);
		}
	}

	private async generateNodeKeyPairObjects(keySizeInBits: number): Promise<void> {
		[this.publicKey, this.privateKey] = await new Promise((resolve, reject) => {
			const keyGenParams: crypto.RSAKeyPairKeyObjectOptions = {
				modulusLength: keySizeInBits,
			};
			try {
				crypto.generateKeyPair('rsa', keyGenParams, (err, publicKey, privateKey) => {
					if (err) {
						reject(err);
					} else {
						resolve([publicKey, privateKey]);
					}
				});
			} catch (err) {
				reject(err);
			}
		});
	}

	private async generateNodeKeyPairBuffers(keySizeInBits: number): Promise<void> {
		[this.publicKey, this.privateKey] = await new Promise((resolve, reject) => {
			const keyGenParams: crypto.RSAKeyPairOptions<'pem', 'pem'> = {
				modulusLength: keySizeInBits,
				publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
				privateKeyEncoding: {
					type: 'pkcs1',
					format: 'pem',
					cipher: <any>undefined,
					passphrase: <any>undefined,
				},
			};
			try {
				crypto.generateKeyPair('rsa', keyGenParams, (err, publicKey, privateKey) => {
					if (err) {
						reject(err);
					} else {
						resolve([publicKey, privateKey]);
					}
				});
			} catch (err) {
				reject(err);
			}
		});
	}

	private async generateExternalKeyPair(keySizeInBits: number): Promise<void> {
		// When running in a version of node that doesn't have a built-in API
		// for RSA key-gen, use an external library. Note this implementation
		// is SLOW because it's pure JS. It may take 1-5 seconds to generate
		// a 2048 bit key.
		const externRsa = await import('node-rsa');
		const keyPair = new externRsa({ b: keySizeInBits });
		this.publicKey = keyPair.exportKey('pkcs1-public-pem');
		this.privateKey = keyPair.exportKey('pkcs1-private-pem');

		// Ensure the PEM format ends in a newline, just for consistency.
		if (!this.publicKey.endsWith('\n')) this.publicKey += '\n';
		if (!this.privateKey.endsWith('\n')) this.privateKey += '\n';
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
			algorithmName !== NodeRsa.rsaWithSha256 &&
			algorithmName !== NodeRsa.rsaWithSha512
		) {
			throw new Error(`Invalid RSA key algorithm: ${algorithmName}`);
		}

		const exponent = reader.readBigInt();
		const modulus = reader.readBigInt();

		// Write public key in PKCS#1 format.
		keyBytes = Pkcs1KeyFormatter.formatRsaPublic({ modulus, exponent });

		if (nodeKeyObjectSupport) {
			this.publicKey = crypto.createPublicKey({
				key: keyBytes,
				type: 'pkcs1',
				format: 'der',
			});
		} else {
			this.publicKey = formatPem(keyBytes, 'RSA PUBLIC KEY');
		}
	}

	public async getPublicKeyBytes(algorithmName?: string): Promise<Buffer | null> {
		if (!this.publicKey) {
			return null;
		}

		if (!algorithmName) {
			algorithmName = this.keyAlgorithmName;
		}

		let keyBytes: Buffer;
		if (typeof this.publicKey === 'string') {
			keyBytes = parsePem(this.publicKey);
		} else {
			keyBytes = <Buffer>this.publicKey.export({
				type: 'pkcs1',
				format: 'der',
			});
		}

		const parameters = Pkcs1KeyFormatter.parseRsaPublic(keyBytes);

		// Write public key in SSH format.
		const keyBuffer = Buffer.alloc(512);
		const keyWriter = new SshDataWriter(keyBuffer);
		keyWriter.writeString(algorithmName, 'ascii');
		keyWriter.writeBigInt(parameters.exponent);
		keyWriter.writeBigInt(parameters.modulus);
		keyBytes = keyWriter.toBuffer();

		return keyBytes;
	}

	public async importParameters(parameters: RsaParameters): Promise<void> {
		if (nodeKeyObjectSupport) {
			this.publicKey = crypto.createPublicKey({
				key: Pkcs1KeyFormatter.formatRsaPublic(parameters),
				format: 'der',
				type: 'pkcs1',
			});
			if (parameters.d) {
				this.privateKey = crypto.createPrivateKey({
					key: Pkcs1KeyFormatter.formatRsaPrivate(parameters),
					format: 'der',
					type: 'pkcs1',
				});
			} else {
				this.privateKey = undefined;
			}
		} else {
			const publicKeyBytes = Pkcs1KeyFormatter.formatRsaPublic(parameters);
			this.publicKey = formatPem(publicKeyBytes, 'RSA PUBLIC KEY');
			if (parameters.d) {
				const privateKeyBytes = Pkcs1KeyFormatter.formatRsaPrivate(parameters);
				this.privateKey = formatPem(privateKeyBytes, 'RSA PRIVATE KEY');
			}
		}
	}

	public async exportParameters(): Promise<RsaParameters> {
		if (!this.publicKey) throw new Error('Public key not set.');

		let keyBytes: Buffer;
		if (nodeKeyObjectSupport) {
			keyBytes = (<crypto.KeyObject>(this.privateKey ?? this.publicKey)).export({
				format: 'der',
				type: 'pkcs1',
			});
		} else {
			keyBytes = parsePem(<string>this.privateKey ?? <string>this.publicKey);
		}

		return this.privateKey
			? Pkcs1KeyFormatter.parseRsaPrivate(keyBytes)
			: Pkcs1KeyFormatter.parseRsaPublic(keyBytes);
	}

	public dispose(): void {
		this.publicKey = undefined;
		this.privateKey = undefined;
	}
}

export class NodeRsa extends PublicKeyAlgorithm {
	public static readonly keyAlgorithmName = 'ssh-rsa';

	public static readonly rsaWithSha256 = 'rsa-sha2-256';
	public static readonly rsaWithSha512 = 'rsa-sha2-512';

	public constructor(name: string, hashAlgorithmName: string) {
		super(name, NodeRsa.keyAlgorithmName, hashAlgorithmName);
	}

	public createKeyPair(): KeyPair {
		return new NodeRsaKeyPair();
	}

	public async generateKeyPair(keySizeInBits?: number): Promise<KeyPair> {
		const rsaKey = new NodeRsaKeyPair();
		await rsaKey.generate(keySizeInBits);
		return rsaKey;
	}

	public createSigner(keyPair: KeyPair): Signer {
		if (!(keyPair instanceof NodeRsaKeyPair)) {
			throw new TypeError('RSA key pair object expected.');
		}

		return new NodeRsaSignerVerifier(
			keyPair,
			NodeRsa.convertHashAlgorithmName(this.hashAlgorithmName),
			NodeHmac.getHashDigestLength(this.hashAlgorithmName),
		);
	}

	public createVerifier(keyPair: KeyPair): Verifier {
		if (!(keyPair instanceof NodeRsaKeyPair)) {
			throw new TypeError('RSA key pair object expected.');
		}

		return new NodeRsaSignerVerifier(
			keyPair,
			NodeRsa.convertHashAlgorithmName(this.hashAlgorithmName),
			NodeHmac.getHashDigestLength(this.hashAlgorithmName),
		);
	}

	private static convertHashAlgorithmName(hashAlgorithmName: string) {
		return hashAlgorithmName.replace('SHA2-', 'SHA');
	}

	public static readonly KeyPair = NodeRsaKeyPair;
}

class NodeRsaSignerVerifier implements Signer, Verifier {
	public constructor(
		private readonly keyPair: NodeRsaKeyPair,
		private readonly hashAlgorithmName: string,
		public readonly digestLength: number,
	) {}

	public async sign(data: Buffer): Promise<Buffer> {
		if (!this.keyPair.privateKey) {
			throw new Error('Private key not set.');
		}

		const signer = crypto.createSign(this.hashAlgorithmName);
		signer.update(data);
		const signature = signer.sign(this.keyPair.privateKey);
		return signature;
	}

	public async verify(data: Buffer, signature: Buffer): Promise<boolean> {
		if (!this.keyPair.publicKey) {
			throw new Error('Public key not set.');
		}

		const verifier = crypto.createVerify(this.hashAlgorithmName);
		verifier.update(data);
		const result = verifier.verify(this.keyPair.publicKey, signature);
		return result;
	}

	public dispose(): void {}
}
