//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as crypto from 'crypto';
import { Buffer } from 'buffer';
import { PublicKeyAlgorithm, KeyPair, ECParameters } from '../publicKeyAlgorithm';
import { Signer, Verifier } from '../hmacAlgorithm';
import { ECCurve, curves } from '../ecdsaCurves';
import { BigInt } from '../../io/bigInt';
import { DerReader, DerWriter } from '../../io/derData';
import { SshDataReader, SshDataWriter, formatBuffer } from '../../io/sshData';
import { NodeHmac } from './nodeHmac';
import { formatPem, parsePem, Sec1KeyFormatter } from './keyFormatters';

const nodeVersionParts = process.versions.node.split('.').map((v) => parseInt(v, 10));
const nodeGenerateKeyPairSupport =
	nodeVersionParts[0] > 10 || (nodeVersionParts[0] === 10 && nodeVersionParts[1] >= 12);
const nodeKeyObjectSupport =
	nodeVersionParts[0] > 11 || (nodeVersionParts[0] === 11 && nodeVersionParts[1] >= 6);

class NodeECDsaKeyPair implements KeyPair {
	private algorithm!: string;

	/* @internal */
	public curve!: ECCurve;

	/* @internal */
	public publicKey?: crypto.KeyObject | string;

	/* @internal */
	public privateKey?: crypto.KeyObject | string;

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

	public generate(): Promise<void> {
		if (nodeGenerateKeyPairSupport && nodeKeyObjectSupport) {
			return this.generateNodeKeyPairObjects();
		} else if (nodeGenerateKeyPairSupport) {
			return this.generateNodeKeyPairBuffers();
		} else {
			return this.generateExternalKeyPair();
		}
	}

	private async generateNodeKeyPairObjects(): Promise<void> {
		[this.publicKey, this.privateKey] = await new Promise((resolve, reject) => {
			const keyGenParams: crypto.ECKeyPairKeyObjectOptions = {
				namedCurve: this.curve.shortName,
			};
			try {
				crypto.generateKeyPair('ec', keyGenParams, (err, publicKey, privateKey) => {
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

	private async generateNodeKeyPairBuffers(): Promise<void> {
		[this.publicKey, this.privateKey] = await new Promise((resolve, reject) => {
			const keyGenParams: crypto.ECKeyPairOptions<'pem', 'pem'> = {
				namedCurve: this.curve.shortName,
				publicKeyEncoding: { type: 'spki', format: 'pem' },
				privateKeyEncoding: {
					type: 'sec1',
					format: 'pem',
					cipher: <any>undefined,
					passphrase: <any>undefined,
				},
			};
			try {
				crypto.generateKeyPair('ec', keyGenParams, (err, publicKey, privateKey) => {
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

	private async generateExternalKeyPair(): Promise<void> {
		throw new Error(
			'This version of node does not support generating key pairs. Use node >= 10.12.',
		);
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
		this.algorithmName = `ecdsa-sha2-${curveName}`;

		const xy = reader.readBinary();
		const x = BigInt.fromBytes(xy.slice(1, 1 + (xy.length - 1) / 2), { unsigned: true });
		const y = BigInt.fromBytes(xy.slice(1 + (xy.length - 1) / 2), { unsigned: true });
		const derKeyBytes = Sec1KeyFormatter.formatECPublic({
			curve: { name: this.curve.name, oid: this.curve.oid },
			x,
			y,
		});

		if (nodeKeyObjectSupport) {
			this.publicKey = crypto.createPublicKey({
				key: derKeyBytes,
				type: 'spki',
				format: 'der',
			});
		} else {
			this.publicKey = formatPem(derKeyBytes, 'PUBLIC KEY');
		}
	}

	public async getPublicKeyBytes(algorithmName?: string): Promise<Buffer | null> {
		if (!this.publicKey) {
			return null;
		}

		let derKeyBytes: Buffer;
		if (typeof this.publicKey === 'string') {
			derKeyBytes = parsePem(this.publicKey);
		} else {
			derKeyBytes = <Buffer>this.publicKey.export({
				type: 'spki',
				format: 'der',
			});
		}

		const ec = Sec1KeyFormatter.parseECPublic(derKeyBytes);

		// Write public key in SSH format.
		algorithmName = algorithmName || this.algorithmName || this.keyAlgorithmName;
		const keyWriter = new SshDataWriter(Buffer.alloc(512));
		keyWriter.writeString(algorithmName, 'ascii');
		keyWriter.writeString(this.curve.name, 'ascii');

		const keySizeInBytes = Math.ceil(this.curve.keySize / 8);
		const xBytes = ec.x.toBytes({ unsigned: true, length: keySizeInBytes });
		const yBytes = ec.y.toBytes({ unsigned: true, length: keySizeInBytes });
		keyWriter.writeUInt32(1 + xBytes.length + yBytes.length);
		keyWriter.writeByte(4); // Indicates uncompressed curve format
		keyWriter.write(xBytes);
		keyWriter.write(yBytes);

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

		const publicKeyBytes = Sec1KeyFormatter.formatECPublic(parameters);
		if (nodeKeyObjectSupport) {
			this.publicKey = crypto.createPublicKey({
				key: publicKeyBytes,
				type: 'spki',
				format: 'der',
			});
		} else {
			this.publicKey = formatPem(publicKeyBytes, 'EC PUBLIC KEY');
		}

		if (parameters.d) {
			const privateKeyBytes = Sec1KeyFormatter.formatECPrivate(parameters);
			if (nodeKeyObjectSupport) {
				this.privateKey = crypto.createPrivateKey({
					key: privateKeyBytes,
					type: 'sec1',
					format: 'der',
				});
			} else {
				this.privateKey = formatPem(privateKeyBytes, 'EC PRIVATE KEY');
			}
		} else {
			this.privateKey = undefined;
		}
	}

	public async exportParameters(): Promise<ECParameters> {
		if (!this.publicKey) {
			throw new Error('Key is not present.');
		}

		let derKeyBytes: Buffer;
		if (typeof this.publicKey === 'string') {
			derKeyBytes = parsePem(<string>this.privateKey ?? this.publicKey);
		} else {
			derKeyBytes = <Buffer>(<crypto.KeyObject>this.privateKey ?? this.publicKey).export({
				type: this.privateKey ? 'sec1' : 'spki',
				format: 'der',
			});
		}

		return this.privateKey
			? Sec1KeyFormatter.parseECPrivate(derKeyBytes)
			: Sec1KeyFormatter.parseECPublic(derKeyBytes);
	}

	public dispose(): void {}
}

export class NodeECDsa extends PublicKeyAlgorithm {
	public static readonly ecdsaSha2Nistp256 = 'ecdsa-sha2-nistp256';
	public static readonly ecdsaSha2Nistp384 = 'ecdsa-sha2-nistp384';
	public static readonly ecdsaSha2Nistp521 = 'ecdsa-sha2-nistp521';

	public constructor(name: string, hashAlgorithmName: string) {
		super(
			name,
			name, // The key algorithm name is the same (unlike RSA).
			hashAlgorithmName,
		);
	}

	public static curves = curves;

	public createKeyPair(): KeyPair {
		return new NodeECDsaKeyPair(this.name);
	}

	public async generateKeyPair(): Promise<KeyPair> {
		const ecdsaKey = new NodeECDsaKeyPair(this.name);
		await ecdsaKey.generate();
		return ecdsaKey;
	}

	public createSigner(keyPair: KeyPair): Signer {
		if (!(keyPair instanceof NodeECDsaKeyPair)) {
			throw new TypeError('ECDSA key pair object expected.');
		}

		return new NodeECDsaSignerVerifier(
			keyPair,
			NodeECDsa.convertHashAlgorithmName(this.hashAlgorithmName),
		);
	}

	public createVerifier(keyPair: KeyPair): Verifier {
		if (!(keyPair instanceof NodeECDsaKeyPair)) {
			throw new TypeError('ECDSA key pair object expected.');
		}

		return new NodeECDsaSignerVerifier(
			keyPair,
			NodeECDsa.convertHashAlgorithmName(this.hashAlgorithmName),
		);
	}

	private static convertHashAlgorithmName(hashAlgorithmName: string) {
		return hashAlgorithmName.replace('SHA2-', 'SHA');
	}

	/* @internal */
	public static getSignatureLength(keySizeInBits: number) {
		// The signature is double the key size, but formatted as 2 bigints.
		// To each bigint add 4 for the length and 1 for a leading zero.
		const keySizeInBytes = Math.ceil(keySizeInBits / 8);
		return (4 + 1 + keySizeInBytes) * 2;
	}

	public static readonly KeyPair = NodeECDsaKeyPair;
}

class NodeECDsaSignerVerifier implements Signer, Verifier {
	public constructor(
		private readonly keyPair: NodeECDsaKeyPair,
		private readonly hashAlgorithmName: string,
	) {}

	public get digestLength(): number {
		const curve = this.keyPair.curve;
		if (!curve) {
			return 0;
		} else {
			return NodeECDsa.getSignatureLength(curve.keySize);
		}
	}

	public async sign(data: Buffer): Promise<Buffer> {
		if (!this.keyPair.privateKey) {
			throw new Error('Private key not set.');
		}

		const signer = crypto.createSign(this.hashAlgorithmName);
		signer.update(data);
		let signature = signer.sign(this.keyPair.privateKey);

		// Reformat the signature integer bytes as required by SSH.
		const signatureReader = new DerReader(signature);
		const x = signatureReader.readInteger();
		const y = signatureReader.readInteger();
		const keySizeInBytes = Math.ceil(this.keyPair.curve.keySize / 8);
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

		// Reformat the signature integer bytes as required by node.
		const signatureReader = new SshDataReader(signature);
		const x = signatureReader.readBigInt();
		const y = signatureReader.readBigInt();
		const signatureWriter = new DerWriter(Buffer.alloc(signature.length));
		signatureWriter.writeInteger(x);
		signatureWriter.writeInteger(y);
		signature = signatureWriter.toBuffer();

		const verifier = crypto.createVerify(this.hashAlgorithmName);
		verifier.update(data);
		const result = verifier.verify(this.keyPair.publicKey, signature);
		return result;
	}

	public dispose(): void {}
}
