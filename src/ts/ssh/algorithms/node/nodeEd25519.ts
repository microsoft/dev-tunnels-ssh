//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as crypto from 'crypto';
import { Buffer } from 'buffer';
import { PublicKeyAlgorithm, KeyPair, EdDSAParameters } from '../publicKeyAlgorithm';
import { Signer, Verifier } from '../hmacAlgorithm';
import { SshDataReader, SshDataWriter } from '../../io/sshData';

const ed25519KeySizeInBytes = 32;
const ed25519SignatureSizeInBytes = 64;

// Ed25519 OID: 1.3.101.112
const ed25519Oid = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]);

// PKCS#8 prefix for Ed25519 private key (wraps a 32-byte raw key).
const pkcs8PrivatePrefix = Buffer.from([
	0x30, 0x2e, // SEQUENCE (46 bytes)
	0x02, 0x01, 0x00, // INTEGER 0
	0x30, 0x05, // SEQUENCE (5 bytes)
	0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
	0x04, 0x22, // OCTET STRING (34 bytes)
	0x04, 0x20, // OCTET STRING (32 bytes)
]);

// SPKI prefix for Ed25519 public key (wraps a 32-byte raw key).
const spkiPublicPrefix = Buffer.from([
	0x30, 0x2a, // SEQUENCE (42 bytes)
	0x30, 0x05, // SEQUENCE (5 bytes)
	0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
	0x03, 0x21, // BIT STRING (33 bytes)
	0x00, // no unused bits
]);

class NodeEd25519KeyPair implements KeyPair {
	/* @internal */
	public publicKey?: crypto.KeyObject;

	/* @internal */
	public privateKey?: crypto.KeyObject;

	public constructor() {}

	public get hasPublicKey() {
		return !!this.publicKey;
	}
	public get hasPrivateKey() {
		return !!this.privateKey;
	}

	public comment: string | null = null;

	public get keyAlgorithmName(): string {
		return NodeEd25519.keyAlgorithmName;
	}

	public async generate(): Promise<void> {
		const keyPair = await new Promise<{ publicKey: crypto.KeyObject; privateKey: crypto.KeyObject }>(
			(resolve, reject) => {
				try {
					crypto.generateKeyPair('ed25519', {}, (err, publicKey, privateKey) => {
						if (err) {
							reject(err);
						} else {
							resolve({ publicKey, privateKey });
						}
					});
				} catch (err) {
					reject(err);
				}
			},
		);
		this.publicKey = keyPair.publicKey;
		this.privateKey = keyPair.privateKey;
	}

	public async setPublicKeyBytes(keyBytes: Buffer): Promise<void> {
		if (!keyBytes) {
			throw new TypeError('Buffer is required.');
		}

		// Read public key in SSH format.
		const reader = new SshDataReader(keyBytes);
		const algorithmName = reader.readString('ascii');
		if (algorithmName !== NodeEd25519.keyAlgorithmName) {
			throw new Error(`Invalid Ed25519 key algorithm: ${algorithmName}`);
		}

		const rawPublicKey = reader.readBinary();
		if (rawPublicKey.length !== ed25519KeySizeInBytes) {
			throw new Error(`Unexpected Ed25519 public key length: ${rawPublicKey.length}`);
		}

		const spki = Buffer.concat([spkiPublicPrefix, rawPublicKey]);
		this.publicKey = crypto.createPublicKey({
			key: spki,
			type: 'spki',
			format: 'der',
		});
	}

	public async getPublicKeyBytes(algorithmName?: string): Promise<Buffer | null> {
		if (!this.publicKey) {
			return null;
		}

		const spki = <Buffer>this.publicKey.export({ type: 'spki', format: 'der' });
		// Extract the raw 32-byte public key from the SPKI structure.
		const rawPublicKey = spki.slice(spki.length - ed25519KeySizeInBytes);

		// Write public key in SSH format.
		algorithmName = algorithmName || NodeEd25519.keyAlgorithmName;
		const keyBuffer = Buffer.alloc(algorithmName.length + rawPublicKey.length + 8);
		const keyWriter = new SshDataWriter(keyBuffer);
		keyWriter.writeString(algorithmName, 'ascii');
		keyWriter.writeBinary(rawPublicKey);

		return keyWriter.toBuffer();
	}

	public async importParameters(parameters: EdDSAParameters): Promise<void> {
		if (!parameters.publicKey) throw new TypeError('Public key bytes are required.');
		if (parameters.publicKey.length !== ed25519KeySizeInBytes) {
			throw new Error(`Unexpected Ed25519 public key length: ${parameters.publicKey.length}`);
		}

		const spki = Buffer.concat([spkiPublicPrefix, parameters.publicKey]);
		this.publicKey = crypto.createPublicKey({
			key: spki,
			type: 'spki',
			format: 'der',
		});

		if (parameters.privateKey) {
			const pkcs8 = Buffer.concat([pkcs8PrivatePrefix, parameters.privateKey]);
			this.privateKey = crypto.createPrivateKey({
				key: pkcs8,
				type: 'pkcs8',
				format: 'der',
			});
		} else {
			this.privateKey = undefined;
		}
	}

	public async exportParameters(): Promise<EdDSAParameters> {
		if (!this.publicKey) {
			throw new Error('Key not present.');
		}

		const spki = <Buffer>this.publicKey.export({ type: 'spki', format: 'der' });
		const rawPublicKey = spki.slice(spki.length - ed25519KeySizeInBytes);

		const parameters: EdDSAParameters = {
			curve: { name: 'Ed25519' },
			publicKey: rawPublicKey,
		};

		if (this.privateKey) {
			const pkcs8 = <Buffer>this.privateKey.export({ type: 'pkcs8', format: 'der' });
			parameters.privateKey = pkcs8.slice(pkcs8.length - ed25519KeySizeInBytes);
		}

		return parameters;
	}

	public dispose(): void {}
}

export class NodeEd25519 extends PublicKeyAlgorithm {
	public static readonly keyAlgorithmName = 'ssh-ed25519';

	public constructor() {
		super(
			NodeEd25519.keyAlgorithmName,
			NodeEd25519.keyAlgorithmName,
			'', // Ed25519 has a built-in hash (SHA-512); no separate hash algorithm.
		);
	}

	public createKeyPair(): KeyPair {
		return new NodeEd25519KeyPair();
	}

	public async generateKeyPair(): Promise<KeyPair> {
		const keyPair = new NodeEd25519KeyPair();
		await keyPair.generate();
		return keyPair;
	}

	public createSigner(keyPair: KeyPair): Signer {
		if (!(keyPair instanceof NodeEd25519KeyPair)) {
			throw new TypeError('Ed25519 key pair object expected.');
		}

		return new NodeEd25519SignerVerifier(keyPair);
	}

	public createVerifier(keyPair: KeyPair): Verifier {
		if (!(keyPair instanceof NodeEd25519KeyPair)) {
			throw new TypeError('Ed25519 key pair object expected.');
		}

		return new NodeEd25519SignerVerifier(keyPair);
	}

	public static readonly KeyPair = NodeEd25519KeyPair;
}

class NodeEd25519SignerVerifier implements Signer, Verifier {
	public constructor(private readonly keyPair: NodeEd25519KeyPair) {}

	public get digestLength(): number {
		return ed25519SignatureSizeInBytes;
	}

	public async sign(data: Buffer): Promise<Buffer> {
		if (!this.keyPair.privateKey) {
			throw new Error('Private key not set.');
		}

		return crypto.sign(null, data, this.keyPair.privateKey);
	}

	public async verify(data: Buffer, signature: Buffer): Promise<boolean> {
		if (!this.keyPair.publicKey) {
			throw new Error('Public key not set.');
		}

		return crypto.verify(null, data, this.keyPair.publicKey, signature);
	}

	public dispose(): void {}
}

// eslint-disable-next-line no-redeclare
export namespace NodeEd25519 {
	// eslint-disable-next-line no-shadow, @typescript-eslint/no-shadow
	export type KeyPair = NodeEd25519KeyPair;
}
