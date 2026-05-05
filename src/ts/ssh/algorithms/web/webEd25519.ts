//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { PublicKeyAlgorithm, KeyPair, EdDSAParameters } from '../publicKeyAlgorithm';
import { SshDataReader, SshDataWriter } from '../../io/sshData';
import { Signer, Verifier } from '../hmacAlgorithm';

const ed25519KeySizeInBytes = 32;
const ed25519SignatureSizeInBytes = 64;

class WebEd25519KeyPair implements KeyPair {
	/* @internal */
	public publicKey?: CryptoKey;

	/* @internal */
	public privateKey?: CryptoKey;

	public constructor() {}

	public get hasPublicKey() {
		return !!this.publicKey;
	}
	public get hasPrivateKey() {
		return !!this.privateKey;
	}

	public comment: string | null = null;

	public get keyAlgorithmName(): string {
		return WebEd25519.keyAlgorithmName;
	}

	public async generate(): Promise<void> {
		try {
			const keyPair = <CryptoKeyPair>(
				await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
			);
			this.publicKey = keyPair.publicKey;
			this.privateKey = keyPair.privateKey;
		} catch (e) {
			throw new Error('Failed to generate Ed25519 key pair: ' + e);
		}
	}

	public async setPublicKeyBytes(keyBytes: Buffer): Promise<void> {
		if (!keyBytes) {
			throw new TypeError('Buffer is required.');
		}

		// Read public key in SSH format.
		const reader = new SshDataReader(keyBytes);
		const algorithmName = reader.readString('ascii');
		if (algorithmName !== WebEd25519.keyAlgorithmName) {
			throw new Error(`Invalid Ed25519 key algorithm: ${algorithmName}`);
		}

		const rawPublicKey = reader.readBinary();
		if (rawPublicKey.length !== ed25519KeySizeInBytes) {
			throw new Error(`Unexpected Ed25519 public key length: ${rawPublicKey.length}`);
		}

		try {
			this.publicKey = await crypto.subtle.importKey(
				'raw',
				rawPublicKey,
				'Ed25519',
				true,
				['verify'],
			);
		} catch (e) {
			throw new Error('Failed to import Ed25519 public key: ' + e);
		}
	}

	public async getPublicKeyBytes(algorithmName?: string): Promise<Buffer | null> {
		if (!this.publicKey) {
			return null;
		}

		let rawPublicKey: Buffer;
		try {
			rawPublicKey = Buffer.from(await crypto.subtle.exportKey('raw', this.publicKey));
		} catch (e) {
			throw new Error('Failed to export Ed25519 public key: ' + e);
		}

		// Write public key in SSH format.
		algorithmName = algorithmName || WebEd25519.keyAlgorithmName;
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

		try {
			this.publicKey = await crypto.subtle.importKey(
				'raw',
				parameters.publicKey,
				'Ed25519',
				true,
				['verify'],
			);

			if (parameters.privateKey) {
				// WebCrypto Ed25519 uses PKCS#8 for private key import.
				const pkcs8 = WebEd25519KeyPair.wrapPrivateKeyPkcs8(parameters.privateKey);
				this.privateKey = await crypto.subtle.importKey(
					'pkcs8',
					pkcs8,
					'Ed25519',
					true,
					['sign'],
				);
			} else {
				this.privateKey = undefined;
			}
		} catch (e) {
			throw new Error('Failed to import Ed25519 key pair: ' + e);
		}
	}

	public async exportParameters(): Promise<EdDSAParameters> {
		if (!this.publicKey) {
			throw new Error('Key not present.');
		}

		let rawPublicKey: Buffer;
		try {
			rawPublicKey = Buffer.from(await crypto.subtle.exportKey('raw', this.publicKey));
		} catch (e) {
			throw new Error('Failed to export Ed25519 public key: ' + e);
		}

		const parameters: EdDSAParameters = {
			curve: { name: 'Ed25519' },
			publicKey: rawPublicKey,
		};

		if (this.privateKey) {
			try {
				const pkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', this.privateKey));
				parameters.privateKey = WebEd25519KeyPair.unwrapPrivateKeyPkcs8(pkcs8);
			} catch (e) {
				throw new Error('Failed to export Ed25519 private key: ' + e);
			}
		}

		return parameters;
	}

	/**
	 * Wraps a raw 32-byte Ed25519 private key in PKCS#8 DER format.
	 *
	 * The PKCS#8 structure for Ed25519 is:
	 *   SEQUENCE {
	 *     INTEGER 0 (version)
	 *     SEQUENCE { OID 1.3.101.112 (Ed25519) }
	 *     OCTET STRING { OCTET STRING { raw private key } }
	 *   }
	 */
	private static wrapPrivateKeyPkcs8(rawPrivateKey: Buffer): Buffer {
		// Pre-computed PKCS#8 prefix for Ed25519 (first 16 bytes of the structure).
		const prefix = Buffer.from([
			0x30, 0x2e, // SEQUENCE (46 bytes)
			0x02, 0x01, 0x00, // INTEGER 0
			0x30, 0x05, // SEQUENCE (5 bytes)
			0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
			0x04, 0x22, // OCTET STRING (34 bytes)
			0x04, 0x20, // OCTET STRING (32 bytes)
		]);
		return Buffer.concat([prefix, rawPrivateKey]);
	}

	/**
	 * Extracts the raw 32-byte Ed25519 private key from PKCS#8 DER format.
	 */
	private static unwrapPrivateKeyPkcs8(pkcs8: Buffer): Buffer {
		// The raw key is the last 32 bytes of the PKCS#8 structure.
		return pkcs8.slice(pkcs8.length - ed25519KeySizeInBytes);
	}

	public dispose(): void {}
}

export class WebEd25519 extends PublicKeyAlgorithm {
	public static readonly keyAlgorithmName = 'ssh-ed25519';

	public constructor() {
		super(
			WebEd25519.keyAlgorithmName,
			WebEd25519.keyAlgorithmName,
			'', // Ed25519 has a built-in hash (SHA-512); no separate hash algorithm.
		);
	}

	public createKeyPair(): KeyPair {
		return new WebEd25519KeyPair();
	}

	public async generateKeyPair(): Promise<KeyPair> {
		const keyPair = new WebEd25519KeyPair();
		await keyPair.generate();
		return keyPair;
	}

	public createSigner(keyPair: KeyPair): Signer {
		if (!(keyPair instanceof WebEd25519KeyPair)) {
			throw new TypeError('Ed25519 key pair object expected.');
		}

		return new WebEd25519SignerVerifier(keyPair);
	}

	public createVerifier(keyPair: KeyPair): Verifier {
		if (!(keyPair instanceof WebEd25519KeyPair)) {
			throw new TypeError('Ed25519 key pair object expected.');
		}

		return new WebEd25519SignerVerifier(keyPair);
	}

	public static readonly KeyPair = WebEd25519KeyPair;
}

class WebEd25519SignerVerifier implements Signer, Verifier {
	public constructor(private readonly keyPair: WebEd25519KeyPair) {}

	public get digestLength(): number {
		return ed25519SignatureSizeInBytes;
	}

	public async sign(data: Buffer): Promise<Buffer> {
		if (!this.keyPair.privateKey) {
			throw new Error('Private key not set.');
		}

		const signature = Buffer.from(
			await crypto.subtle.sign('Ed25519', this.keyPair.privateKey, data),
		);
		return signature;
	}

	public async verify(data: Buffer, signature: Buffer): Promise<boolean> {
		if (!this.keyPair.publicKey) {
			throw new Error('Public key not set.');
		}

		const result = await crypto.subtle.verify(
			'Ed25519',
			this.keyPair.publicKey,
			signature,
			data,
		);
		return result;
	}

	public dispose(): void {}
}

// eslint-disable-next-line no-redeclare
export namespace WebEd25519 {
	// eslint-disable-next-line no-shadow, @typescript-eslint/no-shadow
	export type KeyPair = WebEd25519KeyPair;
}
