//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import {
	SshAlgorithms,
	KeyPair,
	Rsa,
	RsaParameters,
	BigInt,
	DerReader,
	DerWriter,
	DerType,
} from '@microsoft/dev-tunnels-ssh';
import { KeyFormatter, getKeyEncryptionAlgorithm } from './keyFormatter';
import { KeyData } from './keyData';

/** Provides import/export of the PKCS#1 key format. */
export class Pkcs1KeyFormatter implements KeyFormatter {
	private static readonly publicKeyType = 'RSA PUBLIC KEY';
	private static readonly privateKeyType = 'RSA PRIVATE KEY';

	public async import(keyData: KeyData): Promise<KeyPair | null> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		if (!keyData.keyType) {
			// Automatically determine public or private by reading the first few bytes.
			try {
				const reader = new DerReader(keyData.data);
				reader.readInteger();
				reader.readInteger();
				keyData.keyType =
					reader.available > 0
						? Pkcs1KeyFormatter.privateKeyType
						: Pkcs1KeyFormatter.publicKeyType;
			} catch (e) {
				return null;
			}
		}

		let parameters: RsaParameters | null = null;
		if (keyData.keyType === Pkcs1KeyFormatter.publicKeyType) {
			parameters = Pkcs1KeyFormatter.parseRsaPublic(keyData.data);
		} else if (keyData.keyType === Pkcs1KeyFormatter.privateKeyType) {
			parameters = Pkcs1KeyFormatter.parseRsaPrivate(keyData.data);
		}

		if (parameters) {
			const keyPair = SshAlgorithms.publicKey.rsaWithSha512!.createKeyPair();
			await keyPair.importParameters(parameters);
			return keyPair;
		}

		return null;
	}

	public async export(keyPair: KeyPair, includePrivate: boolean): Promise<KeyData> {
		if (!keyPair) throw new TypeError('KeyPair object expected.');

		if (keyPair instanceof Rsa.KeyPair) {
			if (!keyPair.hasPublicKey) {
				throw new Error('KeyPair object does not have a public key.');
			} else if (includePrivate && !keyPair.hasPrivateKey) {
				throw new Error('KeyPair object does not have a private key.');
			}

			let keyData = new KeyData();
			const parameters = await keyPair.exportParameters();
			if (includePrivate) {
				keyData.keyType = Pkcs1KeyFormatter.privateKeyType;
				keyData.data = Pkcs1KeyFormatter.formatRsaPrivate(parameters);
			} else {
				keyData.keyType = Pkcs1KeyFormatter.publicKeyType;
				keyData.data = Pkcs1KeyFormatter.formatRsaPublic(parameters);
			}

			return keyData;
		} else {
			throw new Error('KeyPair class not supported.');
		}
	}

	public async decrypt(keyData: KeyData, passphrase: string | null): Promise<KeyData | null> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		if (
			keyData.keyType === Pkcs1KeyFormatter.publicKeyType ||
			(!keyData.keyType && !passphrase)
		) {
			return keyData;
		} else if (keyData.keyType === Pkcs1KeyFormatter.privateKeyType || !keyData.keyType) {
			const procTypeHeader = keyData.headers.get('Proc-Type');
			if (procTypeHeader === '4,ENCRYPTED') {
				if (!passphrase) {
					throw new Error('A passphrase is required to decrypt the key.');
				}

				return Pkcs1KeyFormatter.decryptPrivate(keyData, passphrase);
			} else {
				return keyData;
			}
		}

		return null;
	}

	public async encrypt(keyData: KeyData, passphrase: string): Promise<KeyData> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		if (keyData.keyType === Pkcs1KeyFormatter.publicKeyType) {
			throw new Error('Public key cannot be encrypted.');
		} else if (keyData.keyType === Pkcs1KeyFormatter.privateKeyType) {
			throw new Error(
				'PKCS#1 export with passphrase is not supported because the format uses ' +
					'a weak key derivation algorithm. Use PKCS#8 to export a ' +
					'passphrase-protected private key.',
			);
		} else {
			throw new Error(`Unsupported key type: ${keyData.keyType}`);
		}
	}

	private static formatRsaPublic(rsa: RsaParameters): Buffer {
		const writer = new DerWriter(Buffer.alloc(1024));
		writer.writeInteger(rsa.modulus);
		writer.writeInteger(rsa.exponent);
		return writer.toBuffer();
	}

	private static formatRsaPrivate(rsa: RsaParameters): Buffer {
		if (!(rsa.d && rsa.p && rsa.q && rsa.dp && rsa.dq && rsa.qi)) {
			throw new Error('Missing private key parameters.');
		}

		const writer = new DerWriter(Buffer.alloc(2048));
		writer.writeInteger(BigInt.fromInt32(0));
		writer.writeInteger(rsa.modulus);
		writer.writeInteger(rsa.exponent);
		writer.writeInteger(rsa.d);
		writer.writeInteger(rsa.p);
		writer.writeInteger(rsa.q);
		writer.writeInteger(rsa.dp);
		writer.writeInteger(rsa.dq);
		writer.writeInteger(rsa.qi);
		return writer.toBuffer();
	}

	private static parseRsaPublic(keyBytes: Buffer): RsaParameters {
		const reader = new DerReader(keyBytes);
		const modulus = reader.readInteger();
		const exponent = reader.readInteger();
		return { modulus, exponent };
	}

	private static parseRsaPrivate(keyBytes: Buffer): RsaParameters {
		const reader = new DerReader(keyBytes);
		const version = reader.readInteger();
		const modulus = reader.readInteger();
		const exponent = reader.readInteger();
		const d = reader.readInteger();
		const p = reader.readInteger();
		const q = reader.readInteger();
		const dp = reader.readInteger();
		const dq = reader.readInteger();
		const qi = reader.readInteger();
		return { modulus, exponent, d, p, q, dp, dq, qi };
	}

	/* @internal */
	public static async decryptPrivate(keyData: KeyData, passphrase: string): Promise<KeyData> {
		const decryptionInfo = keyData.headers.get('DEK-Info');
		if (!decryptionInfo) {
			throw new Error('PKCS#1 decryption parameters not found.');
		}

		const decryptionInfoParts = decryptionInfo.split(',');
		const cipherName = decryptionInfoParts[0];
		const ivHex = decryptionInfoParts[1];
		const iv = Buffer.from(ivHex, 'hex');

		const encryption = getKeyEncryptionAlgorithm(cipherName);
		const key = Pkcs1KeyFormatter.deriveDecryptionKey(
			Buffer.from(passphrase, 'utf8'),
			iv,
			encryption.keyLength,
		);

		const decryptedKeyData = new KeyData(keyData.keyType);
		decryptedKeyData.headers = new Map<string, string>(keyData.headers);
		decryptedKeyData.headers.delete('Proc-Type');
		decryptedKeyData.headers.delete('DEK-Info');

		const decipher = await encryption.createCipher(false, key, iv);
		decryptedKeyData.data = await decipher.transform(keyData.data);

		// The first part of the key should be a DER sequence header.
		if (decryptedKeyData.data[0] !== (DerType.Constructed | DerType.Sequence)) {
			throw new Error('Key decryption failed - incorrect passphrase.');
		}

		return decryptedKeyData;
	}

	private static deriveDecryptionKey(
		passphraseBytes: Buffer,
		iv: Buffer,
		keyLength: number,
	): Buffer {
		const useWebCrypto = !!(typeof crypto === 'object' && crypto.subtle);
		if (useWebCrypto) {
			// Web crypto does not provide an MD5 implementation. An external lib could be used here,
			// but it's not worth it to support an insecure encryption format. Use PKCS#8 instead.
			throw new Error('PKCS#1 decryption not implemented.');
		}

		const nodeCrypto = require('crypto');
		const PKCS5_SALT_LEN = 8;
		const salt = iv.slice(0, PKCS5_SALT_LEN);

		let key = Buffer.alloc(0);
		while (key.length < keyLength) {
			// MD5 is an unsafe hash algorithm, but it is used only for decrypting (importing) keys,
			// not encrypting.
			const md5 = nodeCrypto.createHash('md5');
			md5.update(key);
			md5.update(passphraseBytes);
			md5.update(salt);
			key = Buffer.concat([key, md5.digest()]);
		}

		key = key.slice(0, keyLength);
		return key;
	}
}
