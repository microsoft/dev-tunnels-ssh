//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import {
	SshAlgorithms,
	KeyPair,
	Rsa,
	RsaParameters,
	BigInt,
	DerType,
	DerReader,
	DerWriter,
	Encryption,
	EncryptionAlgorithm,
	Random,
	ECParameters,
	ECDsa,
} from '@microsoft/dev-tunnels-ssh';
import { KeyFormatter } from './keyFormatter';
import { KeyData } from './keyData';

const enum Oids {
	rsa = '1.2.840.113549.1.1.1',
	ec = '1.2.840.10045.2.1',
	pkcs5PBKDF2 = '1.2.840.113549.1.5.12',
	pkcs5PBES2 = '1.2.840.113549.1.5.13',
	hmacWithSHA256 = '1.2.840.113549.2.9',
	desEde3Cbc = '1.2.840.113549.3.7',
	prime256v1 = '1.2.840.10045.3.1.7',
	secp384r1 = '1.3.132.0.34',
	secp521r1 = '1.3.132.0.35',
	aes128Cbc = '2.16.840.1.101.3.4.1.2',
	aes192Cbc = '2.16.840.1.101.3.4.1.22',
	aes256Cbc = '2.16.840.1.101.3.4.1.42',
}

declare namespace Pkcs8KeyFormatter {
	interface Importer {
		(keyBytes: Buffer, oidReader: DerReader, includePrivate: boolean): Promise<KeyPair>;
	}
	interface Exporter {
		(keyPair: KeyPair, oidWriter: DerWriter, includePrivate: boolean): Promise<Buffer>;
	}
}

/** Provides import/export of the PKCS#8 key format. */
// eslint-disable-next-line no-redeclare
export class Pkcs8KeyFormatter implements KeyFormatter {
	private static readonly publicKeyType = 'PUBLIC KEY';
	private static readonly privateKeyType = 'PRIVATE KEY';
	private static readonly encryptedPrivateKeyType = 'ENCRYPTED PRIVATE KEY';

	public constructor() {
		this.importers.set(Oids.rsa, Pkcs8KeyFormatter.importRsaKey);
		this.importers.set(Oids.ec, Pkcs8KeyFormatter.importECKey);
		this.exporters.set(Rsa.keyAlgorithmName, Pkcs8KeyFormatter.exportRsaKey);
		this.exporters.set(ECDsa.ecdsaSha2Nistp256, Pkcs8KeyFormatter.exportECKey);
		this.exporters.set(ECDsa.ecdsaSha2Nistp384, Pkcs8KeyFormatter.exportECKey);
		this.exporters.set(ECDsa.ecdsaSha2Nistp521, Pkcs8KeyFormatter.exportECKey);
	}

	/** Mapping from public key algorithm OID to import handler for that algorithm. */
	public readonly importers = new Map<string, Pkcs8KeyFormatter.Importer>();

	/** Mapping from public key algorithm name to export handler for that algorithm. */
	public readonly exporters = new Map<string, Pkcs8KeyFormatter.Exporter>();

	/** Enables overriding randomness for predictable testing. */
	public random: Random = SshAlgorithms.random;

	public async import(keyData: KeyData): Promise<KeyPair | null> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		if (!keyData.keyType) {
			// Automatically determine public or private by reading the first few bytes.
			try {
				const reader = new DerReader(keyData.data);
				if (reader.peek() === (DerType.Constructed | DerType.Sequence)) {
					keyData.keyType = Pkcs8KeyFormatter.publicKeyType;
				} else if (reader.peek() === DerType.Integer) {
					keyData.keyType = Pkcs8KeyFormatter.privateKeyType;
				}
			} catch (e) {
				return null;
			}
		}

		if (keyData.keyType === Pkcs8KeyFormatter.publicKeyType) {
			return await this.importPublic(keyData);
		} else if (keyData.keyType === Pkcs8KeyFormatter.privateKeyType) {
			return await this.importPrivate(keyData);
		} else if (keyData.keyType === Pkcs8KeyFormatter.encryptedPrivateKeyType) {
			throw new Error('Decrypt before importing.');
		}

		return null;
	}

	public async export(keyPair: KeyPair, includePrivate: boolean): Promise<KeyData> {
		if (!keyPair) throw new TypeError('KeyPair object expected.');

		if (includePrivate) {
			if (!keyPair.hasPrivateKey) {
				throw new Error('KeyPair object does not contain the private key.');
			}

			return await this.exportPrivate(keyPair);
		} else {
			return await this.exportPublic(keyPair);
		}
	}

	public async decrypt(keyData: KeyData, passphrase: string | null): Promise<KeyData | null> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		if (
			keyData.keyType === Pkcs8KeyFormatter.publicKeyType ||
			keyData.keyType === Pkcs8KeyFormatter.privateKeyType ||
			(!keyData.keyType && !passphrase)
		) {
			return keyData;
		} else if (
			keyData.keyType === Pkcs8KeyFormatter.encryptedPrivateKeyType ||
			(!keyData.keyType && passphrase)
		) {
			if (!passphrase) {
				throw new Error('A passphrase is required to decrypt the key.');
			}

			return Pkcs8KeyFormatter.decryptPrivate(keyData, passphrase);
		}

		return null;
	}

	public async encrypt(keyData: KeyData, passphrase: string): Promise<KeyData> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		if (keyData.keyType === Pkcs8KeyFormatter.publicKeyType) {
			throw new Error('Public key cannot be encrypted.');
		} else if (keyData.keyType === Pkcs8KeyFormatter.privateKeyType) {
			return Pkcs8KeyFormatter.encryptPrivate(keyData, passphrase, this.random);
		} else if (keyData.keyType === Pkcs8KeyFormatter.encryptedPrivateKeyType) {
			throw new Error('Already encrypted.');
		} else {
			throw new Error(`Unsupported key type: ${keyData.keyType}`);
		}
	}

	private async importPublic(keyData: KeyData): Promise<KeyPair> {
		const reader = new DerReader(keyData.data);
		const oidReader = reader.readSequence();
		const keyAlgorithm = oidReader.readObjectIdentifier();
		const keyBytes = reader.readBitString();

		const importer = this.importers.get(keyAlgorithm);
		if (!importer) {
			throw new Error(`No PKCS#8 importer available for key algorithm: ${keyAlgorithm}`);
		}

		return await importer(keyBytes, oidReader, false);
	}

	private async importPrivate(keyData: KeyData): Promise<KeyPair> {
		const reader = new DerReader(keyData.data);
		const version = reader.readInteger().toInt32();
		if (version !== 0) {
			throw new Error(`PKCS#8 format version not supported: ${version}`);
		}

		const oidReader = reader.readSequence();
		const keyAlgorithm = oidReader.readObjectIdentifier();
		const keyBytes = reader.readOctetString();

		const importer = this.importers.get(keyAlgorithm);
		if (!importer) {
			throw new Error(`No PKCS#8 importer available for key algorithm: ${keyAlgorithm}`);
		}

		return await importer(keyBytes, oidReader, true);
	}

	private static async importRsaKey(
		keyBytes: Buffer,
		oidReader: DerReader,
		includePrivate: boolean,
	): Promise<KeyPair> {
		const keyReader = new DerReader(keyBytes);
		if (includePrivate) {
			const version = keyReader.readInteger().toInt32();
			if (version !== 0) {
				throw new Error(`PKCS#8 key format version not supported: ${version}`);
			}
		}

		const parameters: RsaParameters = {
			modulus: keyReader.readInteger(),
			exponent: keyReader.readInteger(),
		};

		if (includePrivate) {
			parameters.d = keyReader.readInteger();
			parameters.p = keyReader.readInteger();
			parameters.q = keyReader.readInteger();
			parameters.dp = keyReader.readInteger();
			parameters.dq = keyReader.readInteger();
			parameters.qi = keyReader.readInteger();
		}

		const keyPair = SshAlgorithms.publicKey.rsaWithSha512!.createKeyPair();
		await keyPair.importParameters(parameters);
		return keyPair;
	}

	private static async importECKey(
		keyBytes: Buffer,
		oidReader: DerReader,
		includePrivate: boolean,
	): Promise<KeyPair> {
		const curveOid = oidReader.readObjectIdentifier();

		let publicKeyBytes: Buffer;
		let privateKeyBytes: Buffer | null = null;
		if (includePrivate) {
			const keyReader = new DerReader(keyBytes);
			const version = keyReader.readInteger().toInt32();
			if (version !== 1) {
				throw new Error(`PKCS#8 EC key format version not supported: ${version}`);
			}

			privateKeyBytes = keyReader.readOctetString();

			const publicKeyReader = keyReader.tryReadTagged(1);
			if (!publicKeyReader) {
				throw new Error('Failed to read EC public key data.');
			}

			publicKeyBytes = publicKeyReader.readBitString();
		} else {
			publicKeyBytes = keyBytes;
		}

		if (publicKeyBytes.length % 2 !== 1) {
			throw new Error(`Unexpected key data length: ${publicKeyBytes.length}`);
		}

		// 4 = uncompressed curve format
		const dataFormat = publicKeyBytes[0];
		if (dataFormat !== 4) {
			throw new Error(`Unexpected curve format: ${dataFormat}`);
		}

		// X and Y parameters are equal length, after a one-byte header.
		const x = BigInt.fromBytes(publicKeyBytes.slice(1, 1 + (publicKeyBytes.length - 1) / 2), {
			unsigned: true,
		});
		const y = BigInt.fromBytes(publicKeyBytes.slice(1 + (publicKeyBytes.length - 1) / 2), {
			unsigned: true,
		});
		const d = privateKeyBytes ? BigInt.fromBytes(privateKeyBytes, { unsigned: true }) : undefined;

		const parameters: ECParameters = {
			curve: { oid: curveOid },
			x,
			y,
			d,
		};

		const keyPair = new ECDsa.KeyPair();
		await keyPair.importParameters(parameters);
		return keyPair;
	}

	private async exportPublic(keyPair: KeyPair): Promise<KeyData> {
		const exporter = this.exporters.get(keyPair.keyAlgorithmName);
		if (!exporter) {
			throw new Error(
				`No PKCS#8 exporter available for key algorithm: ${keyPair.keyAlgorithmName}`,
			);
		}

		const oidWriter = new DerWriter(Buffer.alloc(256));
		const keyBytes = await exporter(keyPair, oidWriter, false);

		const writer = new DerWriter(Buffer.alloc(1024));
		writer.writeSequence(oidWriter);
		writer.writeBitString(keyBytes);

		const keyData = new KeyData();
		keyData.keyType = Pkcs8KeyFormatter.publicKeyType;
		keyData.data = writer.toBuffer();
		return keyData;
	}

	private async exportPrivate(keyPair: KeyPair): Promise<KeyData> {
		const exporter = this.exporters.get(keyPair.keyAlgorithmName);
		if (!exporter) {
			throw new Error(
				`No PKCS#8 exporter available for key algorithm: ${keyPair.keyAlgorithmName}`,
			);
		}

		const oidWriter = new DerWriter(Buffer.alloc(256));
		const keyBytes = await exporter(keyPair, oidWriter, true);

		const writer = new DerWriter(Buffer.alloc(2048));
		writer.writeInteger(BigInt.fromInt32(0)); // version
		writer.writeSequence(oidWriter);
		writer.writeOctetString(keyBytes);

		return new KeyData(Pkcs8KeyFormatter.privateKeyType, writer.toBuffer());
	}

	private static async exportRsaKey(
		keyPair: KeyPair,
		oidWriter: DerWriter,
		includePrivate: boolean,
	): Promise<Buffer> {
		const parameters = <RsaParameters>await keyPair.exportParameters();

		oidWriter.writeObjectIdentifier(Oids.rsa);
		oidWriter.writeNull();

		const keyWriter = new DerWriter(Buffer.alloc(1024));
		if (includePrivate) {
			keyWriter.writeInteger(BigInt.fromInt32(0)); // version
		}

		keyWriter.writeInteger(parameters.modulus);
		keyWriter.writeInteger(parameters.exponent);

		if (includePrivate) {
			keyWriter.writeInteger(parameters.d!);
			keyWriter.writeInteger(parameters.p!);
			keyWriter.writeInteger(parameters.q!);
			keyWriter.writeInteger(parameters.dp!);
			keyWriter.writeInteger(parameters.dq!);
			keyWriter.writeInteger(parameters.qi!);
		}

		return keyWriter.toBuffer();
	}

	private static async exportECKey(
		keyPair: KeyPair,
		oidWriter: DerWriter,
		includePrivate: boolean,
	): Promise<Buffer> {
		const parameters = <ECParameters>await keyPair.exportParameters();

		const curve = ECDsa.curves.find((c) => c.oid === parameters.curve.oid)!;
		const keySizeInBytes = Math.ceil(curve.keySize / 8);

		oidWriter.writeObjectIdentifier(Oids.ec);
		oidWriter.writeObjectIdentifier(parameters.curve.oid!);

		const x = parameters.x.toBytes({ unsigned: true, length: keySizeInBytes });
		const y = parameters.y.toBytes({ unsigned: true, length: keySizeInBytes });
		const publicKeyData = Buffer.alloc(1 + x.length + y.length);
		publicKeyData[0] = 4; // Indicates uncompressed curve format
		x.copy(publicKeyData, 1);
		y.copy(publicKeyData, 1 + x.length);

		if (includePrivate) {
			const keyWriter = new DerWriter(Buffer.alloc(512));
			keyWriter.writeInteger(BigInt.fromInt32(1)); // version
			keyWriter.writeOctetString(parameters.d!.toBytes({ unsigned: true }));

			const publicKeyWriter = new DerWriter(Buffer.alloc(1024));
			publicKeyWriter.writeBitString(publicKeyData);
			keyWriter.writeTagged(1, publicKeyWriter);
			return keyWriter.toBuffer();
		} else {
			return publicKeyData;
		}
	}

	private static async decryptPrivate(keyData: KeyData, passphrase: string): Promise<KeyData> {
		let reader = new DerReader(keyData.data);
		const innerReader = reader.readSequence();
		let privateKeyData = reader.readOctetString();
		reader = innerReader;

		reader.readObjectIdentifier(Oids.pkcs5PBES2);

		reader = reader.readSequence();
		let kdfReader = reader.readSequence();
		const algReader = reader.readSequence();

		kdfReader.readObjectIdentifier(Oids.pkcs5PBKDF2);

		kdfReader = kdfReader.readSequence();
		const salt = kdfReader.readOctetString();
		const iterations = kdfReader.readInteger().toInt32();
		kdfReader = kdfReader.readSequence();
		kdfReader.readObjectIdentifier(Oids.hmacWithSHA256);
		kdfReader.readNull();

		const algorithmOid = algReader.readObjectIdentifier();
		const iv = algReader.readOctetString();

		const encryption = Pkcs8KeyFormatter.getKeyEncryptionAlgorithm(algorithmOid);
		const key = await Pkcs8KeyFormatter.pbkdf2(
			Buffer.from(passphrase, 'utf8'),
			salt,
			iterations,
			encryption.keyLength,
		);

		const decipher = await encryption.createCipher(false, key, iv);
		try {
			privateKeyData = await decipher.transform(privateKeyData);
		} catch (e) {
			// Web crypto AES-CBC may throw an error due to invalid padding, if the key is incorrect.
			privateKeyData = Buffer.alloc(0);
		} finally {
			decipher.dispose();
		}

		// The first part of the key should be a DER sequence header.
		if (privateKeyData[0] !== (DerType.Constructed | DerType.Sequence)) {
			throw new Error('Key decryption failed - incorrect passphrase.');
		}

		return new KeyData(Pkcs8KeyFormatter.privateKeyType, privateKeyData);
	}

	private static async encryptPrivate(
		keyData: KeyData,
		passphrase: string,
		random: Random,
	): Promise<KeyData> {
		let privateKeyData = Buffer.from(keyData.data);
		const encryption = Pkcs8KeyFormatter.getKeyEncryptionAlgorithm(Oids.aes256Cbc);

		const salt = Buffer.alloc(8);
		random.getBytes(salt);

		const iterations = 2048;
		const key = await Pkcs8KeyFormatter.pbkdf2(
			Buffer.from(passphrase, 'utf8'),
			salt,
			iterations,
			encryption.keyLength,
		);
		const iv = Buffer.alloc(encryption.blockLength);
		random.getBytes(iv);

		// Append PKCS#7 padding up to next block boundary.
		const paddingLength =
			encryption.blockLength - (privateKeyData.length % encryption.blockLength);
		const paddedData = Buffer.alloc(privateKeyData.length + paddingLength);
		privateKeyData.copy(paddedData, 0);
		for (let i = privateKeyData.length; i < paddedData.length; i++) {
			paddedData[i] = paddingLength;
		}
		privateKeyData = paddedData;

		const cipher = await encryption.createCipher(true, key, iv);
		try {
			privateKeyData = await cipher.transform(privateKeyData);
		} finally {
			cipher.dispose();
		}

		const pbeWriter = new DerWriter(Buffer.alloc(256));
		pbeWriter.writeObjectIdentifier(Oids.pkcs5PBES2);

		const kdfAndAlgWriter = new DerWriter(Buffer.alloc(256));

		const kdfWriter = new DerWriter(Buffer.alloc(256));
		kdfWriter.writeObjectIdentifier(Oids.pkcs5PBKDF2);
		const kdfParamsWriter = new DerWriter(Buffer.alloc(32));
		kdfParamsWriter.writeOctetString(salt);
		kdfParamsWriter.writeInteger(BigInt.fromInt32(iterations));
		const hmacWriter = new DerWriter(Buffer.alloc(16));
		hmacWriter.writeObjectIdentifier(Oids.hmacWithSHA256);
		hmacWriter.writeNull();
		kdfParamsWriter.writeSequence(hmacWriter);
		kdfWriter.writeSequence(kdfParamsWriter);
		kdfAndAlgWriter.writeSequence(kdfWriter);

		const algWriter = new DerWriter(Buffer.alloc(64));
		algWriter.writeObjectIdentifier(Oids.aes256Cbc);
		algWriter.writeOctetString(iv);

		kdfAndAlgWriter.writeSequence(algWriter);
		pbeWriter.writeSequence(kdfAndAlgWriter);

		const writer = new DerWriter(Buffer.alloc(2048));
		writer.writeSequence(pbeWriter);
		writer.writeOctetString(privateKeyData);

		return new KeyData(Pkcs8KeyFormatter.encryptedPrivateKeyType, writer.toBuffer());
	}

	private static getKeyEncryptionAlgorithm(algorithmOid: string): EncryptionAlgorithm {
		// Note algorithms other than AES256 are used only for decrypting (importing) keys.
		if (algorithmOid === Oids.aes256Cbc) {
			return new Encryption('aes256-cbc', 'AES', 'CBC', 256);
		} else if (algorithmOid === Oids.aes192Cbc) {
			return new Encryption('aes192-cbc', 'AES', 'CBC', 192);
		} else if (algorithmOid === Oids.aes128Cbc) {
			return new Encryption('aes128-cbc', 'AES', 'CBC', 128);
		} else if (algorithmOid === Oids.desEde3Cbc) {
			return new Encryption('3des-cbc', '3DES', 'CBC', 192);
		} else {
			throw new Error(`Key cipher not supported: ${algorithmOid}`);
		}
	}

	private static async pbkdf2(
		passphrase: Buffer,
		salt: Buffer,
		iterations: number,
		keyLength: number,
	): Promise<Buffer> {
		const useWebCrypto = typeof window !== 'undefined' &&
			!!(typeof crypto === 'object' && crypto.subtle);
		if (useWebCrypto) {
			const passphraseKey = await crypto.subtle.importKey(
				'raw',
				passphrase,
				'PBKDF2',
				false, // extractable
				['deriveBits'],
			);
			const key = await crypto.subtle.deriveBits(
				{
					name: 'PBKDF2',
					salt,
					iterations,
					hash: 'SHA-256',
				},
				passphraseKey,
				keyLength * 8,
			);
			return Buffer.from(key);
		} else {
			const crypto = await import('crypto');
			return await new Promise<Buffer>((resolve, reject) => {
				crypto.pbkdf2(
					passphrase,
					salt,
					iterations,
					keyLength,
					'sha256',
					(err: Error | null, derivedKey: Buffer) => {
						if (err) reject(err);
						else resolve(derivedKey);
					},
				);
			});
		}
	}
}
