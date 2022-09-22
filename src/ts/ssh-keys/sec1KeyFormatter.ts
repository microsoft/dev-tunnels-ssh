//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import {
	SshAlgorithms,
	KeyPair,
	BigInt,
	DerReader,
	DerWriter,
	DerType,
	ECDsa,
	ECParameters,
} from '@microsoft/dev-tunnels-ssh';
import { KeyFormatter, getKeyEncryptionAlgorithm } from './keyFormatter';
import { KeyData } from './keyData';
import { Pkcs1KeyFormatter } from './pkcs1KeyFormatter';

/** Provides import/export of the SEC1 key format. */
export class Sec1KeyFormatter implements KeyFormatter {
	private static readonly privateKeyType = 'EC PRIVATE KEY';

	public async import(keyData: KeyData): Promise<KeyPair | null> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		if (keyData.keyType === Sec1KeyFormatter.privateKeyType || !keyData.keyType) {
			const parameters = Sec1KeyFormatter.importECPrivate(keyData.data);
			const keyPair = new ECDsa.KeyPair();
			await keyPair.importParameters(parameters);
			return keyPair;
		}

		return null;
	}

	public async export(keyPair: KeyPair, includePrivate: boolean): Promise<KeyData> {
		if (!keyPair) throw new TypeError('KeyPair object expected.');

		if (!includePrivate) {
			throw new Error('Public-only export is not supported by this format.');
		}

		if (keyPair instanceof ECDsa.KeyPair) {
			if (!keyPair.hasPublicKey) {
				throw new Error('KeyPair object does not have a public key.');
			} else if (!keyPair.hasPrivateKey) {
				throw new Error('KeyPair object does not have a private key.');
			}

			let keyData = new KeyData();
			const parameters = await keyPair.exportParameters();
			keyData.keyType = Sec1KeyFormatter.privateKeyType;
			keyData.data = Sec1KeyFormatter.exportECPrivate(parameters);

			return keyData;
		} else {
			throw new Error('KeyPair class not supported.');
		}
	}

	public async decrypt(keyData: KeyData, passphrase: string | null): Promise<KeyData | null> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		if (keyData.keyType === Sec1KeyFormatter.privateKeyType || !keyData.keyType) {
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

		if (keyData.keyType === Sec1KeyFormatter.privateKeyType) {
			throw new Error(
				'SEC1 export with passphrase is not supported because the format uses ' +
					'a weak key derivation algorithm. Use PKCS#8 to export a ' +
					'passphrase-protected private key.',
			);
		} else {
			throw new Error(`Unsupported key type: ${keyData.keyType}`);
		}
	}

	private static exportECPrivate(ec: ECParameters): Buffer {
		const curve = ECDsa.curves.find((c) => c.oid === ec.curve.oid)!;
		const keySizeInBytes = Math.ceil(curve.keySize / 8);

		const writer = new DerWriter(Buffer.alloc(1024));

		writer.writeInteger(BigInt.fromInt32(1)); // version
		writer.writeOctetString(ec.d!.toBytes({ unsigned: true, length: keySizeInBytes }));

		const curveWriter = new DerWriter(Buffer.alloc(100));
		curveWriter.writeObjectIdentifier(ec.curve.oid!);
		writer.writeTagged(0, curveWriter);

		const publicKeyWriter = new DerWriter(Buffer.alloc(512));
		const x = ec.x.toBytes({ unsigned: true, length: keySizeInBytes });
		const y = ec.y.toBytes({ unsigned: true, length: keySizeInBytes });
		const publicKeyData = Buffer.alloc(1 + x.length + y.length);
		publicKeyData[0] = 4; // Indicates uncompressed curve format
		x.copy(publicKeyData, 1);
		y.copy(publicKeyData, 1 + x.length);
		publicKeyWriter.writeBitString(publicKeyData);
		writer.writeTagged(1, publicKeyWriter);

		return writer.toBuffer();
	}

	private static importECPrivate(keyBytes: Buffer): ECParameters {
		const reader = new DerReader(keyBytes);
		const version = reader.readInteger().toInt32();
		if (version !== 1) {
			throw new Error(`Unsupported SEC1 format version: ${version}`);
		}

		const d = BigInt.fromBytes(reader.readOctetString(), { unsigned: true });

		const curveReader = reader.tryReadTagged(0);
		if (!curveReader) {
			throw new Error('SEC1 curve info not found.');
		}

		const curveOid = curveReader.readObjectIdentifier();
		const curveName = ECDsa.curves.find((c) => c.oid === curveOid)?.name;

		const publicKeyReader = reader.tryReadTagged(1);
		if (!publicKeyReader) {
			throw new Error('SEC1 public key data not found.');
		}

		const xy = publicKeyReader.readBitString();
		if (xy.length % 2 !== 1) {
			throw new Error(`Unexpected key data length: ${xy.length}`);
		}

		const x = BigInt.fromBytes(xy.slice(1, 1 + (xy.length - 1) / 2), { unsigned: true });
		const y = BigInt.fromBytes(xy.slice(1 + (xy.length - 1) / 2), { unsigned: true });
		const ec: ECParameters = {
			curve: { name: curveName, oid: curveOid },
			x,
			y,
			d,
		};
		return ec;
	}
}
