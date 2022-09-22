//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { BigInt } from '../../io/bigInt';
import { DerReader, DerWriter } from '../../io/derData';
import { RsaParameters, ECParameters } from '../publicKeyAlgorithm';
import { curves } from '../ecdsaCurves';

export function formatPem(keyBytes: Buffer, name: string): string {
	const key =
		`-----BEGIN ${name}-----\n` +
		keyBytes
			.toString('base64')
			.match(/.{1,64}/g)!
			.join('\n') +
		'\n' +
		`-----END ${name}-----\n`;
	return key;
}

export function parsePem(key: string): Buffer {
	const keyBase64 = key.replace(/-+[^-\n]+KEY-+/g, '').replace(/\s/g, '');
	const keyBytes = Buffer.from(keyBase64, 'base64');
	return keyBytes;
}

/**
 * Provides *minimal* PKCS#1 import/export support for Node.js keys.
 *
 * This code is redundant with some of the PKCS#1 import/export code in the separate
 * `ssh-keys` library; that is intentional, and necessary to support a consistent
 * interface for importing/exporting key parameters in the core `ssh` library.
 */
export class Pkcs1KeyFormatter {
	public static formatRsaPublic(rsa: RsaParameters): Buffer {
		const writer = new DerWriter(Buffer.alloc(1024));
		writer.writeInteger(rsa.modulus);
		writer.writeInteger(rsa.exponent);
		return writer.toBuffer();
	}

	public static formatRsaPrivate(rsa: RsaParameters): Buffer {
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

	public static parseRsaPublic(keyBytes: Buffer): RsaParameters {
		const reader = new DerReader(keyBytes);
		const modulus = reader.readInteger();
		const exponent = reader.readInteger();
		return { modulus, exponent };
	}

	public static parseRsaPrivate(keyBytes: Buffer): RsaParameters {
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
}

/**
 * Provides *minimal* SEC1 import/export support for Node.js keys.
 *
 * This code is redundant with some of the SEC1 import/export code in the separate
 * `ssh-keys` library; that is intentional, and necessary to support a consistent
 * interface for importing/exporting key parameters in the core `ssh` library.
 */
export class Sec1KeyFormatter {
	private static readonly ecPublicKeyOid = '1.2.840.10045.2.1';

	public static formatECPublic(ec: ECParameters): Buffer {
		const curve = curves.find((c) => c.oid === ec.curve.oid)!;
		const keySizeInBytes = Math.ceil(curve.keySize / 8);

		const writer = new DerWriter(Buffer.alloc(512));
		const oidsWriter = new DerWriter(Buffer.alloc(100));
		oidsWriter.writeObjectIdentifier(Sec1KeyFormatter.ecPublicKeyOid);
		oidsWriter.writeObjectIdentifier(ec.curve.oid!);
		writer.writeSequence(oidsWriter);

		const x = ec.x.toBytes({ unsigned: true, length: keySizeInBytes });
		const y = ec.y.toBytes({ unsigned: true, length: keySizeInBytes });
		const publicKeyData = Buffer.alloc(1 + x.length + y.length);
		publicKeyData[0] = 4; // Indicates uncompressed curve format
		x.copy(publicKeyData, 1);
		y.copy(publicKeyData, 1 + x.length);

		writer.writeBitString(publicKeyData);
		return writer.toBuffer();
	}

	public static formatECPrivate(ec: ECParameters): Buffer {
		const curve = curves.find((c) => c.oid === ec.curve.oid)!;
		const keySizeInBytes = Math.ceil(curve.keySize / 8);

		const writer = new DerWriter(Buffer.alloc(512));
		writer.writeInteger(BigInt.fromInt32(1)); // version
		writer.writeOctetString(ec.d!.toBytes({ unsigned: true, length: keySizeInBytes }));

		const curveWriter = new DerWriter(Buffer.alloc(100));
		curveWriter.writeObjectIdentifier(ec.curve.oid!);
		writer.writeTagged(0, curveWriter);

		const x = ec.x.toBytes({ unsigned: true, length: keySizeInBytes });
		const y = ec.y.toBytes({ unsigned: true, length: keySizeInBytes });
		const publicKeyData = Buffer.alloc(1 + x.length + y.length);
		publicKeyData[0] = 4; // Indicates uncompressed curve format
		x.copy(publicKeyData, 1);
		y.copy(publicKeyData, 1 + x.length);

		const keyWriter = new DerWriter(Buffer.alloc(512));
		keyWriter.writeBitString(publicKeyData);
		writer.writeTagged(1, keyWriter);
		return writer.toBuffer();
	}

	public static parseECPublic(keyBytes: Buffer): ECParameters {
		const reader = new DerReader(keyBytes);

		const oidsReader = reader.readSequence();
		const keyTypeOid = oidsReader.readObjectIdentifier();
		if (keyTypeOid !== Sec1KeyFormatter.ecPublicKeyOid) {
			throw new Error(`Unexpected key type OID: ${keyTypeOid}`);
		}

		const curveOid = oidsReader.readObjectIdentifier();
		const curveName = curves.find((c) => c.oid === curveOid)?.name;

		const xy = reader.readBitString();
		if (xy.length % 2 !== 1) {
			throw new Error(`Unexpected key data length: ${xy.length}`);
		}

		const x = BigInt.fromBytes(xy.slice(1, 1 + (xy.length - 1) / 2), { unsigned: true });
		const y = BigInt.fromBytes(xy.slice(1 + (xy.length - 1) / 2), { unsigned: true });

		const ec: ECParameters = {
			curve: { name: curveName, oid: curveOid },
			x,
			y,
		};
		return ec;
	}

	public static parseECPrivate(keyBytes: Buffer): ECParameters {
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
		const curveName = curves.find((c) => c.oid === curveOid)?.name;

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
