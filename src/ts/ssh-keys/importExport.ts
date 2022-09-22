//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { KeyPair, ECDsa, Rsa } from '@microsoft/dev-tunnels-ssh';
import { KeyFormatter } from './keyFormatter';
import { DefaultKeyFormatter } from './defaultKeyFormatter';
import { PublicKeyFormatter } from './publicKeyFormatter';
import { Pkcs1KeyFormatter } from './pkcs1KeyFormatter';
import { Sec1KeyFormatter } from './sec1KeyFormatter';
import { Pkcs8KeyFormatter } from './pkcs8KeyFormatter';
import { JsonWebKeyFormatter } from './jsonWebKeyFormatter';
import { KeyData } from './keyData';
import { KeyFormat } from './keyFormat';

/**
 * Specifies how formatted key data is encoded into a string or file.
 */
export const enum KeyEncoding {
	Default = 0,
	Binary = 1,
	Base64 = 2,
	Pem = 3,
	SshBase64 = 4,
	Json = 5,
}

/**
 * Mapping to formatters for each supported key format.
 */
export const keyFormatters = new Map<KeyFormat, KeyFormatter>();
keyFormatters.set(KeyFormat.Default, new DefaultKeyFormatter());
keyFormatters.set(KeyFormat.Ssh, new PublicKeyFormatter());
keyFormatters.set(KeyFormat.Pkcs1, new Pkcs1KeyFormatter());
keyFormatters.set(KeyFormat.Sec1, new Sec1KeyFormatter());
keyFormatters.set(KeyFormat.Pkcs8, new Pkcs8KeyFormatter());
keyFormatters.set(KeyFormat.Jwk, new JsonWebKeyFormatter());

const enableFileIO = !!process?.versions?.node;

/** Exports the public key from a key pair, as a string. */
export function exportPublicKey(
	keyPair: KeyPair,
	keyFormat: KeyFormat = KeyFormat.Default,
	keyEncoding: KeyEncoding = KeyEncoding.Default,
): Promise<string> {
	if (keyEncoding === KeyEncoding.Binary) {
		throw new Error('Cannot represent binary-encoded key as a string.');
	}

	return exportPublicKeyBytes(keyPair, keyFormat, keyEncoding).then((keyBytes) =>
		keyBytes.toString('utf8'),
	);
}

/** Exports the public key from a key pair, to a file. */
export function exportPublicKeyFile(
	keyPair: KeyPair,
	keyFile: string,
	keyFormat: KeyFormat = KeyFormat.Default,
	keyEncoding: KeyEncoding = KeyEncoding.Default,
): Promise<void> {
	if (!enableFileIO) throw new Error('File I/O is not supported in a browser environment.');

	return exportPublicKeyBytes(keyPair, keyFormat, keyEncoding).then((keyBytes) =>
		require('fs').promises.writeFile(keyFile, keyBytes),
	);
}

/** Exports the public key from a key pair, to a byte buffer. */
export function exportPublicKeyBytes(
	keyPair: KeyPair,
	keyFormat: KeyFormat = KeyFormat.Default,
	keyEncoding: KeyEncoding = KeyEncoding.Default,
): Promise<Buffer> {
	return exportKeyBytes(keyPair, null, keyFormat, keyEncoding, false);
}

/** Exports the private key from a key pair, as a string. */
export function exportPrivateKey(
	keyPair: KeyPair,
	passphrase: string | null = null,
	keyFormat: KeyFormat = KeyFormat.Default,
	keyEncoding: KeyEncoding = KeyEncoding.Default,
): Promise<string> {
	if (keyEncoding === KeyEncoding.Binary) {
		throw new Error('Cannot represent binary-encoded key as a string.');
	}

	return exportPrivateKeyBytes(keyPair, passphrase, keyFormat, keyEncoding).then((keyBytes) =>
		keyBytes.toString('utf8'),
	);
}

/** Exports the private key from a key pair, to a file. */
export function exportPrivateKeyFile(
	keyPair: KeyPair,
	passphrase: string | null = null,
	keyFile: string,
	keyFormat: KeyFormat = KeyFormat.Default,
	keyEncoding: KeyEncoding = KeyEncoding.Default,
): Promise<void> {
	if (!enableFileIO) throw new Error('File I/O is not supported in a browser environment.');

	return exportPrivateKeyBytes(keyPair, passphrase, keyFormat, keyEncoding).then((keyBytes) =>
		require('fs').promises.writeFile(keyFile, keyBytes),
	);
}

/** Exports the private key from a key pair, to a byte buffer. */
export function exportPrivateKeyBytes(
	keyPair: KeyPair,
	passphrase: string | null = null,
	keyFormat: KeyFormat = KeyFormat.Default,
	keyEncoding: KeyEncoding = KeyEncoding.Default,
): Promise<Buffer> {
	return exportKeyBytes(keyPair, passphrase, keyFormat, keyEncoding, true);
}

/** Imports a public key or public/private key pair from a string. */
export function importKey(
	keyString: string,
	passphrase: string | null = null,
	keyFormat: KeyFormat = KeyFormat.Default,
	keyEncoding: KeyEncoding = KeyEncoding.Default,
): Promise<KeyPair> {
	if (keyEncoding === KeyEncoding.Binary) {
		throw new Error('Cannot represent binary-encoded key as a string.');
	}

	return importKeyBytes(Buffer.from(keyString, 'utf8'), passphrase, keyFormat, keyEncoding);
}

/** Imports a public key or public/private key pair from a file. */
export function importKeyFile(
	keyFile: string,
	passphrase: string | null = null,
	keyFormat: KeyFormat = KeyFormat.Default,
	keyEncoding: KeyEncoding = KeyEncoding.Default,
): Promise<KeyPair> {
	if (keyEncoding === KeyEncoding.Binary) {
		throw new Error('Cannot represent binary-encoded key as a string.');
	}

	return require('fs')
		.promises.readFile(keyFile)
		.then((keyBytes: Buffer) => importKeyBytes(keyBytes, passphrase, keyFormat, keyEncoding));
}

/** Imports a public key or public/private key pair from a byte array. */
export async function importKeyBytes(
	keyBytes: Buffer,
	passphrase: string | null = null,
	keyFormat: KeyFormat = KeyFormat.Default,
	keyEncoding: KeyEncoding = KeyEncoding.Default,
): Promise<KeyPair> {
	if (!(keyBytes instanceof Buffer)) throw new TypeError('Buffer expected.');

	let keyData: KeyData | null = null;
	if (keyEncoding === KeyEncoding.Default || keyEncoding === KeyEncoding.Pem) {
		keyData = KeyData.tryDecodePemBytes(keyBytes);
		if (!keyData && keyEncoding === KeyEncoding.Pem) {
			throw new Error('Key is not PEM-encoded.');
		}
	}

	let keyType: string | null = null;
	let comment: string | null = null;

	if (!keyData && (keyEncoding === KeyEncoding.Default || keyEncoding === KeyEncoding.Json)) {
		try {
			JSON.parse(keyBytes.toString('utf8'));
			keyData = new KeyData();
			keyData.data = keyBytes;
			keyEncoding = KeyEncoding.Json;
			keyFormat = KeyFormat.Jwk;
		} catch (e) {
			if (keyEncoding === KeyEncoding.Json) {
				throw new Error('Key is not JSON-formatted.');
			}
		}
	}

	if (
		!keyData &&
		(keyFormat === KeyFormat.Default || keyFormat === KeyFormat.Ssh) &&
		(keyEncoding === KeyEncoding.Default || keyEncoding === KeyEncoding.SshBase64)
	) {
		try {
			let keyString = keyBytes.toString('utf8');
			const lines = keyString.split('\n').filter((line) => !!line);
			if (lines.length === 1) {
				keyString = lines[0];

				const parts = keyString.split(' ', 3);
				if (parts.length >= 2 && parts[0].length < 40) {
					keyType = parts[0];
					keyBytes = Buffer.from(parts[1], 'utf8');
					comment = parts.length === 3 ? parts[2].trimRight() : null;
					keyEncoding = KeyEncoding.Base64;
					keyFormat = KeyFormat.Ssh;
				}
			}
		} catch (e) {}

		if (!keyType && keyEncoding === KeyEncoding.SshBase64) {
			throw new Error('Key does not have SSH algorithm prefix.');
		}
	}

	if (!keyData && (keyEncoding === KeyEncoding.Default || keyEncoding === KeyEncoding.Base64)) {
		try {
			const keyString = keyBytes.toString('utf8');
			// Node doesn't throw when parsing invalid base64. To check if the parse was successful,
			// compare the resulting decoded bytes to the expected length, which is 3/4 of the input.
			if (keyString.length % 4 === 0) {
				const encodedLengthWithoutPadding =
					keyString.length - (keyString.endsWith('==') ? 2 : keyString.endsWith('=') ? 1 : 0);
				const decodedLength = Math.floor((encodedLengthWithoutPadding / 4) * 3);
				const decoded = Buffer.from(keyString, 'base64');
				if (decoded.length === decodedLength) {
					keyBytes = decoded;
					keyEncoding = KeyEncoding.Binary;
				}
			}
		} catch (e) {
			if (keyEncoding === KeyEncoding.Base64) {
				throw new Error('Key is not base64-encoded.');
			}
		}
	}

	if (
		keyData === null &&
		(keyEncoding === KeyEncoding.Default ||
			keyEncoding === KeyEncoding.Binary ||
			keyEncoding === KeyEncoding.Json)
	) {
		keyData = new KeyData();
		keyData.data = keyBytes;

		if (keyType) {
			keyData.keyType = keyType;
		}

		if (comment) {
			keyData.headers.set('Comment', comment);
		}
	}

	if (!keyData) {
		throw new Error('Failed to decode key.');
	}

	if (keyFormat === KeyFormat.Default && !keyData.keyType) {
		throw new Error('Specify a key format when importing binary data.');
	}

	const formatter = keyFormatters.get(keyFormat);
	if (!formatter) {
		throw new Error(`Unimplemented or invalid or key format: ${keyFormat}`);
	}

	keyData = await formatter.decrypt(keyData, passphrase);
	if (!keyData) {
		throw new Error('Failed to decrypt key.');
	}

	const keyPair = await formatter.import(keyData);
	if (!keyPair) {
		throw new Error('Failed to import key.');
	}

	return keyPair;
}

async function exportKeyBytes(
	keyPair: KeyPair,
	passphrase: string | null,
	keyFormat: KeyFormat,
	keyEncoding: KeyEncoding,
	includePrivate: boolean,
): Promise<Buffer> {
	if (typeof keyPair !== 'object') throw new TypeError('KeyPair object expected.');

	if (includePrivate && !keyPair.hasPrivateKey) {
		throw new Error('The KeyPair object does not contain a private key.');
	}

	if (keyFormat === KeyFormat.Default) {
		keyFormat = includePrivate ? KeyFormat.Pkcs8 : KeyFormat.Ssh;
	}

	if (keyEncoding === KeyEncoding.Default) {
		switch (keyFormat) {
			case KeyFormat.Ssh:
				keyEncoding = KeyEncoding.SshBase64;
				break;
			case KeyFormat.Jwk:
				keyEncoding = KeyEncoding.Json;
				break;
			default:
				keyEncoding = KeyEncoding.Pem;
				break;
		}
	}

	// Automatically switch between PKCS#1/SEC1 based on key algorithm.
	if (keyFormat === KeyFormat.Pkcs1 && keyPair instanceof ECDsa.KeyPair) {
		keyFormat = KeyFormat.Sec1;
	} else if (keyFormat === KeyFormat.Sec1 && keyPair instanceof Rsa.KeyPair) {
		keyFormat = KeyFormat.Pkcs1;
	}

	const formatter = keyFormatters.get(keyFormat);
	if (!formatter) {
		throw new Error(`Unimplemented or invalid or key format: ${keyFormat}`);
	}

	let keyData = await formatter.export(keyPair, includePrivate);
	if (passphrase) {
		keyData = await formatter.encrypt(keyData, passphrase);
	}

	switch (keyEncoding) {
		case KeyEncoding.Binary:
		case KeyEncoding.Json:
			return keyData.data;
		case KeyEncoding.Base64:
			return Buffer.from(keyData.data.toString('base64'), 'utf8');
		case KeyEncoding.SshBase64:
			return keyData.encodeSshPublicKeyBytes();
		case KeyEncoding.Pem:
			return keyData.encodePemBytes();
		default:
			throw new Error('Invalid key encoding.');
	}
}
