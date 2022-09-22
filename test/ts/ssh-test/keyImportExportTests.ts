//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, params, pending, slow, timeout } from '@testdeck/mocha';
import {
	KeyFormat,
	KeyEncoding,
	keyFormatters,
	importKey,
	exportPublicKey,
	exportPrivateKey,
	exportPublicKeyBytes,
	importKeyBytes,
	exportPrivateKeyBytes,
	Pkcs8KeyFormatter,
} from '@microsoft/dev-tunnels-ssh-keys';
import { MockRandom } from './mockRandom';

@suite
@slow(200)
export class KeyImportExportTests {
	@test
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa521', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'ecdsa521', keyFormat: KeyFormat.Pkcs8 })
	@params.naming((p) => `importPublicKey(${p.algorithm}, ${getFormatName(p.keyFormat)})`)
	public async importPublicKey({
		algorithm,
		keyFormat,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
	}) {
		const suffix = getFormatName(keyFormat);
		const keyPair = await importKey(readTestFile(`public-${algorithm}-${suffix}`));
		assert(keyPair);
		assert(keyPair.hasPublicKey);
		assert(!keyPair.hasPrivateKey);

		let expected = readTestFile(`public-${algorithm}-ssh`);
		if (
			keyFormat === KeyFormat.Pkcs1 ||
			keyFormat == KeyFormat.Sec1 ||
			keyFormat === KeyFormat.Pkcs8
		) {
			// Some formats don't support comments.
			const publicKey = await importKey(expected);
			publicKey.comment = null;
			expected = await exportPublicKey(publicKey);
		}

		const exported = await exportPublicKey(keyPair);
		assert.equal(exported, expected);
	}

	@test
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8, passphrase: 'password' })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Sec1 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8, passphrase: 'password' })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa521', keyFormat: KeyFormat.Sec1 })
	@params({ algorithm: 'ecdsa521', keyFormat: KeyFormat.Pkcs8 })
	@params.naming(
		(p) =>
			`importPrivateKey(${p.algorithm}, ${getFormatName(p.keyFormat)}, ${p.passphrase ??
				'null'})`,
	)
	public async importPrivateKey({
		algorithm,
		keyFormat,
		passphrase,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
		passphrase?: string;
	}) {
		const suffix = getFormatName(keyFormat) + (passphrase ? '-pw' : '');
		const keyPair = await importKey(readTestFile(`private-${algorithm}-${suffix}`), passphrase);
		assert(keyPair);
		assert(keyPair.hasPublicKey);
		assert(keyPair.hasPrivateKey);

		let expected = readTestFile(`public-${algorithm}-ssh`);
		if (
			keyFormat === KeyFormat.Pkcs1 ||
			keyFormat == KeyFormat.Sec1 ||
			keyFormat === KeyFormat.Pkcs8
		) {
			// Some formats don't support comments.
			const publicKey = await importKey(expected);
			publicKey.comment = null;
			expected = await exportPublicKey(publicKey);
		}

		try {
			const exported = await exportPublicKey(keyPair);
			assert.equal(exported, expected);
		} catch (e) {
			if (keyFormat === KeyFormat.Pkcs1) throw e;
		}
	}

	@test
	@pending(!process.platform) // Not implemented on browser platform.
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs1, passphrase: 'password' })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Sec1, passphrase: 'password' })
	@params.naming(
		(p) =>
			`importPrivateKey(${p.algorithm}, ${getFormatName(p.keyFormat)}, ${p.passphrase ??
				'null'})`,
	)
	public async importPrivateKey2({
		algorithm,
		keyFormat,
		passphrase,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
		passphrase?: string;
	}) {
		await this.importPrivateKey({ algorithm, keyFormat, passphrase });
	}

	@test
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8 })
	@params.naming(
		(p) => `importPrivateKeyInvalidPassword(${p.algorithm}, ${getFormatName(p.keyFormat)})`,
	)
	public async importPrivateKeyInvalidPassword({
		algorithm,
		keyFormat,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
	}) {
		const suffix = getFormatName(keyFormat) + '-pw';
		const privateKeyFile = readTestFile(`private-${algorithm}-${suffix}`);

		let error: Error | null = null;
		try {
			await importKey(privateKeyFile, null);
		} catch (e) {
			error = e as Error;
		}

		assert(error);
		assert.equal(error?.message, 'A passphrase is required to decrypt the key.');

		error = null;
		try {
			await importKey(privateKeyFile, 'invalid');
		} catch (e) {
			error = e as Error;
		}

		assert(error);
		assert.equal(error?.message, 'Key decryption failed - incorrect passphrase.');
	}

	@test
	@pending(!process.platform) // Not implemented on browser platform.
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Sec1 })
	@params.naming(
		(p) => `importPrivateKeyInvalidPassword(${p.algorithm}, ${getFormatName(p.keyFormat)})`,
	)
	public async importPrivateKeyInvalidPassword2({
		algorithm,
		keyFormat,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
	}) {
		await this.importPrivateKeyInvalidPassword({ algorithm, keyFormat });
	}

	@test
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa521', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'ecdsa521', keyFormat: KeyFormat.Pkcs8 })
	@params.naming((p) => `exportPublicKey(${p.algorithm}, ${getFormatName(p.keyFormat)})`)
	public async exportPublicKey({
		algorithm,
		keyFormat,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
	}) {
		const suffix = getFormatName(keyFormat);
		const publicKey = await importKey(readTestFile(`public-${algorithm}-ssh`));

		const exported = await exportPublicKey(publicKey, keyFormat);
		const expected = readTestFile(`public-${algorithm}-${suffix}`);
		assert.equal(exported, expected);
	}

	@test
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Sec1 })
	@params.naming(
		(p) => `exportPublicKeyNotSupported(${p.algorithm}, ${getFormatName(p.keyFormat)})`,
	)
	public async exportPublicKeyNotSupported({
		algorithm,
		keyFormat,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
	}) {
		const suffix = getFormatName(keyFormat);
		const publicKey = await importKey(readTestFile(`public-${algorithm}-ssh`));

		let error: Error | null = null;
		try {
			await exportPublicKey(publicKey, keyFormat);
		} catch (e) {
			error = e as Error;
		}

		assert(error);
		assert(error?.message && /not supported/.test(error.message));
	}

	@test
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs1, passphrase: 'password' })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8, passphrase: 'password' })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa4096', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Sec1 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Sec1, passphrase: 'password' })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8, passphrase: 'password' })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa521', keyFormat: KeyFormat.Sec1 })
	@params({ algorithm: 'ecdsa521', keyFormat: KeyFormat.Pkcs8 })
	@params.naming(
		(p) =>
			`exportPrivateKey(${p.algorithm}, ${getFormatName(p.keyFormat)}, ${p.passphrase ??
				'null'})`,
	)
	public async exportPrivateKey({
		algorithm,
		keyFormat,
		passphrase,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
		passphrase?: string;
	}) {
		provideMockRandomBytes(keyFormat, !!passphrase);

		const suffix = getFormatName(keyFormat) + (passphrase ? '-pw' : '');
		const formatSuffix = algorithm.startsWith('rsa') ? 'pkcs1' : 'sec1';
		const keyPair = await importKey(readTestFile(`private-${algorithm}-${formatSuffix}`));
		keyPair.comment = 'comment';

		let error: Error | null = null;
		let exported: string | null = null;
		try {
			exported = await exportPrivateKey(keyPair, passphrase, keyFormat);
		} catch (e) {
			error = e as Error;
		}

		if (passphrase && (keyFormat === KeyFormat.Pkcs1 || keyFormat === KeyFormat.Sec1)) {
			// PKCS1/SEC1 export with passphrase is not supported due to weak encryption.
			assert(error);
			assert(error?.message && /export with passphrase is not supported/.test(error.message));
		} else {
			const expected = readTestFile(`private-${algorithm}-${suffix}`);
			assert.equal(exported, expected);
		}
	}

	@test
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Ssh })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Jwk })
	@params.naming(
		(p) => `exportImportPublicKeyBytes(${p.algorithm}, ${getFormatName(p.keyFormat)})`,
	)
	public async exportImportPublicKeyBytes({
		algorithm,
		keyFormat,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
	}) {
		const publicKey = await importKey(readTestFile(`public-${algorithm}-ssh`));
		const publicKeyBytes = await exportPublicKeyBytes(publicKey, keyFormat, KeyEncoding.Binary);
		const publicKey2 = await importKeyBytes(publicKeyBytes, null, keyFormat);
		publicKey2.comment = 'comment';

		const exported = await exportPublicKey(publicKey2, KeyFormat.Ssh);
		const expected = readTestFile(`public-${algorithm}-ssh`);
		assert.equal(exported, expected);
	}

	@test
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs1 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Pkcs8, passphrase: 'password' })
	@params({ algorithm: 'rsa2048', keyFormat: KeyFormat.Jwk })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Sec1 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8 })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Pkcs8, passphrase: 'password' })
	@params({ algorithm: 'ecdsa384', keyFormat: KeyFormat.Jwk })
	@params.naming(
		(p) =>
			`exportImportPrivateKeyBytes(${p.algorithm}, ${getFormatName(
				p.keyFormat,
			)}, ${p.passphrase ?? 'null'})`,
	)
	public async exportImportPrivateKeyBytes({
		algorithm,
		keyFormat,
		passphrase,
	}: {
		algorithm: string;
		keyFormat: KeyFormat;
		passphrase?: string;
	}) {
		provideMockRandomBytes(keyFormat, !!passphrase);

		const formatSuffix = algorithm.startsWith('rsa') ? 'pkcs1' : 'sec1';
		const privateKey = await importKey(readTestFile(`private-${algorithm}-${formatSuffix}`));
		const privateKeyBytes = await exportPrivateKeyBytes(
			privateKey,
			passphrase,
			keyFormat,
			KeyEncoding.Binary,
		);

		const privateKey2 = await importKeyBytes(privateKeyBytes, passphrase, keyFormat);

		const exportFormat = algorithm == 'rsa' ? KeyFormat.Pkcs1 : KeyFormat.Sec1;
		const exported = await exportPrivateKey(privateKey2, null, exportFormat);
		const expected = readTestFile(`private-${algorithm}-${formatSuffix}`);
		assert.equal(exported, expected);
	}
}

function readTestFile(name: string): string {
	const testKeys = require('./testKeys');
	const bytes: Buffer = testKeys[name];
	if (!bytes) throw new Error('Test key file not found: ' + name);
	return bytes.toString('utf8').replace(/\r/g, '');
}

function getFormatName(keyFormat: KeyFormat): string {
	switch (keyFormat) {
		case KeyFormat.Ssh:
			return 'ssh';
		case KeyFormat.Pkcs1:
			return 'pkcs1';
		case KeyFormat.Sec1:
			return 'sec1';
		case KeyFormat.Pkcs8:
			return 'pkcs8';
		case KeyFormat.Jwk:
			return 'jwk';
		default:
			throw new Error('Not implemented.');
	}
}

function provideMockRandomBytes(keyFormat: KeyFormat, encrypting: boolean): void {
	if (keyFormat === KeyFormat.Pkcs8 && encrypting) {
		var mockRandom = new MockRandom();
		var formatter = <Pkcs8KeyFormatter>keyFormatters.get(KeyFormat.Pkcs8);
		formatter.random = mockRandom;

		var salt = [0x1f, 0xc0, 0xf9, 0x60, 0xc9, 0x51, 0x89, 0x9a];
		mockRandom.values.push(Buffer.from(salt));

		// prettier-ignore
		var iv = [
			0x38, 0xaf, 0x3d, 0x00, 0xec, 0xe6, 0x43, 0x42,
			0x7c, 0x94, 0x30, 0x73, 0xcb, 0x92, 0x4f, 0xa2,
		];
		mockRandom.values.push(Buffer.from(iv));
	}
}
