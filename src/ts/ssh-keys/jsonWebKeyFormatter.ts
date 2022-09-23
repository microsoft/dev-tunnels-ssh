//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshAlgorithms, KeyPair, Rsa, RsaParameters, BigInt } from '@microsoft/dev-tunnels-ssh';
import { KeyFormatter } from './keyFormatter';
import { KeyData } from './keyData';
import { ECDsa, ECParameters } from '../ssh/algorithms/sshAlgorithms';

interface CommentedJwk extends JsonWebKey {
	comment?: string;
}

/** Provides import/export of the JSON Web Key format. */
export class JsonWebKeyFormatter implements KeyFormatter {
	public async import(keyData: KeyData): Promise<KeyPair | null> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		let keyJson: string;
		try {
			keyJson = JSON.parse(keyData.data.toString('utf8'));
		} catch (e) {
			return null;
		}

		const jwk = <CommentedJwk>keyJson;
		if (!jwk) {
			return null;
		}

		if (jwk.kty === 'RSA') {
			const parameters = JsonWebKeyFormatter.parseRsa(jwk);
			const keyPair = SshAlgorithms.publicKey.rsaWithSha512!.createKeyPair();
			await keyPair.importParameters(parameters);
			keyPair.comment = jwk.comment ?? null;
			return keyPair;
		} else if (jwk.kty === 'EC') {
			const parameters = JsonWebKeyFormatter.parseEC(jwk);
			const keyPair = new ECDsa.KeyPair();
			await keyPair.importParameters(parameters);
			keyPair.comment = jwk.comment ?? null;
			return keyPair;
		} else {
			throw new Error(`Key type not supported: ${jwk.kty}`);
		}
	}

	public async export(keyPair: KeyPair, includePrivate: boolean): Promise<KeyData> {
		if (!keyPair) throw new TypeError('KeyPair object expected.');

		let jwk: CommentedJwk;
		if (keyPair instanceof Rsa.KeyPair) {
			const parameters = await keyPair.exportParameters();
			jwk = <CommentedJwk>JsonWebKeyFormatter.formatRsa(parameters, includePrivate);
		} else if (keyPair instanceof ECDsa.KeyPair) {
			const parameters = await keyPair.exportParameters();
			jwk = <CommentedJwk>JsonWebKeyFormatter.formatEC(parameters, includePrivate);
		} else {
			throw new Error('KeyPair class not supported: ' + keyPair.constructor?.name);
		}

		if (keyPair.comment) {
			jwk.comment = keyPair.comment;
		}

		const keyData = new KeyData();
		keyData.data = Buffer.from(JSON.stringify(jwk, null, '\t') + '\n', 'utf8');
		return keyData;
	}

	public async decrypt(keyData: KeyData, passphrase: string | null): Promise<KeyData | null> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		// Just check if it's valid JSON.
		try {
			JSON.parse(keyData.data.toString('utf8'));
			return keyData;
		} catch (e) {
			return null;
		}
	}

	public encrypt(keyData: KeyData, passphrase: string): Promise<KeyData> {
		throw new Error('JWK does not support encryption.');
	}

	private static formatRsa(rsa: RsaParameters, includePrivate?: boolean): JsonWebKey {
		const formatBigInt = JsonWebKeyFormatter.formatBigInt;

		let jwk: JsonWebKey;
		if (includePrivate !== false && rsa.d && rsa.p && rsa.q && rsa.dp && rsa.dq && rsa.qi) {
			jwk = {
				kty: 'RSA',
				n: formatBigInt(rsa.modulus),
				e: formatBigInt(rsa.exponent),
				d: formatBigInt(rsa.d),
				p: formatBigInt(rsa.p),
				q: formatBigInt(rsa.q),
				dp: formatBigInt(rsa.dp),
				dq: formatBigInt(rsa.dq),
				qi: formatBigInt(rsa.qi),
			};
		} else if (!includePrivate) {
			jwk = {
				kty: 'RSA',
				n: formatBigInt(rsa.modulus),
				e: formatBigInt(rsa.exponent),
			};
		} else {
			throw new Error('Missing private key parameters.');
		}

		return jwk;
	}

	private static parseRsa(jwk: JsonWebKey): RsaParameters {
		if (jwk?.kty !== 'RSA' || !(jwk.n && jwk.e)) throw new Error('Invalid RSA JWK.');

		const parseBigInt = JsonWebKeyFormatter.parseBigInt;

		let rsa: RsaParameters;
		if (jwk.d && jwk.p && jwk.q && jwk.dp && jwk.dq && jwk.qi) {
			rsa = {
				modulus: parseBigInt(jwk.n),
				exponent: parseBigInt(jwk.e),
				d: parseBigInt(jwk.d),
				p: parseBigInt(jwk.p),
				q: parseBigInt(jwk.q),
				dp: parseBigInt(jwk.dp),
				dq: parseBigInt(jwk.dq),
				qi: parseBigInt(jwk.qi),
			};
		} else {
			rsa = {
				modulus: parseBigInt(jwk.n),
				exponent: parseBigInt(jwk.e),
			};
		}

		return rsa;
	}

	private static formatEC(ec: ECParameters, includePrivate?: boolean): JsonWebKey {
		const curve = ECDsa.curves.find((c) => c.oid === ec.curve.oid)!;
		const keySizeInBytes = Math.ceil(curve.keySize / 8);

		const formatBigInt = JsonWebKeyFormatter.formatBigInt;
		const jwk: JsonWebKey = {
			kty: 'EC',
			crv: ec.curve.name,
			x: formatBigInt(ec.x, keySizeInBytes),
			y: formatBigInt(ec.y, keySizeInBytes),
		};

		if (includePrivate !== false && ec.d) {
			jwk.d = formatBigInt(ec.d, keySizeInBytes);
		} else if (includePrivate) {
			throw new Error('Missing private key parameters.');
		}

		return jwk;
	}

	private static parseEC(jwk: JsonWebKey): ECParameters {
		if (jwk?.kty !== 'EC' || !(jwk.crv && jwk.x && jwk.y)) throw new Error('Invalid EC JWK.');

		const curveOid = ECDsa.curves.find((c) => c.name === jwk.crv)?.oid;
		if (!curveOid) {
			throw new Error(`Unknown EC curve: ${jwk.crv}`);
		}

		const parseBigInt = JsonWebKeyFormatter.parseBigInt;
		const ec: ECParameters = {
			curve: { name: jwk.crv, oid: curveOid },
			x: parseBigInt(jwk.x),
			y: parseBigInt(jwk.y),
		};

		if (jwk.d) {
			ec.d = parseBigInt(jwk.d!);
		}

		return ec;
	}

	private static formatBigInt(value: BigInt, length?: number) {
		return JsonWebKeyFormatter.base64UrlEncode(value.toBytes({ unsigned: true, length }));
	}

	private static parseBigInt(value: string) {
		return BigInt.fromBytes(Buffer.from(value, 'base64'), { unsigned: true });
	}

	private static base64UrlEncode(data: Buffer): string {
		// JWK format uses base64-url-encoding, which is base64 but with 2 substituted characters.
		// (Note Buffer's base64 DECODING implicitly supports this format.)
		return data
			.toString('base64')
			.replace(/=+$/g, '')
			.replace(/\+/g, '-')
			.replace(/\//g, '_');
	}
}
