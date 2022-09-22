//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { BigInt } from '../../io/bigInt';
import { RsaParameters, ECParameters } from '../publicKeyAlgorithm';
import { curves } from '../ecdsaCurves';

/**
 * Provides *minimal* JWK import/export support for web keys.
 *
 * This code is redundant with some of the JWK import/export code in the separate
 * `ssh-keys` library; that is intentional, and necessary to support a consistent
 * interface for importing/exporting key parameters in the core `ssh` library.
 */
export class JsonWebKeyFormatter {
	public static formatRsa(rsa: RsaParameters, includePrivate?: boolean): JsonWebKey {
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

	public static parseRsa(jwk: JsonWebKey, includePrivate?: boolean): RsaParameters {
		if (jwk?.kty !== 'RSA' || !(jwk.n && jwk.e)) throw new Error('Invalid RSA JWK.');

		const parseBigInt = JsonWebKeyFormatter.parseBigInt;

		let rsa: RsaParameters;
		if (includePrivate !== false && jwk.d && jwk.p && jwk.q && jwk.dp && jwk.dq && jwk.qi) {
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

	public static formatEC(ec: ECParameters, includePrivate?: boolean): JsonWebKey {
		const formatBigInt = JsonWebKeyFormatter.formatBigInt;

		const curve = curves.find(
			(c) => c.oid === ec.curve.oid || c.name === ec.curve.name || c.shortName === ec.curve.name,
		)!;
		const keySizeInBytes = Math.ceil(curve.keySize / 8);

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

	public static parseEC(jwk: JsonWebKey, includePrivate?: boolean): ECParameters {
		if (jwk?.kty !== 'EC' || !(jwk.crv && jwk.x && jwk.y)) throw new Error('Invalid EC JWK.');

		const parseBigInt = JsonWebKeyFormatter.parseBigInt;
		const ec: ECParameters = {
			curve: { name: jwk.crv },
			x: parseBigInt(jwk.x),
			y: parseBigInt(jwk.y),
		};

		if (includePrivate !== false && jwk.d) {
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
