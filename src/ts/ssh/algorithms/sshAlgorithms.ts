//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshAlgorithm } from './sshAlgorithm';
import { KeyExchangeAlgorithm, KeyExchange } from './keyExchangeAlgorithm';
import { PublicKeyAlgorithm, KeyPair, RsaParameters, ECParameters } from './publicKeyAlgorithm';
import { EncryptionAlgorithm, Cipher } from './encryptionAlgorithm';
import {
	HmacAlgorithm,
	Signer,
	Verifier,
	MessageSigner,
	MessageVerifier,
	HmacInfo,
} from './hmacAlgorithm';
import { CompressionAlgorithm } from './compressionAlgorithm';

export {
	SshAlgorithm,
	KeyExchangeAlgorithm,
	KeyExchange,
	PublicKeyAlgorithm,
	KeyPair,
	EncryptionAlgorithm,
	Cipher,
	HmacAlgorithm,
	Signer,
	Verifier,
	MessageSigner,
	MessageVerifier,
	HmacInfo,
	CompressionAlgorithm,
	RsaParameters,
	ECParameters,
};

// Swap imports to node crypto implementations when web crypto is not available.
const useWebCrypto = typeof window !== 'undefined' &&
	!!(typeof crypto === 'object' && crypto.subtle);

import { WebDiffieHellman, WebECDiffieHellman } from './web/webKeyExchange';
import { WebRsa } from './web/webRsa';
import { WebECDsa } from './web/webECDsa';
import { WebEncryption } from './web/webEncryption';
import { WebHmac } from './web/webHmac';
import { WebRandom } from './web/webRandom';

export interface Random {
	getBytes(buffer: Buffer): void;
}

/* eslint-disable @typescript-eslint/naming-convention, id-match */
const DiffieHellman: typeof WebDiffieHellman = useWebCrypto
	? WebDiffieHellman
	: require('./node/nodeKeyExchange').NodeDiffieHellman;
const ECDiffieHellman: typeof WebECDiffieHellman = useWebCrypto
	? WebECDiffieHellman
	: require('./node/nodeKeyExchange').NodeECDiffieHellman;
const Rsa: typeof WebRsa = useWebCrypto ? WebRsa : require('./node/nodeRsa').NodeRsa;
const ECDsa: typeof WebECDsa = useWebCrypto ? WebECDsa : require('./node/nodeECDsa').NodeECDsa;
const Encryption: typeof WebEncryption = useWebCrypto
	? WebEncryption
	: require('./node/nodeEncryption').NodeEncryption;
const Hmac: typeof WebHmac = useWebCrypto ? WebHmac : require('./node/nodeHmac').NodeHmac;
// eslint-disable-next-line no-redeclare
const Random: typeof WebRandom = useWebCrypto ? WebRandom : require('./node/nodeRandom').NodeRandom;
/* eslint-enable @typescript-eslint/naming-convention, id-match */

// eslint-disable-next-line no-redeclare
namespace Rsa {
	// eslint-disable-next-line no-shadow,@typescript-eslint/no-shadow
	export type KeyPair = WebRsa.KeyPair;
}

// eslint-disable-next-line no-redeclare
namespace ECDsa {
	// eslint-disable-next-line no-shadow,@typescript-eslint/no-shadow
	export type KeyPair = WebECDsa.KeyPair;
}

export { Rsa, ECDsa, Encryption };

export class SshAlgorithms {
	public static keyExchange: { [id: string]: KeyExchangeAlgorithm | null } = {
		none: null,
		dhGroup14Sha256: new DiffieHellman('diffie-hellman-group14-sha256', 2048, 'SHA2-256'),
		dhGroup16Sha512: new DiffieHellman('diffie-hellman-group16-sha512', 4096, 'SHA2-512'),
		ecdhNistp256Sha256: new ECDiffieHellman('ecdh-sha2-nistp256', 256, 'SHA2-256'),
		ecdhNistp384Sha384: new ECDiffieHellman('ecdh-sha2-nistp384', 384, 'SHA2-384'),
		ecdhNistp521Sha512: new ECDiffieHellman('ecdh-sha2-nistp521', 521, 'SHA2-512'),
	};

	public static publicKey: { [id: string]: PublicKeyAlgorithm | null } = {
		none: null,
		rsaWithSha256: new Rsa('rsa-sha2-256', 'SHA2-256'),
		rsaWithSha512: new Rsa('rsa-sha2-512', 'SHA2-512'),
		ecdsaSha2Nistp256: new ECDsa('ecdsa-sha2-nistp256', 'SHA2-256'),
		ecdsaSha2Nistp384: new ECDsa('ecdsa-sha2-nistp384', 'SHA2-384'),
		ecdsaSha2Nistp521: new ECDsa('ecdsa-sha2-nistp521', 'SHA2-512'),
	};

	public static encryption: { [id: string]: EncryptionAlgorithm | null } = {
		none: null,
		////aes256Cbc: new Encryption('aes256-cbc', 'AES', 'CBC', 256) },
		aes256Ctr: new Encryption('aes256-ctr', 'AES', 'CTR', 256),
		aes256Gcm: new Encryption('aes256-gcm@openssh.com', 'AES', 'GCM', 256),
	};

	public static hmac: { [id: string]: HmacAlgorithm | null } = {
		none: null,
		hmacSha256: new Hmac('hmac-sha2-256', 'SHA2-256'),
		hmacSha512: new Hmac('hmac-sha2-512', 'SHA2-512'),
		hmacSha256Etm: new Hmac('hmac-sha2-256-etm@openssh.com', 'SHA2-256', true),
		hmacSha512Etm: new Hmac('hmac-sha2-512-etm@openssh.com', 'SHA2-512', true),
	};

	public static compression: { [id: string]: CompressionAlgorithm | null } = {
		none: null,
	};

	public static random: Random = new Random();
}

export function algorithmNames<T extends SshAlgorithm>(list: (T | null)[]): string[] {
	return list.map((a) => (a ? a.name : 'none'));
}
