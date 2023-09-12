//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { KeyPair, EncryptionAlgorithm, Encryption } from '@microsoft/dev-tunnels-ssh';
import { KeyData } from './keyData';

/**
 * Interface for a provider of import, export, decryption, and encryption for one of the
 * supported key formats.
 */
export interface KeyFormatter {
	/**
	 * Creates a key pair object by deserializing key data.
	 * @param keyData Key data that was decoded from PEM or other encoding and already
	 * decrypted if necessary.
	 * @returns The created key pair, or null if this formatter does not handle the
	 * format of the supplied key data.
	 */
	import(keyData: KeyData): Promise<KeyPair | null>;

	/**
	 * Serializes a key pair object.
	 * @param keyPair The public key or public/private key pair to serialize.
	 * @param includePrivate True if the private key should be serialized.</param>
	 * @returns Formatted (but not yet encrypted or encoded) key data.
	 */
	export(keyPair: KeyPair, includePrivate: boolean): Promise<KeyData>;

	/**
	 * Decrypts key data before it is imported.
	 * @param keyData Key data that was decoded from PEM or other encoding.
	 * @param passphrase Decryption passphrase supplied by the caller, or null
	 * if no passphrase was supplied.
	 * @returns Decrypted key data (still in the same format), or null if this formatter
	 * does not handle the format of the supplied key data.
	 */
	decrypt(keyData: KeyData, passphrase: string | null): Promise<KeyData | null>;

	/**
	 * Encrypts key data after it was exported.
	 * @param keyData Key data that was exported by the same formatter.
	 * @param passphrase Passphrase from which an encryption key is derived.
	 * @returns Encrypted key data (still in the same format).
	 */
	encrypt(keyData: KeyData, passphrase: string): Promise<KeyData>;
}

export function getKeyEncryptionAlgorithm(algorithm: string): EncryptionAlgorithm {
	// Different formats may use different casing and hyphens. Normalize before comparing.
	algorithm = algorithm.toUpperCase().replace(/-/g, '');

	// Note algorithms other than AES256 are used only for decrypting (importing) keys.
	switch (algorithm) {
		case 'AES128CBC':
			return new Encryption('aes128-cbc', 'AES', 'CBC', 128);
		case 'AES128CTR':
			return new Encryption('aes128-ctr', 'AES', 'CTR', 128);
		case 'AES192CBC':
			return new Encryption('aes192-cbc', 'AES', 'CBC', 192);
		case 'AES192CTR':
			return new Encryption('aes192-ctr', 'AES', 'CTR', 192);
		case 'AES256CBC':
			return new Encryption('aes256-cbc', 'AES', 'CBC', 256);
		case 'AES256CTR':
			return new Encryption('aes256-ctr', 'AES', 'CTR', 256);
		default:
			throw new Error(`Key cipher not supported: ${algorithm}`);
	}
}

/**
 * Use web crypto when in a browser and the crypto.subtle API is available.
 * Otherwise use Node.js crypto.
 */
export function useWebCrypto(): boolean {
	return typeof window !== 'undefined' && !!(typeof crypto === 'object' && crypto.subtle);
}
