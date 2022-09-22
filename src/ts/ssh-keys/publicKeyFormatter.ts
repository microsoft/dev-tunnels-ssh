//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshAlgorithms, KeyPair, Rsa, ECDsa, SshDataReader } from '@microsoft/dev-tunnels-ssh';
import { KeyFormatter } from './keyFormatter';
import { KeyData } from './keyData';

/** Provides import/export of the SSH public key format. */
export class PublicKeyFormatter implements KeyFormatter {
	public async import(keyData: KeyData): Promise<KeyPair | null> {
		if (!keyData) throw new TypeError('KeyData object expected.');

		if (!keyData.keyType) {
			// Try to parse binary data without any key type prefix.
			try {
				const reader = new SshDataReader(keyData.data);
				keyData.keyType = reader.readString('ascii');
			} catch (e) {
				return null;
			}
		}

		let keyPair: KeyPair | null = null;

		if (keyData.keyType === Rsa.keyAlgorithmName) {
			keyPair = SshAlgorithms.publicKey.rsaWithSha512!.createKeyPair();
		} else if (keyData.keyType === ECDsa.ecdsaSha2Nistp256) {
			keyPair = SshAlgorithms.publicKey.ecdsaSha2Nistp256!.createKeyPair();
		} else if (keyData.keyType === ECDsa.ecdsaSha2Nistp384) {
			keyPair = SshAlgorithms.publicKey.ecdsaSha2Nistp384!.createKeyPair();
		} else if (keyData.keyType === ECDsa.ecdsaSha2Nistp521) {
			keyPair = SshAlgorithms.publicKey.ecdsaSha2Nistp521!.createKeyPair();
		}

		if (keyPair) {
			await keyPair.setPublicKeyBytes(keyData.data);

			const comment = keyData.headers.get('Comment');
			keyPair.comment = comment ?? null;
		}

		return keyPair;
	}

	public async export(keyPair: KeyPair, includePrivate: boolean): Promise<KeyData> {
		if (!keyPair) throw new TypeError('KeyPair object expected.');

		if (includePrivate) {
			throw new Error('SSH public key formatter does not support private keys.');
		}

		if (!keyPair.hasPublicKey) {
			throw new Error('KeyPair object does not include a public key.');
		}

		const keyData = new KeyData();
		keyData.keyType = keyPair.keyAlgorithmName;
		keyData.data = (await keyPair.getPublicKeyBytes())!;

		if (keyPair.comment) {
			keyData.headers.set('Comment', keyPair.comment);
		}

		return keyData;
	}

	public async decrypt(keyData: KeyData, passphrase: string | null): Promise<KeyData | null> {
		return keyData;
	}

	public encrypt(keyData: KeyData, passphrase: string): Promise<KeyData> {
		throw new Error('SSH public key format does not support encryption.');
	}
}
