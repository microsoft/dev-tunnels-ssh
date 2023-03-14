//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { KeyPair } from '@microsoft/dev-tunnels-ssh';
import { KeyFormat } from './keyFormat';
import { KeyFormatter } from './keyFormatter';
import { KeyData } from './keyData';
import { keyFormatters } from './importExport';

/**
 * Auto-detects the format of a key when importing, by trying all the available formatters.
 */
export class DefaultKeyFormatter implements KeyFormatter {
	public export(keyPair: KeyPair, includePrivate: boolean): Promise<KeyData> {
		throw new Error('DefaultKeyFormatter should not be used for exporting.');
	}

	public encrypt(keyData: KeyData, passphrase: string): Promise<KeyData> {
		throw new Error('DefaultKeyFormatter should not be used for encrypting.');
	}

	public async import(keyData: KeyData): Promise<KeyPair | null> {
		for (const [keyFormat, keyFormatter] of keyFormatters) {
			if (
				keyFormat !== KeyFormat.Default &&
				keyFormat !== KeyFormat.Ssh &&
				keyFormat !== KeyFormat.Jwk
			) {
				const keyPair = await keyFormatter.import(keyData);
				if (keyPair) {
					return keyPair;
				}
			}
		}

		return null;
	}

	public async decrypt(keyData: KeyData, passphrase: string | null): Promise<KeyData | null> {
		for (const [keyFormat, keyFormatter] of keyFormatters) {
			if (
				keyFormat !== KeyFormat.Default &&
				keyFormat !== KeyFormat.Ssh &&
				keyFormat !== KeyFormat.Jwk
			) {
				const decryptedKeyData = await keyFormatter.decrypt(keyData, passphrase);
				if (decryptedKeyData) {
					return decryptedKeyData;
				}
			}
		}

		return null;
	}
}
