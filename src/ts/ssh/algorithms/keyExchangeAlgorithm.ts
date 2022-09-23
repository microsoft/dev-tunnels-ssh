//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { SshAlgorithm } from './sshAlgorithm';
import { Signer } from './hmacAlgorithm';

export abstract class KeyExchangeAlgorithm implements SshAlgorithm {
	protected constructor(
		public readonly name: string,
		public readonly keySizeInBits: number,
		public readonly hashAlgorithmName: string,
		public readonly hashDigestLength: number,
	) {}

	public abstract createKeyExchange(): KeyExchange;
}

export interface KeyExchange extends Signer {
	startKeyExchange(): Promise<Buffer>;
	decryptKeyExchange(exchangeValue: Buffer): Promise<Buffer>;
}
