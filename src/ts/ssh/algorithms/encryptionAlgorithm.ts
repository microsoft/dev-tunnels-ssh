//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { Disposable } from 'vscode-jsonrpc';
import { SshAlgorithm } from './sshAlgorithm';

export abstract class EncryptionAlgorithm implements SshAlgorithm {
	protected constructor(public readonly name: string) {}

	public abstract readonly keyLength: number;
	public abstract readonly blockLength: number;

	public abstract createCipher(isEncryption: boolean, key: Buffer, iv: Buffer): Promise<Cipher>;
}

export interface Cipher extends Disposable {
	readonly blockLength: number;
	transform(data: Buffer): Promise<Buffer>;
}
