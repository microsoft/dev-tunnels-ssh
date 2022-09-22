//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { Disposable } from 'vscode-jsonrpc';
import { SshAlgorithm } from './sshAlgorithm';

export abstract class HmacAlgorithm implements SshAlgorithm {
	protected constructor(
		public readonly name: string,
		public readonly algorithmName: string,
		public readonly keyLength: number,
		public readonly digestLength: number,
	) {}

	public abstract createSigner(key: Buffer): Promise<MessageSigner>;
	public abstract createVerifier(key: Buffer): Promise<MessageVerifier>;
}

export interface HmacInfo {
	readonly encryptThenMac?: boolean;
	readonly authenticatedEncryption?: boolean;
}

export interface Signer extends Disposable {
	readonly digestLength: number;
	sign(data: Buffer): Promise<Buffer>;
}

export interface MessageSigner extends Signer, HmacInfo {}

export interface Verifier extends Disposable {
	readonly digestLength: number;
	verify(data: Buffer, signature: Buffer): Promise<boolean>;
}

export interface MessageVerifier extends Verifier, HmacInfo {}
