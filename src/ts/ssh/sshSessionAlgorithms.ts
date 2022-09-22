//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Disposable } from 'vscode-jsonrpc';
import {
	Cipher,
	Signer,
	Verifier,
	MessageSigner,
	MessageVerifier,
	CompressionAlgorithm,
} from './algorithms/sshAlgorithms';

export class SshSessionAlgorithms implements Disposable {
	public publicKeyAlgorithmName?: string;
	public cipher?: Cipher | null;
	public decipher?: Cipher | null;
	public signer?: Signer | null;
	public verifier?: Verifier | null;
	public messageSigner?: MessageSigner | null;
	public messageVerifier?: MessageVerifier | null;
	public compressor?: CompressionAlgorithm | null;
	public decompressor?: CompressionAlgorithm | null;

	public dispose(): void {
		if (this.cipher) this.cipher.dispose();
		if (this.decipher) this.decipher.dispose();
		if (this.signer) this.signer.dispose();
		if (this.verifier) this.verifier.dispose();
	}
}
