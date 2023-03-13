//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import { SshDataWriter, SshDataReader } from '../io/sshData';
import { SshAlgorithm } from './sshAlgorithm';
import { Signer, Verifier } from './hmacAlgorithm';
import { Disposable, CancellationToken } from 'vscode-jsonrpc';
import { BigInt } from '../io/bigInt';

export abstract class PublicKeyAlgorithm implements SshAlgorithm {
	protected constructor(
		public readonly name: string,
		public readonly keyAlgorithmName: string,
		public readonly hashAlgorithmName: string,
	) {}

	public abstract createKeyPair(): KeyPair;
	public abstract generateKeyPair(keySizeInBits?: number): Promise<KeyPair>;
	public abstract createSigner(keyPair: KeyPair): Signer;
	public abstract createVerifier(keyPair: KeyPair): Verifier;

	public readSignatureData(signatureData: Buffer): Buffer {
		const reader = new SshDataReader(signatureData);
		const algorithmName = reader.readString('ascii');
		if (algorithmName !== this.name) {
			throw new Error(
				'Mismatched public key algorithm: ' +
					`got '${algorithmName}', expected '${this.name}'.`,
			);
		}

		const signature = reader.readBinary();
		return signature;
	}

	public createSignatureData(signature: Buffer): Buffer {
		const writer = new SshDataWriter(Buffer.alloc(this.name.length + signature.length + 20));
		writer.writeString(this.name, 'ascii');
		writer.writeBinary(signature);
		return writer.toBuffer();
	}
}

export interface KeyPair extends Disposable {
	readonly keyAlgorithmName: string;
	readonly hasPublicKey: boolean;
	readonly hasPrivateKey: boolean;
	comment: string | null;
	setPublicKeyBytes(keyBytes: Buffer): Promise<void>;
	getPublicKeyBytes(algorithmName?: string): Promise<Buffer | null>;
	generate(): Promise<void>;
	importParameters(parameters: KeyPairParameters): Promise<void>;
	exportParameters(): Promise<KeyPairParameters>;
}

// eslint-disable-next-line @typescript-eslint/no-empty-interface
interface KeyPairParameters {}

export interface RsaParameters extends KeyPairParameters {
	modulus: BigInt;
	exponent: BigInt;
	d?: BigInt;
	p?: BigInt;
	q?: BigInt;
	dp?: BigInt;
	dq?: BigInt;
	qi?: BigInt;
}

export interface ECParameters extends KeyPairParameters {
	curve: { name?: string; oid?: string };
	x: BigInt;
	y: BigInt;
	d?: BigInt;
}

/**
 * Given a public key, provides the corresponding private key.
 */
export type PrivateKeyProvider = (
	publicKey: KeyPair,
	cancellation: CancellationToken,
) => Promise<KeyPair | null>;
