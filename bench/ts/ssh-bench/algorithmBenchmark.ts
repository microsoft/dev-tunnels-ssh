//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Buffer } from 'buffer';
import {
	SshAlgorithms,
	EncryptionAlgorithm,
	HmacAlgorithm,
	KeyExchangeAlgorithm,
	PublicKeyAlgorithm,
	MessageSigner,
	MessageVerifier,
} from '@microsoft/dev-tunnels-ssh';
import { Benchmark } from './benchmark';

declare type hrtime = [number, number];
const millis = ([s, ns]: hrtime) => s * 1000 + ns / 1000000;

export class EncryptionBenchmark extends Benchmark {
	private static readonly EncryptDecryptTimeMeasurement = 'Encrypt+Decrypt time (ms)';
	private static readonly ThroughputMeasurement = 'Throughput (MB/s)';

	private readonly algorithm: EncryptionAlgorithm;
	private readonly payloadSize: number;

	public constructor(algorithm: EncryptionAlgorithm, payloadSize: number) {
		super(
			`Encryption ${algorithm.name} ${payloadSize}B`,
			'algorithm-encryption',
			{ algo: algorithm.name, size: payloadSize.toString() },
		);

		this.higherIsBetter.set(EncryptionBenchmark.EncryptDecryptTimeMeasurement, false);
		this.algorithm = algorithm;
		this.payloadSize = payloadSize;
	}

	public async run(): Promise<void> {
		const algorithm = this.algorithm;
		const key = Buffer.alloc(algorithm.keyLength);
		const encIv = Buffer.alloc(algorithm.blockLength);
		const decIv = Buffer.alloc(algorithm.blockLength);
		SshAlgorithms.random.getBytes(key);
		SshAlgorithms.random.getBytes(encIv);
		encIv.copy(decIv);

		// Round payload to block length
		const blockLen = algorithm.blockLength;
		let alignedSize = Math.floor(this.payloadSize / blockLen) * blockLen;
		if (alignedSize < blockLen) alignedSize = blockLen;

		const plaintext = Buffer.alloc(alignedSize);
		SshAlgorithms.random.getBytes(plaintext);

		const encCipher = await algorithm.createCipher(true, key, encIv);
		const decCipher = await algorithm.createCipher(false, key, decIv);

		const startTime: hrtime = process.hrtime();

		const ciphertext = await encCipher.transform(plaintext);

		// For GCM, copy auth tag from encryptor to decryptor
		if ('sign' in encCipher && 'verify' in decCipher) {
			const signer = encCipher as unknown as MessageSigner;
			const verifier = decCipher as unknown as MessageVerifier;
			const tag = await signer.sign(Buffer.alloc(0));
			await verifier.verify(Buffer.alloc(0), tag);
		}

		await decCipher.transform(ciphertext);

		const elapsed: hrtime = process.hrtime(startTime);

		const ms = millis(elapsed);
		this.addMeasurement(EncryptionBenchmark.EncryptDecryptTimeMeasurement, ms);

		// Skip throughput for small payloads — sub-millisecond operations produce
		// wildly noisy MB/s values due to timer resolution limits.
		if (alignedSize >= 4096) {
			const megabytes = alignedSize / (1024 * 1024);
			const seconds = ms / 1000;
			this.addMeasurement(
				EncryptionBenchmark.ThroughputMeasurement,
				seconds > 0 ? megabytes / seconds : 0,
			);
		}

		encCipher.dispose();
		decCipher.dispose();
	}

	public async verify(): Promise<void> {
		const algorithm = this.algorithm;
		const key = Buffer.alloc(algorithm.keyLength);
		const encIv = Buffer.alloc(algorithm.blockLength);
		const decIv = Buffer.alloc(algorithm.blockLength);
		SshAlgorithms.random.getBytes(key);
		SshAlgorithms.random.getBytes(encIv);
		encIv.copy(decIv);

		const blockLen = algorithm.blockLength;
		let alignedSize = Math.floor(this.payloadSize / blockLen) * blockLen;
		if (alignedSize < blockLen) alignedSize = blockLen;

		const plaintext = Buffer.alloc(alignedSize);
		SshAlgorithms.random.getBytes(plaintext);
		const original = Buffer.from(plaintext);

		const encCipher = await algorithm.createCipher(true, key, encIv);
		const decCipher = await algorithm.createCipher(false, key, decIv);

		const ciphertext = await encCipher.transform(plaintext);

		// For GCM, copy auth tag from encryptor to decryptor
		if ('sign' in encCipher && 'verify' in decCipher) {
			const signer = encCipher as unknown as MessageSigner;
			const verifier = decCipher as unknown as MessageVerifier;
			const tag = await signer.sign(Buffer.alloc(0));
			await verifier.verify(Buffer.alloc(0), tag);
		}

		// Verify ciphertext differs from plaintext
		if (ciphertext.equals(original)) {
			throw new Error('Ciphertext should differ from plaintext');
		}

		const decrypted = await decCipher.transform(ciphertext);

		// Verify decrypted matches original
		if (!decrypted.equals(original)) {
			throw new Error('Decrypted data does not match original plaintext');
		}

		encCipher.dispose();
		decCipher.dispose();
	}

	public async dispose(): Promise<void> {}
}

export class HmacBenchmark extends Benchmark {
	private static readonly SignVerifyTimeMeasurement = 'Sign+Verify time (ms)';

	private readonly algorithm: HmacAlgorithm;

	public constructor(algorithm: HmacAlgorithm) {
		super(
			`HMAC ${algorithm.name}`,
			'algorithm-hmac',
			{ algo: algorithm.name },
		);

		this.higherIsBetter.set(HmacBenchmark.SignVerifyTimeMeasurement, false);
		this.algorithm = algorithm;
	}

	public async run(): Promise<void> {
		const algorithm = this.algorithm;
		const key = Buffer.alloc(algorithm.keyLength);
		SshAlgorithms.random.getBytes(key);

		const signer = await algorithm.createSigner(key);
		const verifier = await algorithm.createVerifier(key);

		const data = Buffer.alloc(256);
		SshAlgorithms.random.getBytes(data);

		const startTime: hrtime = process.hrtime();

		const signature = await signer.sign(data);
		await verifier.verify(data, signature);

		const elapsed: hrtime = process.hrtime(startTime);

		this.addMeasurement(HmacBenchmark.SignVerifyTimeMeasurement, millis(elapsed));

		signer.dispose();
		verifier.dispose();
	}

	public async verify(): Promise<void> {
		const algorithm = this.algorithm;
		const key = Buffer.alloc(algorithm.keyLength);
		SshAlgorithms.random.getBytes(key);

		const signer = await algorithm.createSigner(key);
		const verifier = await algorithm.createVerifier(key);

		const data = Buffer.alloc(256);
		SshAlgorithms.random.getBytes(data);

		// Sign and verify should succeed
		const signature = await signer.sign(data);
		const valid = await verifier.verify(data, signature);
		if (!valid) {
			throw new Error('HMAC verification failed for valid data');
		}

		// Tampered data should fail verification
		const tampered = Buffer.from(data);
		tampered[0] ^= 0xff;
		const verifier2 = await algorithm.createVerifier(key);
		const invalid = await verifier2.verify(tampered, signature);
		if (invalid) {
			throw new Error('HMAC verification should have failed for tampered data');
		}

		signer.dispose();
		verifier.dispose();
		verifier2.dispose();
	}

	public async dispose(): Promise<void> {}
}

export class KeyExchangeBenchmark extends Benchmark {
	private static readonly KexTimeMeasurement = 'Key exchange time (ms)';

	private readonly algorithm: KeyExchangeAlgorithm;

	public constructor(algorithm: KeyExchangeAlgorithm) {
		super(
			`KEX ${algorithm.name}`,
			'algorithm-kex',
			{ algo: algorithm.name },
		);

		this.higherIsBetter.set(KeyExchangeBenchmark.KexTimeMeasurement, false);
		this.algorithm = algorithm;
	}

	public async run(): Promise<void> {
		const clientKex = this.algorithm.createKeyExchange();
		const serverKex = this.algorithm.createKeyExchange();

		const startTime: hrtime = process.hrtime();

		const clientPublic = await clientKex.startKeyExchange();
		const serverPublic = await serverKex.startKeyExchange();
		await clientKex.decryptKeyExchange(serverPublic);
		await serverKex.decryptKeyExchange(clientPublic);

		const elapsed: hrtime = process.hrtime(startTime);

		this.addMeasurement(KeyExchangeBenchmark.KexTimeMeasurement, millis(elapsed));

		clientKex.dispose();
		serverKex.dispose();
	}

	public async verify(): Promise<void> {
		const clientKex = this.algorithm.createKeyExchange();
		const serverKex = this.algorithm.createKeyExchange();

		const clientPublic = await clientKex.startKeyExchange();
		const serverPublic = await serverKex.startKeyExchange();

		const clientSecret = await clientKex.decryptKeyExchange(serverPublic);
		const serverSecret = await serverKex.decryptKeyExchange(clientPublic);

		// Both sides should derive the same shared secret
		if (!clientSecret.equals(serverSecret)) {
			throw new Error('Key exchange shared secrets do not match');
		}

		// Shared secret should not be empty
		if (clientSecret.length === 0) {
			throw new Error('Key exchange shared secret is empty');
		}

		clientKex.dispose();
		serverKex.dispose();
	}

	public async dispose(): Promise<void> {}
}

export class KeygenBenchmark extends Benchmark {
	private static readonly KeygenTimeMeasurement = 'Keygen time (ms)';

	private readonly algorithm: PublicKeyAlgorithm;
	private readonly keySizeInBits: number;

	public constructor(algorithm: PublicKeyAlgorithm, keySizeInBits: number) {
		super(
			`Keygen ${algorithm.keyAlgorithmName} ${keySizeInBits}`,
			'algorithm-keygen',
			{ algo: algorithm.keyAlgorithmName, size: keySizeInBits.toString() },
		);

		this.higherIsBetter.set(KeygenBenchmark.KeygenTimeMeasurement, false);
		this.algorithm = algorithm;
		this.keySizeInBits = keySizeInBits;
	}

	public async run(): Promise<void> {
		const startTime: hrtime = process.hrtime();

		const keyPair = await this.algorithm.generateKeyPair(this.keySizeInBits);

		const elapsed: hrtime = process.hrtime(startTime);

		this.addMeasurement(KeygenBenchmark.KeygenTimeMeasurement, millis(elapsed));

		keyPair.dispose();
	}

	public async verify(): Promise<void> {
		const keyPair = await this.algorithm.generateKeyPair(this.keySizeInBits);

		// Verify the generated key has the expected bit size.
		await verifyKeySize(keyPair, this.keySizeInBits, this.algorithm.keyAlgorithmName);

		// Sign test data and verify the signature
		const signer = this.algorithm.createSigner(keyPair);
		const verifier = this.algorithm.createVerifier(keyPair);

		const data = Buffer.alloc(64);
		SshAlgorithms.random.getBytes(data);

		const signature = await signer.sign(data);
		const valid = await verifier.verify(data, signature);
		if (!valid) {
			throw new Error('Keygen: signature verification failed for generated key');
		}

		signer.dispose();
		verifier.dispose();
		keyPair.dispose();
	}

	public async dispose(): Promise<void> {}
}

export class SignatureBenchmark extends Benchmark {
	private static readonly SignVerifyTimeMeasurement = 'Sign+Verify time (ms)';

	private readonly algorithm: PublicKeyAlgorithm;
	private readonly keySizeInBits: number;

	public constructor(algorithm: PublicKeyAlgorithm, keySizeInBits: number) {
		super(
			`Signature ${algorithm.name} ${keySizeInBits}`,
			'algorithm-signature',
			{ algo: algorithm.name, size: keySizeInBits.toString() },
		);

		this.higherIsBetter.set(SignatureBenchmark.SignVerifyTimeMeasurement, false);
		this.algorithm = algorithm;
		this.keySizeInBits = keySizeInBits;
	}

	public async run(): Promise<void> {
		const keyPair = await this.algorithm.generateKeyPair(this.keySizeInBits);
		const signer = this.algorithm.createSigner(keyPair);
		const verifier = this.algorithm.createVerifier(keyPair);

		const data = Buffer.alloc(256);
		SshAlgorithms.random.getBytes(data);

		const startTime: hrtime = process.hrtime();

		const signature = await signer.sign(data);
		await verifier.verify(data, signature);

		const elapsed: hrtime = process.hrtime(startTime);

		this.addMeasurement(SignatureBenchmark.SignVerifyTimeMeasurement, millis(elapsed));

		signer.dispose();
		verifier.dispose();
		keyPair.dispose();
	}

	public async verify(): Promise<void> {
		const keyPair = await this.algorithm.generateKeyPair(this.keySizeInBits);

		// Verify the generated key has the expected bit size.
		await verifyKeySize(keyPair, this.keySizeInBits, this.algorithm.keyAlgorithmName);

		const signer = this.algorithm.createSigner(keyPair);
		const verifier = this.algorithm.createVerifier(keyPair);

		const data = Buffer.alloc(256);
		SshAlgorithms.random.getBytes(data);

		// Sign and verify should succeed
		const signature = await signer.sign(data);
		const valid = await verifier.verify(data, signature);
		if (!valid) {
			throw new Error('Signature verification failed for valid data');
		}

		// Verify with wrong data should fail
		const wrongData = Buffer.alloc(256);
		SshAlgorithms.random.getBytes(wrongData);
		const verifier2 = this.algorithm.createVerifier(keyPair);
		const invalid = await verifier2.verify(wrongData, signature);
		if (invalid) {
			throw new Error('Signature verification should have failed for wrong data');
		}

		signer.dispose();
		verifier.dispose();
		verifier2.dispose();
		keyPair.dispose();
	}

	public async dispose(): Promise<void> {}
}

/**
 * Verifies that a generated key pair has the expected bit size by checking
 * the SSH public key byte length. For RSA, the modulus is the dominant
 * component, so the total byte count is a reliable proxy for key size.
 */
async function verifyKeySize(
	keyPair: import('@microsoft/dev-tunnels-ssh').KeyPair,
	expectedSizeInBits: number,
	keyAlgorithmName: string,
): Promise<void> {
	const pubKeyBytes = await keyPair.getPublicKeyBytes();
	if (!pubKeyBytes) {
		throw new Error('Failed to get public key bytes for key size verification');
	}

	if (keyAlgorithmName === 'ssh-rsa') {
		// RSA public key SSH wire format: [string "ssh-rsa"] [mpint e] [mpint n]
		// Expected total: ~11 (algo) + ~7 (exponent) + 5 (mpint header) + keySizeInBits/8.
		const expectedModulusBytes = expectedSizeInBits / 8;
		const minExpectedLength = expectedModulusBytes + 10;
		const maxExpectedLength = expectedModulusBytes + 25;

		if (pubKeyBytes.length < minExpectedLength || pubKeyBytes.length > maxExpectedLength) {
			throw new Error(
				`Expected ${expectedSizeInBits}-bit RSA key (pub key ~${minExpectedLength}-${maxExpectedLength} bytes), ` +
				`but got ${pubKeyBytes.length} bytes. Key size mismatch.`,
			);
		}
	} else if (keyAlgorithmName.startsWith('ecdsa-sha2-')) {
		// ECDSA public key SSH wire format: [string algo] [string curve] [string Q]
		// Q is uncompressed: 0x04 || X || Y, so Q length = 1 + 2*ceil(bits/8).
		const coordBytes = Math.ceil(expectedSizeInBits / 8);
		const expectedQLen = 1 + 2 * coordBytes;
		const curveName = keyAlgorithmName.substring('ecdsa-sha2-'.length);
		const expectedTotal = (4 + keyAlgorithmName.length) + (4 + curveName.length) + (4 + expectedQLen);
		// Allow small tolerance for encoding variations.
		if (pubKeyBytes.length < expectedTotal - 2 || pubKeyBytes.length > expectedTotal + 2) {
			throw new Error(
				`Expected ${expectedSizeInBits}-bit ECDSA key (pub key ~${expectedTotal} bytes), ` +
				`but got ${pubKeyBytes.length} bytes. Key size mismatch.`,
			);
		}
	}
}
