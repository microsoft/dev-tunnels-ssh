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

	public async dispose(): Promise<void> {}
}
