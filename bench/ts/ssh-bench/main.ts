//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as yargs from 'yargs';
import { Benchmark } from './benchmark';
import { SessionSetupBenchmark } from './sessionSetupBenchmark';
import { ThroughputBenchmark } from './throughputBenchmark';
import { PortForwardBenchmark } from './portForwardBenchmark';
import {
	EncryptionBenchmark,
	HmacBenchmark,
	KeyExchangeBenchmark,
	KeygenBenchmark,
	SignatureBenchmark,
} from './algorithmBenchmark';
import {
	ChannelDataSerializationBenchmark,
	ChannelOpenSerializationBenchmark,
	KeyExchangeInitSerializationBenchmark,
	KexCycleBenchmark,
} from './messageBenchmark';
import { JsonResultWriter } from './jsonResultWriter';
import { SshAlgorithms } from '@microsoft/dev-tunnels-ssh';
import 'source-map-support/register';

main()
	.then((exitCode) => process.exit(exitCode))
	.catch((e) => {
		console.error(e);
		process.exit(1);
	});

function usage(errorMessage?: string): number {
	if (errorMessage) {
		console.error(errorMessage);
		console.error('');
	}

	console.error('Usage: node bench.js');
	return 2;
}

async function main(): Promise<number> {
	const argv = await yargs.argv;
	let nameList: string[] | null = null;
	let runCount = 7;
	let jsonPath: string | null = null;

	// Parse --json=<path> from argv
	if (typeof argv.json === 'string') {
		jsonPath = argv.json;
	}

	for (let arg of <string[]>argv._) {
		try {
			const runCountArg = parseInt(arg);
			if (runCountArg > 0) {
				runCount = runCountArg;
				continue;
			}
		} catch (e) {}

		if (!nameList) {
			nameList = [];
		}
		nameList.push(arg);
	}

	const jsonWriter = jsonPath ? new JsonResultWriter() : null;

	var t = 1000;

	var benchmarks = new Map<string, () => Benchmark>();

	// Algorithm benchmarks - Encryption
	benchmarks.set('encryption-aes256gcm-1024', () =>
		new EncryptionBenchmark(SshAlgorithms.encryption.aes256Gcm!, 1024));
	benchmarks.set('encryption-aes256gcm-32768', () =>
		new EncryptionBenchmark(SshAlgorithms.encryption.aes256Gcm!, 32768));
	benchmarks.set('encryption-aes256gcm-65536', () =>
		new EncryptionBenchmark(SshAlgorithms.encryption.aes256Gcm!, 65536));
	benchmarks.set('encryption-aes256ctr-32768', () =>
		new EncryptionBenchmark(SshAlgorithms.encryption.aes256Ctr!, 32768));

	// Algorithm benchmarks - HMAC
	benchmarks.set('hmac-sha256', () =>
		new HmacBenchmark(SshAlgorithms.hmac.hmacSha256!));
	benchmarks.set('hmac-sha512', () =>
		new HmacBenchmark(SshAlgorithms.hmac.hmacSha512!));
	benchmarks.set('hmac-sha256-etm', () =>
		new HmacBenchmark(SshAlgorithms.hmac.hmacSha256Etm!));
	benchmarks.set('hmac-sha512-etm', () =>
		new HmacBenchmark(SshAlgorithms.hmac.hmacSha512Etm!));

	// Algorithm benchmarks - Key Exchange
	benchmarks.set('kex-ecdh-p256', () =>
		new KeyExchangeBenchmark(SshAlgorithms.keyExchange.ecdhNistp256Sha256!));
	benchmarks.set('kex-ecdh-p384', () =>
		new KeyExchangeBenchmark(SshAlgorithms.keyExchange.ecdhNistp384Sha384!));
	benchmarks.set('kex-ecdh-p521', () =>
		new KeyExchangeBenchmark(SshAlgorithms.keyExchange.ecdhNistp521Sha512!));
	benchmarks.set('kex-dh-group14', () =>
		new KeyExchangeBenchmark(SshAlgorithms.keyExchange.dhGroup14Sha256!));
	benchmarks.set('kex-dh-group16', () =>
		new KeyExchangeBenchmark(SshAlgorithms.keyExchange.dhGroup16Sha512!));

	// Algorithm benchmarks - Key Generation
	benchmarks.set('keygen-rsa-2048', () =>
		new KeygenBenchmark(SshAlgorithms.publicKey.rsaWithSha256!, 2048));
	benchmarks.set('keygen-rsa-4096', () =>
		new KeygenBenchmark(SshAlgorithms.publicKey.rsaWithSha256!, 4096));
	benchmarks.set('keygen-ecdsa-p256', () =>
		new KeygenBenchmark(SshAlgorithms.publicKey.ecdsaSha2Nistp256!, 256));
	benchmarks.set('keygen-ecdsa-p384', () =>
		new KeygenBenchmark(SshAlgorithms.publicKey.ecdsaSha2Nistp384!, 384));
	benchmarks.set('keygen-ecdsa-p521', () =>
		new KeygenBenchmark(SshAlgorithms.publicKey.ecdsaSha2Nistp521!, 521));

	// Algorithm benchmarks - Signatures
	benchmarks.set('sig-rsa-sha256', () =>
		new SignatureBenchmark(SshAlgorithms.publicKey.rsaWithSha256!, 2048));
	benchmarks.set('sig-rsa-sha512', () =>
		new SignatureBenchmark(SshAlgorithms.publicKey.rsaWithSha512!, 2048));
	benchmarks.set('sig-ecdsa-p256', () =>
		new SignatureBenchmark(SshAlgorithms.publicKey.ecdsaSha2Nistp256!, 256));
	benchmarks.set('sig-ecdsa-p384', () =>
		new SignatureBenchmark(SshAlgorithms.publicKey.ecdsaSha2Nistp384!, 384));
	benchmarks.set('sig-ecdsa-p521', () =>
		new SignatureBenchmark(SshAlgorithms.publicKey.ecdsaSha2Nistp521!, 521));

	// Protocol benchmarks - Serialization
	benchmarks.set('serialize-channel-data', () =>
		new ChannelDataSerializationBenchmark());
	benchmarks.set('serialize-channel-open', () =>
		new ChannelOpenSerializationBenchmark());
	benchmarks.set('serialize-kex-init', () =>
		new KeyExchangeInitSerializationBenchmark());

	// Protocol benchmarks - KEX Cycle
	benchmarks.set('kex-cycle-ecdh-p384', () =>
		new KexCycleBenchmark());

	// Session benchmarks
	benchmarks.set('session', () => new SessionSetupBenchmark(false));
	benchmarks.set('session-with-latency', () => new SessionSetupBenchmark(true));
	benchmarks.set('encrypted-10', () => new ThroughputBenchmark(t, 10, true));
	benchmarks.set('encrypted-200', () => new ThroughputBenchmark(t, 200, true));
	benchmarks.set('encrypted-50000', () => new ThroughputBenchmark(t, 50000, true));
	benchmarks.set('encrypted-1000000', () => new ThroughputBenchmark(t, 1000000, true));
	benchmarks.set('unencrypted-10', () => new ThroughputBenchmark(t, 10, false));
	benchmarks.set('unencrypted-200', () => new ThroughputBenchmark(t, 200, false));
	benchmarks.set('unencrypted-50000', () => new ThroughputBenchmark(t, 50000, false));
	benchmarks.set('unencrypted-1000000', () => new ThroughputBenchmark(t, 1000000, false));
	benchmarks.set('portforward-ipv4', () => new PortForwardBenchmark('127.0.0.1', '127.0.0.1'));
	benchmarks.set(
		'portforward-ipv4-localhost',
		() => new PortForwardBenchmark('127.0.0.1', 'localhost'),
	);
	benchmarks.set('portforward-ipv6', () => new PortForwardBenchmark('::1', '::1'));
	benchmarks.set('portforward-ipv6-localhost', () => new PortForwardBenchmark('::1', 'localhost'));

	for (let [benchmarkName, benchmarkFunc] of benchmarks.entries()) {
		if (nameList && !nameList.includes(benchmarkName)) {
			continue;
		}

		try {
			const benchmark = await benchmarkFunc();

			benchmark.reportTitle();

			// Warmup run (not recorded).
			try { await benchmark.run(); } catch {}
			benchmark.measurements.clear();

			for (let i = 0; i < runCount; i++) {
				await new Promise((c) => setTimeout(c, 100));
				try {
					await benchmark.run();
					process.stdout.write('.');
				} catch (e: any) {
					console.error(
						`\nRun ${i + 1} of '${benchmarkName}' failed: ${e.message || e}`);
				}
			}

			benchmark.reportResults();
			jsonWriter?.addBenchmark(benchmark);
			await benchmark.dispose();
		} catch (e: any) {
			console.error(`\nBenchmark '${benchmarkName}' failed: ${e.message || e}`);
		}
	}

	if (jsonWriter && jsonPath) {
		jsonWriter.write(jsonPath, runCount);
		console.log(`JSON results written to ${jsonPath}`);
	}

	return 0;
}
