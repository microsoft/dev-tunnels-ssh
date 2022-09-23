//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as yargs from 'yargs';
import { Benchmark } from './benchmark';
import { SessionSetupBenchmark } from './sessionSetupBenchmark';
import { ThroughputBenchmark } from './throughputBenchmark';
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

	var t = 1000;

	var benchmarks = new Map<string, () => Benchmark>();

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

	for (let [benchmarkName, benchmarkFunc] of benchmarks.entries()) {
		if (nameList && !nameList.includes(benchmarkName)) {
			continue;
		}

		const benchmark = await benchmarkFunc();

		benchmark.reportTitle();

		for (let i = 0; i < runCount; i++) {
			await new Promise((c) => setTimeout(c, 100));
			await benchmark.run();
			process.stdout.write('.');
		}

		benchmark.reportResults();
		await benchmark.dispose();
	}

	return 0;
}
