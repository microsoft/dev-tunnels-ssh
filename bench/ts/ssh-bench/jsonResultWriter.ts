//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execSync } from 'child_process';
import { Benchmark } from './benchmark';

interface MetricResult {
	name: string;
	unit: string;
	values: number[];
	higherIsBetter: boolean;
}

interface VerificationResult {
	passed: boolean;
	error?: string;
}

interface SuiteResult {
	category: string;
	name: string;
	tags: Record<string, string>;
	metrics: MetricResult[];
	verification?: VerificationResult;
}

interface MetadataResult {
	platform: string;
	platformVersion: string;
	os: string;
	timestamp: string;
	runCount: number;
	gitCommit: string;
}

interface ResultFile {
	metadata: MetadataResult;
	suites: SuiteResult[];
}

export class JsonResultWriter {
	private readonly suites: SuiteResult[] = [];

	public addBenchmark(benchmark: Benchmark, verificationResult?: VerificationResult): void {
		const metrics: MetricResult[] = [];

		for (const [name, values] of benchmark.measurements.entries()) {
			// Extract unit from measurement name, e.g. "Connect time (ms)" → name="Connect time", unit="ms"
			let unit = '';
			let metricName = name;
			const parenStart = name.lastIndexOf('(');
			const parenEnd = name.lastIndexOf(')');
			if (parenStart >= 0 && parenEnd > parenStart) {
				unit = name.substring(parenStart + 1, parenEnd);
				metricName = name.substring(0, parenStart).trimEnd();
			}

			const higherIsBetter = benchmark.higherIsBetter.has(name)
				? benchmark.higherIsBetter.get(name)!
				: true;

			metrics.push({
				name: metricName,
				unit,
				values: values.map((v) => Math.round(v * 1000000) / 1000000),
				higherIsBetter,
			});
		}

		const suiteResult: SuiteResult = {
			category: benchmark.category,
			name: benchmark.title,
			tags: { ...benchmark.tags },
			metrics,
		};
		if (verificationResult) {
			suiteResult.verification = verificationResult;
		}
		this.suites.push(suiteResult);
	}

	public write(filePath: string, runCount: number): void {
		const result: ResultFile = {
			metadata: {
				platform: 'ts',
				platformVersion: `Node.js ${process.version}`,
				os: `${process.platform}-${process.arch}`,
				timestamp: new Date().toISOString(),
				runCount,
				gitCommit: JsonResultWriter.getGitCommit(),
			},
			suites: this.suites,
		};

		const dir = path.dirname(filePath);
		if (dir) {
			fs.mkdirSync(dir, { recursive: true });
		}

		fs.writeFileSync(filePath, JSON.stringify(result, null, 2));
	}

	private static getGitCommit(): string {
		try {
			return execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
		} catch {
			return 'unknown';
		}
	}
}
