#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const yargs = require('yargs');

const argv = yargs
	.option('input', {
		alias: 'i',
		describe: 'Directory containing JSON result files',
		type: 'string',
		demandOption: true,
	})
	.option('output', {
		alias: 'o',
		describe: 'Output file path for the markdown report',
		type: 'string',
		demandOption: true,
	})
	.help()
	.argv;

// Platform display names and order
const PLATFORMS = ['cs', 'ts', 'go'];
const PLATFORM_NAMES = { cs: 'C#', ts: 'TypeScript', go: 'Go' };

// Category display names and order
const CATEGORY_ORDER = [
	'algorithm-encryption',
	'algorithm-hmac',
	'algorithm-kex',
	'algorithm-keygen',
	'algorithm-signature',
	'protocol-serialization',
	'protocol-kex-cycle',
	'session-setup',
	'session-throughput',
	'session-multichannel',
	'e2e-portforward',
	'e2e-reconnect',
];

const CATEGORY_NAMES = {
	'algorithm-encryption': 'Algorithm: Encryption',
	'algorithm-hmac': 'Algorithm: HMAC',
	'algorithm-kex': 'Algorithm: Key Exchange',
	'algorithm-keygen': 'Algorithm: Key Generation',
	'algorithm-signature': 'Algorithm: Signature',
	'protocol-serialization': 'Protocol: Serialization',
	'protocol-kex-cycle': 'Protocol: KEX Cycle',
	'session-setup': 'Session: Setup',
	'session-throughput': 'Session: Throughput',
	'session-multichannel': 'Session: Multi-Channel',
	'e2e-portforward': 'E2E: Port Forwarding',
	'e2e-reconnect': 'E2E: Reconnect',
};

const CATEGORY_DESCRIPTIONS = {
	'algorithm-encryption':
		'Measures raw encrypt + decrypt round-trip time and throughput for symmetric ciphers, ' +
		'isolated from the SSH protocol. Each iteration encrypts then decrypts a single buffer.',
	'algorithm-hmac':
		'Measures HMAC sign + verify time for each MAC algorithm, isolated from the SSH protocol.',
	'algorithm-kex':
		'Measures the time for a single Diffie-Hellman or ECDH key exchange operation ' +
		'(one side only, not a full handshake).',
	'algorithm-keygen':
		'Measures key pair generation time for RSA and ECDSA at various key sizes.',
	'algorithm-signature':
		'Measures sign + verify time for RSA and ECDSA signature algorithms.',
	'protocol-serialization':
		'Measures the time to serialize and deserialize SSH protocol messages (round-trip).',
	'protocol-kex-cycle':
		'Measures a full key exchange cycle between two in-process sessions ' +
		'(both sides, including DH/ECDH computation and new-keys exchange).',
	'session-setup':
		'Measures the time to establish a full SSH session: version exchange, key exchange, ' +
		'authentication, and channel open. Broken down into sub-phases. ' +
		'"With latency" adds simulated 100ms round-trip network delay.',
	'session-throughput':
		'Measures message throughput over an established SSH session at various message sizes, ' +
		'with and without encryption enabled.',
	'session-multichannel':
		'Measures aggregate throughput when sending data concurrently over multiple SSH channels.',
	'e2e-portforward':
		'Measures real TCP port-forwarding performance through an SSH tunnel using each ' +
		"platform's PortForwardingService. Connect time measures the full path: " +
		'TCP connect → SSH channel open → TCP connect to target.',
	'e2e-reconnect':
		'Measures the time to reconnect an SSH session after the transport is interrupted, ' +
		'including new transport setup, key re-negotiation, and session state restoration.',
};

function mean(values) {
	if (values.length === 0) return 0;
	return values.reduce((sum, v) => sum + v, 0) / values.length;
}

function trimmedMean(values) {
	if (values.length <= 2) return mean(values);
	const sorted = [...values].sort((a, b) => a - b);
	const trimmed = sorted.slice(1, sorted.length - 1);
	return mean(trimmed);
}

function stddev(values) {
	if (values.length <= 1) return 0;
	const m = mean(values);
	const variance = values.reduce((sum, v) => sum + (v - m) ** 2, 0) / (values.length - 1);
	return Math.sqrt(variance);
}

function formatValue(value) {
	if (Math.abs(value) >= 1000) return value.toFixed(0);
	if (Math.abs(value) >= 100) return value.toFixed(1);
	if (Math.abs(value) >= 10) return value.toFixed(2);
	if (Math.abs(value) >= 1) return value.toFixed(3);
	return value.toPrecision(3);
}

function formatStat(m, sd, n) {
	return `${formatValue(m)} ± ${formatValue(sd)} (${n})`;
}

// Read all JSON result files from input directory
function readResultFiles(inputDir) {
	const files = fs.readdirSync(inputDir).filter((f) => f.endsWith('.json'));
	const results = [];
	for (const file of files) {
		const filePath = path.join(inputDir, file);
		const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
		results.push(data);
	}
	return results;
}

// Group suites by (category, tags) exact match across platforms.
function groupBenchmarks(results) {
	// Map<compositeKey, { category, tags, name, platforms: Map<platform, metrics[]> }>
	const groups = new Map();

	for (const result of results) {
		const platform = result.metadata.platform;

		for (const suite of result.suites) {
			const key = suite.category + '|' + JSON.stringify(suite.tags, Object.keys(suite.tags).sort());
			if (!groups.has(key)) {
				groups.set(key, {
					category: suite.category,
					tags: suite.tags,
					name: suite.name,
					platforms: new Map(),
				});
			}
			const group = groups.get(key);
			if (!group.platforms.has(platform)) {
				group.platforms.set(platform, suite.metrics);
			}
		}
	}

	return groups;
}

// Find the winner for a metric across platforms
function findWinner(platformValues, higherIsBetter) {
	let bestPlatform = null;
	let bestValue = null;

	for (const [platform, tm] of platformValues) {
		if (bestValue === null ||
			(higherIsBetter && tm > bestValue) ||
			(!higherIsBetter && tm < bestValue)) {
			bestValue = tm;
			bestPlatform = platform;
		}
	}

	return bestPlatform;
}

function generateReport(results) {
	const groups = groupBenchmarks(results);

	// Collect metadata for header
	const gitCommits = new Set();
	const runCounts = new Set();
	for (const result of results) {
		gitCommits.add(result.metadata.gitCommit);
		runCounts.add(result.metadata.runCount);
	}

	const lines = [];

	// Header
	lines.push('# Dev Tunnels SSH — Cross-Platform Benchmark Report');
	lines.push('');
	lines.push(`**Generated:** ${new Date().toISOString()}`);
	lines.push(`**Git Commit:** ${[...gitCommits].join(', ')}`);
	lines.push(`**Run Count:** ${[...runCounts].join(', ')}`);
	lines.push('');
	lines.push('Values shown as `trimmed mean ± stddev (n)`. **Bold** = best per metric. ↑ = higher is better, ↓ = lower is better.');
	lines.push('');

	// Organize groups by category
	const byCategory = new Map();
	for (const [, group] of groups) {
		if (!byCategory.has(group.category)) {
			byCategory.set(group.category, []);
		}
		byCategory.get(group.category).push(group);
	}

	// Output tables by category in order
	for (const category of CATEGORY_ORDER) {
		const categoryGroups = byCategory.get(category);
		if (!categoryGroups || categoryGroups.length === 0) continue;

		const displayName = CATEGORY_NAMES[category] || category;
		lines.push(`## ${displayName}`);
		lines.push('');
		const description = CATEGORY_DESCRIPTIONS[category];
		if (description) {
			lines.push(`> ${description}`);
			lines.push('');
		}

		// Collect all unique metric names across all groups in this category
		const metricNames = new Set();
		for (const group of categoryGroups) {
			for (const [, metrics] of group.platforms) {
				for (const metric of metrics) {
					metricNames.add(metric.name);
				}
			}
		}

		// For each metric, build a table
		for (const metricName of metricNames) {
			// Determine unit from first occurrence
			let unit = '';
			for (const group of categoryGroups) {
				for (const [, metrics] of group.platforms) {
					const m = metrics.find((m) => m.name === metricName);
					if (m) { unit = m.unit; break; }
				}
				if (unit) break;
			}

			// Determine higherIsBetter from first occurrence
			let higherIsBetter = false;
			for (const group of categoryGroups) {
				for (const [, metrics] of group.platforms) {
					const m = metrics.find((m) => m.name === metricName);
					if (m) { higherIsBetter = m.higherIsBetter; break; }
				}
				if (higherIsBetter !== false) break;
			}

			const metricLabel = unit ? `${metricName} (${unit})` : metricName;
			const directionArrow = higherIsBetter ? '↑' : '↓';
			const directionText = higherIsBetter ? 'higher is better' : 'lower is better';
			lines.push(`### ${metricLabel} ${directionArrow} ${directionText}`);
			lines.push('');

			// Table header
			const platformHeaders = PLATFORMS.map((p) => PLATFORM_NAMES[p]);
			lines.push(`| Benchmark | ${platformHeaders.join(' | ')} |`);
			lines.push(`| --- | ${PLATFORMS.map(() => '---').join(' | ')} |`);

			// Table rows
			for (const group of categoryGroups) {
				// Build a label from name or tags
				const label = group.name;

				// Collect trimmed means per platform for winner detection
				const platformTrimmedMeans = new Map();
				const platformCells = new Map();

				for (const platform of PLATFORMS) {
					const metrics = group.platforms.get(platform);
					if (!metrics) {
						platformCells.set(platform, 'N/A');
						continue;
					}
					const metric = metrics.find((m) => m.name === metricName);
					if (!metric) {
						platformCells.set(platform, 'N/A');
						continue;
					}
					const tm = trimmedMean(metric.values);
					const sd = stddev(metric.values);
					platformTrimmedMeans.set(platform, tm);
					platformCells.set(platform, formatStat(tm, sd, metric.values.length));
				}

				// Find winner
				const winner = platformTrimmedMeans.size > 1
					? findWinner(platformTrimmedMeans, higherIsBetter)
					: null;

				// Build row with winner highlighted
				const cells = PLATFORMS.map((p) => {
					const cell = platformCells.get(p);
					if (p === winner && cell !== 'N/A') {
						return `**${cell}**`;
					}
					return cell;
				});

				lines.push(`| ${label} | ${cells.join(' | ')} |`);
			}

			lines.push('');
		}
	}

	return lines.join('\n');
}

// Main
const inputDir = path.resolve(argv.input);
if (!fs.existsSync(inputDir)) {
	console.error(`Input directory does not exist: ${inputDir}`);
	process.exit(1);
}

const results = readResultFiles(inputDir);
if (results.length === 0) {
	console.error(`No JSON result files found in: ${inputDir}`);
	process.exit(1);
}

console.log(`Read ${results.length} result file(s) from ${inputDir}`);

const report = generateReport(results);
const outputPath = path.resolve(argv.output);
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, report, 'utf8');
console.log(`Report written to ${outputPath}`);
