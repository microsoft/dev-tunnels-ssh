//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import chalk from 'chalk';

export abstract class Benchmark {
	public readonly measurements = new Map<string, number[]>();
	public readonly higherIsBetter = new Map<string, boolean>();

	protected constructor(public readonly title: string) {}

	protected addMeasurement(measurement: string, value: number): void {
		let list = this.measurements.get(measurement);
		if (!list) {
			list = [];
			this.measurements.set(measurement, list);
		}

		list.push(value);
	}

	public reportTitle(): void {
		process.stdout.write(chalk.yellow('# ' + this.title) + ' ');
	}

	public reportResults(): void {
		process.stdout.write('\n');

		for (let [measurement, measurements] of this.measurements.entries()) {
			const higherIsBetter = this.higherIsBetter.has(measurement)
				? this.higherIsBetter.get(measurement)
				: true;

			const min = Math.min(...measurements);
			const minIndex = measurements.indexOf(min);
			const max = Math.max(...measurements);
			const maxIndex = measurements.indexOf(max);
			const refinedMeasurements = measurements.filter((m, i) => i != minIndex && i != maxIndex);
			const allEqual = min == max;

			process.stdout.write(measurement.padEnd(24));
			for (let value of measurements) {
				if (!allEqual && value === (higherIsBetter ? min : max)) {
					process.stdout.write(' ' + chalk.red(value.toFixed(2).padStart(8)));
				} else if (!allEqual && value === (higherIsBetter ? max : min)) {
					process.stdout.write(' ' + chalk.green(value.toFixed(2).padStart(8)));
				} else {
					process.stdout.write(' ' + value.toFixed(2).padStart(8));
				}
			}

			if (refinedMeasurements.length > 0) {
				const average =
					refinedMeasurements.reduce((p, c) => p + c, 0) / refinedMeasurements.length;
				process.stdout.write(chalk.blue('     Average: ' + average.toFixed(2).padStart(8)));
			}

			process.stdout.write('\n');
		}

		process.stdout.write('\n');
	}

	protected static findAvailablePort(): number {
		// TODO: Use that node module...
		return 9876;
	}

	public abstract run(): Promise<void>;

	public abstract dispose(): Promise<void>;
}
