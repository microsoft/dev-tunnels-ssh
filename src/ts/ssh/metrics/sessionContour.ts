//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { CancellationToken, Disposable } from 'vscode-jsonrpc';
import { ObjectDisposedError } from '../errors';
import { Queue } from '../util/queue';
import { Semaphore } from '../util/semaphore';
import { SessionMetrics } from './sessionMetrics';

interface ContourUpdate {
	readonly time: number;
	readonly bytesSent?: number;
	readonly bytesReceived?: number;
	readonly latency?: number;
}

/**
 * Collects session metrics over time, producing an outline of the timing, speed,
 * and quantity of bytes sent/received during the session.
 *
 * Metrics are recorded across a number of equal time intervals. As the session time
 * increases, intervals are expanded to keep the number of intervals under the configured
 * maximum. Each expansion doubles the length of all intervals, while combining the metrics
 * within each pair of combined intervals. Therefore, a longer session has longer intervals
 * and less-granular metrics. In this way, the memory usage (and serialized size) of the
 * session contour remains roughly constant regardless of the length of the session.
 *
 * Metrics exposed via the collection properties on this class may be momentarily
 * inconsistent (but will not throw exceptions) if continued session operation causes
 * intervals to be expanded while the data is being read concurrently. To avoid any
 * inconsistency, hold a lock on the <see cref="SessionContour" /> instance while reading
 * data. (Or wait until the session ends.)
 *
 * A session contour can be exported in a compact form suitable for logging or telemetry.
 * Use the code in `SessionContour.kql` to chart a session contour in Azure Data Explorer.
 */
export class SessionContour implements Disposable {
	private static readonly initialInterval = 1000; // 1 second (in milliseconds)

	/** Current size of the metrics interval, in milliseconds. */
	private intervalMs = SessionContour.initialInterval;

	/** Number of intervals for which metrics have been recorded. */
	private count = 0;

	// Each of these arrays holds one metric per interval.
	private readonly intervalBytesSent: number[];
	private readonly intervalBytesReceived: number[];
	private readonly intervalLatencyMin: number[];
	private readonly intervalLatencyMax: number[];
	private readonly intervalLatencySum: number[];
	private readonly intervalLatencyCount: number[];
	private readonly intervalLatencyAvg: number[];

	private readonly updateQueue = new Queue<ContourUpdate>();
	private readonly updateSemaphore = new Semaphore(0);

	private disposed = false;

	/**
	 * Creates a new instance of the `SessionContour` class.
	 *
	 * @param maxIntervals Maximum number of metric intervals to record,
	 * defaults to 256. Must be a power of two.
	 */
	public constructor(maxIntervals = 256) {
		if (maxIntervals < 2 || (maxIntervals & (maxIntervals - 1)) !== 0) {
			throw new Error('Contour intervals must be a power of two.');
		}

		this.maxIntervals = maxIntervals;
		this.intervalBytesSent = new Array<number>(maxIntervals);
		this.intervalBytesReceived = new Array<number>(maxIntervals);
		this.intervalLatencyMin = new Array<number>(maxIntervals);
		this.intervalLatencyMax = new Array<number>(maxIntervals);
		this.intervalLatencySum = new Array<number>(maxIntervals);
		this.intervalLatencyCount = new Array<number>(maxIntervals);
		this.intervalLatencyAvg = new Array<number>(maxIntervals);

		this.intervalBytesSent.fill(0);
		this.intervalBytesReceived.fill(0);
		this.intervalLatencyMin.fill(0);
		this.intervalLatencyMax.fill(0);
		this.intervalLatencySum.fill(0);
		this.intervalLatencyCount.fill(0);
		this.intervalLatencyAvg.fill(0);
	}

	/**
	 * Gets the maximum number of intervals that can be recorded in this contour. Intervals
	 * are expanded as necesary such that the entire duration of the session is always covered
	 * by fewer intervals than this limit.
	 */
	public readonly maxIntervals: number;

	/**
	 * Gets the current number of contour intervals with recorded metrics. This is always
	 * less than `maxIntervals`.
	 */
	public get intervalCount(): number {
		return this.count;
	}

	/**
	 * Gets the current time span of each contour interval, in milliseconds. This interval time
	 * span is doubled as necesary such that the entire duration of the session is always covered
	 * by fewer intervals than the maximum.
	 */
	public get interval(): number {
		return this.intervalMs;
	}

	/**
	 * Gets the total number of bytes sent for each interval during the session,
	 * including all channels and non-channel protocol messages, and including message
	 * framing, padding, and MAC bytes. The number of values is equal to `intervalCount`.
	 */
	public get bytesSent(): readonly number[] {
		return this.intervalBytesSent.slice(0, this.count);
	}

	/**
	 * Gets the total number of bytes received for each interval during the session,
	 * including all channels and non-channel protocol messages, and including message
	 * framing, padding, and MAC bytes. The number of values is equal to `intervalCount`.
	 */
	public get bytesReceived(): readonly number[] {
		return this.intervalBytesReceived.slice(0, this.count);
	}

	/**
	 * Gets the minimum recorded round-trip connection latency between client and server for
	 * each interval during the session. The number of values is equal to `intervalCount`.
	 */
	public get latencyMinMs(): readonly number[] {
		return this.intervalLatencyMin.slice(0, this.count);
	}

	/**
	 * Gets the maximum recorded round-trip connection latency between client and server for
	 * each interval during the session. The number of values is equal to `intervalCount`.
	 */
	public get latencyMaxMs(): readonly number[] {
		return this.intervalLatencyMax.slice(0, this.count);
	}

	/**
	 * Gets the average recorded round-trip connection latency between client and server for
	 * each interval during the session. The number of values is equal to `intervalCount`.
	 */
	public get latencyAverageMs(): readonly number[] {
		return this.intervalLatencyAvg.slice(0, this.count);
	}

	private onMessageSent(e: { time: number; size: number }) {
		this.updateQueue.enqueue({
			time: e.time,
			bytesSent: e.size,
		});
		this.updateSemaphore.tryRelease();
	}

	private onMessageReceived(e: { time: number; size: number }) {
		this.updateQueue.enqueue({
			time: e.time,
			bytesReceived: e.size,
		});
		this.updateSemaphore.tryRelease();
	}

	private onLatencyUpdated(e: { time: number; latency: number }) {
		this.updateQueue.enqueue(e);
		this.updateSemaphore.tryRelease();
	}

	private onSessionClosed() {
		this.updateSemaphore.tryRelease();
	}

	/**
	 * Starts collecting session metrics, and processes the metrics in a backgroud loop until
	 * cancelled or until the session is closed or the `SessionContour` instance is disposed.
	 */
	public async collectMetrics(
		sessionMetrics: SessionMetrics,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (!sessionMetrics) throw new TypeError('A session metrics object is required.');
		if (this.disposed) throw new ObjectDisposedError(this);

		const eventRegistrations: Disposable[] = [];
		eventRegistrations.push(sessionMetrics.onMessageSent(this.onMessageSent.bind(this)));
		eventRegistrations.push(sessionMetrics.onMessageReceived(this.onMessageReceived.bind(this)));
		eventRegistrations.push(sessionMetrics.onLatencyUpdated(this.onLatencyUpdated.bind(this)));
		eventRegistrations.push(sessionMetrics.onSessionClosed(this.onSessionClosed.bind(this)));
		try {
			while (!cancellation?.isCancellationRequested) {
				try {
					await this.updateSemaphore.wait(cancellation);
				} catch (e) {
					// The semaphore was disposed.
					break;
				}

				const update = this.updateQueue.dequeue();
				if (!update) {
					// The semaphore was released without enqueueing an update item.
					break;
				}

				const intervalIndex = this.updateInterval(update.time);

				if (update.bytesSent) {
					this.intervalBytesSent[intervalIndex] += update.bytesSent;
				}

				if (update.bytesReceived) {
					this.intervalBytesReceived[intervalIndex] += update.bytesReceived;
				}

				const latency = update.latency;
				if (latency) {
					if (
						!this.intervalLatencyMin[intervalIndex] ||
						latency < this.intervalLatencyMin[intervalIndex]
					) {
						this.intervalLatencyMin[intervalIndex] = latency;
					}

					if (
						!this.intervalLatencyMax[intervalIndex] ||
						latency > this.intervalLatencyMax[intervalIndex]
					) {
						this.intervalLatencyMax[intervalIndex] = latency;
					}

					this.intervalLatencySum[intervalIndex] += latency;
					this.intervalLatencyCount[intervalIndex]++;
					this.intervalLatencyAvg[intervalIndex] =
						this.intervalLatencySum[intervalIndex] / this.intervalLatencyCount[intervalIndex];
				}
			}

			if (this.disposed) {
				this.updateSemaphore.dispose();
			}
		} finally {
			for (const eventRegistration of eventRegistrations) {
				eventRegistration.dispose();
			}
		}
	}

	private updateInterval(time: number): number {
		let intervalIndex = Math.floor(time / this.intervalMs);
		if (intervalIndex >= this.intervalCount) {
			// Expand as needed to accomodate the current time interval.
			while (intervalIndex >= this.maxIntervals) {
				this.expandIntervals();
				intervalIndex = Math.floor(time / this.intervalMs);
			}

			this.count = intervalIndex + 1;
		}

		return intervalIndex;
	}

	private expandIntervals(): void {
		const combineLatency = (a: number, b: number, f: (a: number, b: number) => number) =>
			a === 0 ? b : b === 0 ? a : f(a, b);

		const halfMaxIntervals = this.maxIntervals / 2;
		for (let i = 0; i < halfMaxIntervals; i++) {
			const iA = 2 * i;
			const iB = 2 * i + 1;
			this.intervalBytesSent[i] = this.intervalBytesSent[iA] + this.intervalBytesSent[iB];
			this.intervalBytesReceived[i] =
				this.intervalBytesReceived[iA] + this.intervalBytesReceived[iB];
			this.intervalLatencyMin[i] = combineLatency(
				this.intervalLatencyMin[iA],
				this.intervalLatencyMin[iB],
				Math.min,
			);
			this.intervalLatencyMax[i] = combineLatency(
				this.intervalLatencyMax[iA],
				this.intervalLatencyMax[iB],
				Math.max,
			);
			this.intervalLatencySum[i] = this.intervalLatencySum[iA] + this.intervalLatencySum[iB];
			const countSum = this.intervalLatencyCount[iA] + this.intervalLatencyCount[iB];
			this.intervalLatencyCount[i] = countSum;
			this.intervalLatencyAvg[i] =
				countSum === 0 ? 0 : this.intervalLatencySum[i] / this.intervalLatencyCount[i];
		}

		this.intervalBytesSent.fill(0, halfMaxIntervals, this.maxIntervals);
		this.intervalBytesReceived.fill(0, halfMaxIntervals, this.maxIntervals);
		this.intervalLatencyMin.fill(0, halfMaxIntervals, this.maxIntervals);
		this.intervalLatencyMax.fill(0, halfMaxIntervals, this.maxIntervals);
		this.intervalLatencySum.fill(0, halfMaxIntervals, this.maxIntervals);
		this.intervalLatencyCount.fill(0, halfMaxIntervals, this.maxIntervals);
		this.intervalLatencyAvg.fill(0, halfMaxIntervals, this.maxIntervals);

		this.intervalMs *= 2;
	}

	public dispose(): void {
		this.disposed = true;

		// The semaphore will be disposed after all remaining updates have been processed.
		this.updateSemaphore.tryRelease();
	}

	/**
	 * Serializes the session contour into a compact form suitable for recording in
	 * logs or telemetry.
	 *
	 * This compact serialization format uses one byte per metric per interval, so there is
	 * some loss of precision, but generally not so much that it affects a visualization. A
	 * scale factor for each metric is automatically determined and included in the serialized
	 * header. The size of the serialized encoded data will be a little under 7 bytes per
	 * interval. With the default interval maximum (256), that comes out to less than 1.75 KB.
	 *
	 * Use the code in `SessionContour.kql` to decode and chart this output in
	 * Azure Data Explorer.
	 */
	public export(): string {
		// Time and value scales are in log2 form, determined based on the maximum
		// value in each series. This allows for a reasonable range of precision for each
		// value (with byte values ranging from 0-255). For example a max latency in the
		// 500ms range will get a scale factor of 1 (because ceil(log2(500/255)) = 1), so
		// each serialized value (0-255) is half the actual value (0-510).
		const getScale = (values: readonly number[]) =>
			Math.max(0, Math.ceil(Math.log2(Math.max(...values) / 255)));
		const applyReverseScale = (value: number, scale: number) =>
			Math.round(value / Math.pow(2, scale));

		const bytes = Buffer.alloc(3 + (2 + this.intervalCount) * 5);

		const version = 1;
		const timeScale = Math.log2(this.interval / SessionContour.initialInterval);

		bytes[0] = version;
		bytes[1] = 5; // Number of metrics per interval
		bytes[2] = timeScale;

		bytes[3] = getScale(this.latencyMinMs);
		bytes[4] = getScale(this.latencyMaxMs);
		bytes[5] = getScale(this.latencyAverageMs);
		bytes[6] = getScale(this.bytesSent);
		bytes[7] = getScale(this.bytesReceived);

		bytes[8] = SessionMetric.latencyMin;
		bytes[9] = SessionMetric.latencyMax;
		bytes[10] = SessionMetric.latencyAverage;
		bytes[11] = SessionMetric.bytesSent;
		bytes[12] = SessionMetric.bytesReceived;

		for (let i = 0; i < this.intervalCount; i++) {
			const offset = 13 + 5 * i;
			bytes[offset + 0] = applyReverseScale(this.intervalLatencyMin[i], bytes[3]);
			bytes[offset + 1] = applyReverseScale(this.intervalLatencyMax[i], bytes[4]);
			bytes[offset + 2] = applyReverseScale(this.intervalLatencyAvg[i], bytes[5]);
			bytes[offset + 3] = applyReverseScale(this.intervalBytesSent[i], bytes[6]);
			bytes[offset + 4] = applyReverseScale(this.intervalBytesReceived[i], bytes[7]);
		}

		return bytes.toString('base64');
	}

	/**
	 * Deserializes a session contour that was previously exported.
	 *
	 * Due to loss in precision, some values in the deserialized contour will not exactly match
	 * the original, but they will be close.
	 */
	public static import(contourBase64: string): SessionContour {
		const bytes = Buffer.from(contourBase64, 'base64');
		if (bytes.length < 3) {
			throw new Error('Invalid session contour string.');
		}

		const version = bytes[0];
		const metricsPerInterval = bytes[1];
		const timeScale = bytes[2];

		if (version !== 1) {
			throw new Error(`Unsupported session contour version: ${version}`);
		}

		const intervalCount = (bytes.length - 3) / metricsPerInterval - 2;
		if (intervalCount < 1 || bytes.length !== 3 + metricsPerInterval * (intervalCount + 2)) {
			throw new Error('Incomplete session contour string.');
		}

		const maxIntervals = Math.pow(2, Math.ceil(Math.log2(intervalCount)));
		const sessionContour = new SessionContour(maxIntervals);
		sessionContour.intervalMs = Math.pow(2, timeScale) * SessionContour.initialInterval;
		sessionContour.count = intervalCount;

		const scales = new Array<number>(metricsPerInterval);
		for (let m = 0; m < metricsPerInterval; m++) {
			scales[m] = Math.pow(2, bytes[3 + m]);
		}

		const ids = new Array<SessionMetric>(metricsPerInterval);
		for (let m = 0; m < metricsPerInterval; m++) {
			ids[m] = <SessionMetric>bytes[3 + metricsPerInterval + m];
		}

		for (let i = 0; i < intervalCount; i++) {
			const offset = 3 + (2 + i) * metricsPerInterval;
			for (let m = 0; m < metricsPerInterval; m++) {
				switch (ids[m]) {
					case SessionMetric.latencyMin:
						sessionContour.intervalLatencyMin[i] = bytes[offset + m] * scales[m];
						break;
					case SessionMetric.latencyMax:
						sessionContour.intervalLatencyMax[i] = bytes[offset + m] * scales[m];
						break;
					case SessionMetric.latencyAverage:
						sessionContour.intervalLatencyAvg[i] = sessionContour.intervalLatencySum[i] =
							bytes[offset + m] * scales[m];
						sessionContour.intervalLatencyCount[i] = bytes[offset + m] === 0 ? 0 : 1;
						break;
					case SessionMetric.bytesSent:
						sessionContour.intervalBytesSent[i] = bytes[offset + m] * scales[m];
						break;
					case SessionMetric.bytesReceived:
						sessionContour.intervalBytesReceived[i] = bytes[offset + m] * scales[m];
						break;
					default:
						// Ignore any unknown metrics
						break;
				}
			}
		}

		return sessionContour;
	}
}

enum SessionMetric {
	none = 0,

	latencyMin = 1,
	latencyMax = 2,
	latencyAverage = 3,

	bytesSent = 11,
	bytesReceived = 12,
}
