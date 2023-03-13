//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { Emitter } from 'vscode-jsonrpc';

/**
 * Collects current and cumulative measurements about a session.
 */
export class SessionMetrics {
	private startTime: number = 0;

	private messagesSentCount: number = 0;
	private messagesReceivedCount: number = 0;
	private bytesSentSum: number = 0;
	private bytesReceivedSum: number = 0;
	private reconnectionsCount: number = 0;

	private currentLatency: number = 0;
	private minLatency: number = 0;
	private maxLatency: number = 0;
	private latencySum: number = 0;
	private latencyCount: number = 0;

	/* @internal */
	public constructor() {
		if (typeof performance === 'object' && typeof performance.now === 'function') {
			Object.defineProperty(this, 'time', { get: this.browserTime });
		} else if (typeof process === 'object' && typeof process.hrtime === 'function') {
			Object.defineProperty(this, 'time', { get: this.nodejsTime });
		}
		this.startTime = this.time;
	}

	/**
	 * Gets the current stopwatch value in milliseconds (possibly including fractional milliseconds),
	 * used for measuring latency.
	 */
	/* @internal */
	public get time(): number {
		// The SessionMetrics constructor may replace this with either of the below
		// high-precision implementations, depending on availability of platform APIs.
		return Date.now() - this.startTime;
	}

	private browserTime(): number {
		// Use the browser high-resolution time API.
		// Note the precision may be reduced for pricacy depending on browser and page policy.
		return performance.now() - this.startTime;
	}

	private nodejsTime(): number {
		// Use Node.js high-resolution time API.
		const [s, ns] = process.hrtime();
		return s * 1000 + ns / 1000000 - this.startTime;
	}

	/**
	 * Gets the total cumulative number of messages sent for the duration of the session,
	 * including all channels and non-channel protocol messages.
	 */
	public get messagesSent() {
		return this.messagesSentCount;
	}

	/**
	 * Gets the total cumulative number of messages received for the duration of the session,
	 * including all channels and non-channel protocol messages.
	 */
	public get messagesReceived() {
		return this.messagesReceivedCount;
	}

	/**
	 * Gets the total cumulative number of bytes sent for the duration of the session,
	 * including all channels and non-channel protocol messages, and including message
	 * framing, padding, and MAC bytes.
	 */
	public get bytesSent() {
		return this.bytesSentSum;
	}

	/**
	 * Gets the total cumulative number of bytes received for the duration of the session,
	 * including all channels and non-channel protocol messages, and including message
	 * framing, padding, and MAC bytes.
	 */
	public get bytesReceived() {
		return this.bytesReceivedSum;
	}

	/**
	 * Gets the number of times the session has reconnected.
	 * </summary>
	 * <remarks>
	 * Reconnection requires both sides to support the
	 * <see cref="SshProtocolExtensionNames.SessionReconnect" /> protocol extension.
	 */
	public get reconnections() {
		return this.reconnectionsCount;
	}

	/**
	 * Gets the average measured round-trip connection latency between client and server
	 * over the duration of the session, in milliseconds.
	 * </summary>
	 * <remarks>
	 * Latency measurement requires both sides to support the
	 * <see cref="SshProtocolExtensionNames.SessionLatency" /> protocol extension.
	 * If not supported, this Sum will be 0.
	 */
	public get latencyAverageMs() {
		return this.latencyCount === 0 ? 0 : this.latencySum / this.latencyCount;
	}

	/**
	 * Gets the minimum measured round-trip connection latency between client and server
	 * over the duration of the session, in milliseconds.
	 * </summary>
	 * <remarks>
	 * Latency measurement requires both sides to support the
	 * <see cref="SshProtocolExtensionNames.SessionLatency" /> protocol extension.
	 * If not supported, this Sum will be 0.
	 */
	public get latencyMinMs() {
		return this.minLatency;
	}

	/**
	 * Gets the maximum measured round-trip connection latency between client and server
	 * over the duration of the session, in milliseconds.
	 * </summary>
	 * <remarks>
	 * Latency measurement requires both sides to support the
	 * <see cref="SshProtocolExtensionNames.SessionLatency" /> protocol extension.
	 * If not supported, this Sum will be 0.
	 */
	public get latencyMaxMs() {
		return this.maxLatency;
	}

	/**
	 * Gets the most recent measurement of round-trip connection latency between client and
	 * server, in milliseconds.
	 * </summary>
	 * <remarks>
	 * Latency measurement requires both sides to support the
	 * <see cref="SshProtocolExtensionNames.SessionLatency" /> protocol extension.
	 * If not supported or the session is not currently connected, this Sum will be 0.
	 */
	public get latencyCurrentMs() {
		return this.currentLatency;
	}

	private readonly messageSentEmitter = new Emitter<{ time: number; size: number }>();
	public readonly onMessageSent = this.messageSentEmitter.event;

	private readonly messageReceivedEmitter = new Emitter<{ time: number; size: number }>();
	public readonly onMessageReceived = this.messageReceivedEmitter.event;

	private readonly latencyUpdatedEmitter = new Emitter<{ time: number; latency: number }>();
	public readonly onLatencyUpdated = this.latencyUpdatedEmitter.event;

	private readonly sessionClosedEmitter = new Emitter<void>();
	public readonly onSessionClosed = this.sessionClosedEmitter.event;

	/* @internal */
	public addMessageSent(size: number): void {
		this.messagesSentCount++;
		this.bytesSentSum += size;

		this.messageSentEmitter.fire({ time: this.time, size });
	}

	/* @internal */
	public addMessageReceived(size: number): void {
		this.messagesReceivedCount++;
		this.bytesReceivedSum += size;

		this.messageReceivedEmitter.fire({ time: this.time, size });
	}

	/* @internal */
	public addReconnection(): void {
		this.reconnectionsCount++;
	}

	/* @internal */
	public updateLatency(latencyMs: number): void {
		if (latencyMs < 0) {
			throw new Error('Measured latency cannot be negative.');
		}

		this.currentLatency = latencyMs;

		if (latencyMs === 0) {
			// Disconnected.
			return;
		}

		if (this.minLatency === 0 || latencyMs < this.minLatency) {
			this.minLatency = latencyMs;
		}

		if (this.maxLatency === 0 || latencyMs > this.maxLatency) {
			this.maxLatency = latencyMs;
		}

		// Enable computing the average.
		this.latencySum += latencyMs;
		this.latencyCount++;

		this.latencyUpdatedEmitter.fire({ time: this.time, latency: latencyMs });
	}

	/* @internal */
	public close(): void {
		this.currentLatency = 0;
		this.sessionClosedEmitter.fire();
	}

	public toString(): string {
		let s =
			`Messages S/R: ${this.messagesSent} / ${this.messagesReceived}; ` +
			`Bytes S/R: ${this.bytesSent} / ${this.bytesReceived}; ` +
			`Reconnections: ${this.reconnections}; `;

		// Show extra precision for a low-latency connection.
		const precision = this.minLatency >= 10 ? 1 : this.minLatency >= 1 ? 10 : 100;

		if (this.maxLatency > 0) {
			const min = Math.round(this.minLatency * precision) / precision;
			const avg = Math.round((this.latencySum / this.latencyCount) * precision) / precision;
			const max = Math.round(this.maxLatency * precision) / precision;
			s += `Latency Min-Avg-Max: ${min} - ${avg} - ${max} ms; `;
		}

		if (this.currentLatency > 0) {
			const current = Math.round(this.currentLatency * precision) / precision;
			s += `Current Latency: ${current} ms; `;
		}

		return s;
	}
}
