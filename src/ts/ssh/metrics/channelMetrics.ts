//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * Collects cumulative measurements about a channel.
 */
export class ChannelMetrics {
	private bytesSentSum: number = 0;
	private bytesReceivedSum: number = 0;

	/* @internal */
	public constructor() {}

	/**
	 * Gets the total cumulative number of bytes sent for the duration of the channel,
	 * not including message framing, padding, and MAC bytes.
	 */
	public get bytesSent(): number {
		return this.bytesSentSum;
	}

	/**
	 * Gets the total cumulative number of bytes received for the duration of the channel,
	 * not including message framing, padding, and MAC bytes.
	 */
	public get bytesReceived(): number {
		return this.bytesReceivedSum;
	}

	/* @internal */
	public addBytesSent(count: number): void {
		this.bytesSentSum += count;
	}

	/* @internal */
	public addBytesReceived(count: number): void {
		this.bytesReceivedSum += count;
	}

	public toString(): string {
		return `Bytes S/R: ${this.bytesSent} / ${this.bytesReceived}; `;
	}
}
