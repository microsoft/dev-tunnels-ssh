//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * Represents a port being forwarded over an SSH session.
 */
export class ForwardedPort {
	/** @internal */
	public constructor(localPort: number | null, remotePort: number | null, isRemote: boolean) {
		if (localPort === null && remotePort === null) {
			throw new TypeError('Local and remote ports cannot both be null.');
		} else if (!isRemote && remotePort === null) {
			// The remote port number should always be known for locally forwarded ports.
			throw new TypeError(
				'The report port number must not be null for locally forwarded ports.',
			);
		}

		if (localPort !== null && (typeof localPort !== 'number' || localPort <= 0)) {
			throw new TypeError('Local port must be a positive integer.');
		} else if (remotePort !== null && (typeof remotePort !== 'number' || remotePort <= 0)) {
			throw new TypeError('Remote port must be a positive integer: ' + remotePort);
		}

		this.localPort = localPort;
		this.remotePort = remotePort;

		// The string representation is constructed ahead of time because it is used as a workaround
		// for JavaScript Map<T> objects not supporting custom object equality. The string
		// representation is used as the map key.
		const arrow = isRemote ? '->' : '<-';
		if (this.localPort === null) {
			this.str = `${arrow}${this.remotePort}`;
		} else if (this.remotePort == null) {
			this.str = `${this.localPort}${arrow}`;
		} else {
			this.str = `${this.localPort}${arrow}${this.remotePort}`;
		}
	}

	/**
	 * Gets the port number on the local side, or null if this is a remotely forwarded port
	 * for which there is no local TCP listener.
	 */
	public readonly localPort: number | null;

	/**
	 * Gets the port number on the remote side, or null if this is a remotely forwarded port
	 * and the remote port number is not known.
	 */
	public readonly remotePort: number | null;

	/**
	 * String representation of the (immutable) forwarded port.
	 */
	private readonly str: string;

	/**
	 * Gets a string representation of the forwarded port, which includes both
	 * local and remote port numbers if present.
	 *
	 * An arrow shows the direction of connections (channel open requests).
	 * Once connections are opened, data may flow in both directions.
	 */
	public toString() {
		return this.str;
	}
}
