//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as net from 'net';
import { CancellationToken } from 'vscode-jsonrpc';

export interface TcpListenerFactory {
	/**
	 * Creates and starts a TCP listener for the specified local network address and port
	 * number.
	 *
	 * @param remotePort The remote port that this local port will connect to (if known).
	 * @param localIPAddress Local IP address to listen on.
	 * @param localPort Requested local port to listen on, or 0 to use a random
	 * available port number.
	 * @param canChangeLocalPort True if the factory is allowed to select a different
	 * local port number than the one that was requested; if false then the factory must either
	 * use the requested port or throw an exception.</param>
	 * @param cancellation">Cancellation token.</param>
	 * @returns TCP listener object that has started listening.</returns>
	 * @exception SocketException Creating or starting the listener failed.</exception>
	 *
	 * The `localIPAddress` may be any of the following values:
	 *  - `IPAddress.Loopback`: Bind to IPv4 and IPv6 loopback interfaces.
	 *  - `IPAddress.IPv6Loopback`: Bind to only the IPv6 loopback interfaces.
	 *  - `IPAddress.Any`: Bind to all IPv4 and IPv6 interfaces.
	 *  - `IPAddress.IPv6Any`: Bind to only IPv6 interfaces.
	 *  - Any other IP address: Bind to the interface with the specified IP address.
	 *
	 * The factory implementation may choose an alternate port number instead of the requested
	 * `localPort` value, for instance if the requested port is in-use or the
	 * current process does not have permission to listen on it. In that case the caller will
	 * obtain the actual port from the returned listener's `localEndpoint` property.
	 */
	createTcpListener(
		remotePort: number | undefined,
		localIPAddress: string,
		localPort: number,
		canChangeLocalPort: boolean,
		cancellation?: CancellationToken,
	): Promise<net.Server>;
}

export class DefaultTcpListenerFactory implements TcpListenerFactory {
	public async createTcpListener(
		remotePort: number | undefined,
		localIPAddress: string,
		localPort: number,
		canChangeLocalPort: boolean,
		cancellation?: CancellationToken,
	): Promise<net.Server> {
		if (!localIPAddress) throw new TypeError('Local IP address is required.');
		if (!Number.isInteger(localPort) || localPort < 0)
			throw new TypeError('Local port must be a non-negative integer.');

		const listener = net.createServer();

		await new Promise((resolve, reject) => {
			listener.listen({
				host: localIPAddress,
				port: localPort,
				ipv6Only: net.isIPv6(localIPAddress),
				exclusive: false,
			});
			listener.on('listening', resolve);
			listener.on('error', reject);
		});

		return listener;
	}
}
