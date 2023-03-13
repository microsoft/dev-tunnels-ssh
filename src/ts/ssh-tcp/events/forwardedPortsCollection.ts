//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshChannel } from '@microsoft/dev-tunnels-ssh';
import { Emitter } from 'vscode-jsonrpc';
import { ForwardedPort } from './forwardedPort';
import { ForwardedPortChannelEventArgs, ForwardedPortEventArgs } from './forwardedPortEventArgs';

/**
 * Tracks the list of ports that are currently being forwarded between the SSH client and server,
 * along with the set of channel connections for each forwarded port.
 *
 * Ports forwarded in either direction (client->server or server->client) are tracked in separate
 * collections. Typically within a session the forwarding is done only in one direction, though
 * the protocol supports bi-directional forwarding.
 *
 * @see PortForwardingService.RemoteForwardedPorts
 * @see PortForwardingService.LocalForwardedPorts
 */
export class ForwardedPortsCollection implements ReadonlySet<ForwardedPort> {
	/**
	 * Maintains a mapping from port keys to port objects and channels for the port.
	 *
	 * The ForwardedPort string representation is used as the keys.
	 */
	private portChannelMap = new Map<string, [ForwardedPort, SshChannel[]]>();

	/** Gets the number of ports in the collection. */
	public get size(): number {
		return this.portChannelMap.size;
	}

	/** Checks whether a port is in the collection. */
	public has(port: ForwardedPort): boolean {
		return this.portChannelMap.has(port.toString());
	}

	/** Lists all the ports in the collection. */
	public *values(): IterableIterator<ForwardedPort> {
		for (const [port, channels] of this.portChannelMap.values()) {
			yield port;
		}
	}

	/** Iterates over all the ports in the collection. */
	public [Symbol.iterator](): IterableIterator<ForwardedPort> {
		return this.values();
	}

	/** Lists all the ports in the collection. */
	public *entries(): IterableIterator<[ForwardedPort, ForwardedPort]> {
		for (const [port, channels] of this.portChannelMap.values()) {
			yield [port, port];
		}
	}

	/**
	 * Lists all the ports in the collection.
	 * (In a set, the keys are the same as the values.)
	 */
	public keys(): IterableIterator<ForwardedPort> {
		return this.values();
	}

	/** Iterates over all the ports in the collection, invoking a callback function on each. */
	public forEach(
		callbackfn: (
			value: ForwardedPort,
			key: ForwardedPort,
			set: ReadonlySet<ForwardedPort>,
		) => void,
		thisArg?: any,
	): void {
		for (const [port, channels] of this.portChannelMap.values()) {
			callbackfn.apply(thisArg, [port, port, this]);
		}
	}

	public getChannels(port: ForwardedPort): SshChannel[] {
		const portAndChannels = this.portChannelMap.get(port.toString());
		if (!portAndChannels) {
			throw new Error(`Port ${port} is not in the collection.`);
		}

		return portAndChannels[1];
	}

	private readonly portAddedEmitter = new Emitter<ForwardedPortEventArgs>();
	public readonly onPortAdded = this.portAddedEmitter.event;

	private readonly portRemovedEmitter = new Emitter<ForwardedPortEventArgs>();
	public readonly onPortRemoved = this.portRemovedEmitter.event;

	private readonly portChannelAddedEmitter = new Emitter<ForwardedPortChannelEventArgs>();
	public readonly onPortChannelAdded = this.portChannelAddedEmitter.event;

	private readonly portChannelRemovedEmitter = new Emitter<ForwardedPortChannelEventArgs>();
	public readonly onPortChannelRemoved = this.portChannelRemovedEmitter.event;

	/** Finds the first port in the collection that matches a predicate. */
	public find(predicate: (port: ForwardedPort) => boolean): ForwardedPort | undefined {
		for (const port of this.values()) {
			if (predicate(port)) {
				return port;
			}
		}

		return undefined;
	}

	/* @internal */
	public addPort(port: ForwardedPort): void {
		if (this.has(port)) {
			throw new Error(`Port ${port} is already in the collection.`);
		}

		this.portChannelMap.set(port.toString(), [port, []]);
		this.portAddedEmitter.fire(new ForwardedPortEventArgs(port));
	}

	/* @internal */
	public removePort(port: ForwardedPort): void {
		if (!this.has(port)) {
			throw new Error(`Port ${port} is not in the collection.`);
		}

		this.portChannelMap.delete(port.toString());
		this.portRemovedEmitter.fire(new ForwardedPortEventArgs(port));
	}

	/* @internal */
	public addChannel(port: ForwardedPort, channel: SshChannel): void {
		const portAndChannels = this.portChannelMap.get(port.toString());
		if (!portAndChannels) {
			throw new Error(`Port ${port} is not in the collection.`);
		}

		const portChannels = portAndChannels[1];
		if (portChannels.find((c) => c.channelId === channel.channelId)) {
			throw new Error(
				`Channel ${channel.channelId} is already in the collection for port ${port}`,
			);
		}

		portChannels.push(channel);
		channel.onClosed(() => this.tryRemoveChannel(port, channel));
		this.portChannelAddedEmitter.fire(new ForwardedPortChannelEventArgs(port, channel));
	}

	private tryRemoveChannel(port: ForwardedPort, channel: SshChannel): void {
		const portAndChannels = this.portChannelMap.get(port.toString());
		if (portAndChannels) {
			const portChannels = portAndChannels[1];
			const index = portChannels.findIndex((c) => c.channelId === channel.channelId);
			if (index >= 0) {
				portChannels.splice(index, 1);
				this.portChannelRemovedEmitter.fire(new ForwardedPortChannelEventArgs(port, channel));
			}
		}
	}

	public toString() {
		return [...this].join(', ');
	}
}
