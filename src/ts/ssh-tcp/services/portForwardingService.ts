//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import {
	SshService,
	SshSession,
	SshChannel,
	SshMessage,
	serviceActivation,
	SshRequestEventArgs,
	SessionRequestMessage,
	SshChannelOpeningEventArgs,
	SshStream,
	SessionRequestFailureMessage,
	SessionRequestSuccessMessage,
	SshChannelOpenFailureReason,
	SshTraceEventIds,
	TraceLevel,
	PromiseCompletionSource,
	ObjectDisposedError,
	CancellationError,
	CancellationToken,
} from '@microsoft/dev-tunnels-ssh';
import { Disposable } from 'vscode-jsonrpc';
import { ForwardedPort } from '../events/forwardedPort';
import { ForwardedPortsCollection } from '../events/forwardedPortsCollection';
import { IPAddressConversions } from '../ipAddressConversions';
import { PortForwardChannelOpenMessage } from '../messages/portForwardChannelOpenMessage';
import { PortForwardRequestMessage } from '../messages/portForwardRequestMessage';
import { PortForwardSuccessMessage } from '../messages/portForwardSuccessMessage';
import { TcpListenerFactory, DefaultTcpListenerFactory } from '../tcpListenerFactory';
import {
	PortForwardMessageFactory,
	DefaultPortForwardMessageFactory,
} from '../portForwardMessageFactory';
import { ChannelForwarder } from './channelForwarder';
import { LocalPortForwarder } from './localPortForwarder';
import { RemotePortConnector } from './remotePortConnector';
import { RemotePortForwarder } from './remotePortForwarder';
import { RemotePortStreamer } from './remotePortStreamer';

/**
 * Implements the standard SSH port-forwarding protocol.
 * @example
 * Use `SshSessionConfiguration.addService()` on both client and server side configurations
 * to add the `PortForwardingService` type before attempting to call methods on the service.
 * Then use `SshSession.activateService()` to get the service instance:
 *
 *     const config = new SshSessionConfiguration();
 *     config.addService(PortForwardingService);
 *     const client = new SshClient(config);
 *     const session = await client.openSession(host, port);
 *     await session.authenticate(clientCredentials);
 *     const pfs = session.activateService(PortForwardingService);
 *     const forwarder = pfs.forwardToRemotePort('::', 3000);
 */
@serviceActivation({ sessionRequest: PortForwardingService.portForwardRequestType })
@serviceActivation({ sessionRequest: PortForwardingService.cancelPortForwardRequestType })
@serviceActivation({ channelType: PortForwardingService.portForwardChannelType })
@serviceActivation({ channelType: PortForwardingService.reversePortForwardChannelType })
export class PortForwardingService extends SshService {
	public static readonly portForwardRequestType = 'tcpip-forward';
	public static readonly cancelPortForwardRequestType = 'cancel-tcpip-forward';
	public static readonly portForwardChannelType = 'forwarded-tcpip';
	public static readonly reversePortForwardChannelType = 'direct-tcpip';

	/**
	 * Maps from FORWARDED port number to the object that manages listening for incoming
	 * connections for that port and forwarding them through the session.
	 *
	 * Note the actual local source port number used may be different from the forwarded port
	 * number if the local TCP listener factory chose a different port. The forwarded port number
	 * is used to identify the port in any messages exchanged between client and server.
	 */
	private readonly localForwarders = new Map<number, LocalPortForwarder>();

	/**
	 * Maps from FORWARDED port numbers to the object that manages relaying forwarded connections
	 * from the session to a local port.
	 *
	 * Note the actual local destination port number used may be different from the forwarded port
	 * number. The forwarded port number is used to identify the port in any messages exchanged
	 * between client and server.
	 */
	private readonly remoteConnectors = new Map<number, RemotePortConnector>();

	/* @internal */
	public readonly channelForwarders: ChannelForwarder[] = [];

	/* @internal */
	public constructor(session: SshSession) {
		super(session);
	}

	/**
	 * Gets or sets a value that controls whether the port-forwarding service listens on
	 * local TCP sockets to accept connections for ports that are forwarded from the remote side.
	 *
	 * The default is true.
	 *
	 * This property is typically initialized before connecting a session (if not keeping the
	 * default). It may be changed at any time while the session is connected, and the new value
	 * will affect any newly forwarded ports after that, but not previously-forwarded ports.
	 *
	 * Regardless of whether this is enabled, connections to forwarded ports can be made using
	 * `connectToForwardedPort()`.
	 */
	public acceptLocalConnectionsForForwardedPorts: boolean = true;

	/**
	 * Gets or sets a value that controls whether the port-forwarding service accepts
	 * 'direct-tcpip' channel open requests and forwards the channel connections to the local port.
	 *
	 * The default is true.
	 *
	 * This property is typically initialized before connecting a session (if not keeping the
	 * default). It may be changed at any time while the session is connected, and the new value
	 * will affect any newly forwarded ports after that, but not previously-forwarded ports.
	 *
	 * Regardless of whether this is enabled, the remote side can open 'forwarded-tcpip' channels
	 * to connect to ports that were explicitly forwarded by this side.
	 */
	public acceptRemoteConnectionsForNonForwardedPorts: boolean = true;

	/**
	 * Gets the collection of ports that are currently being forwarded from the remote side
	 * to the local side.
	 *
	 * Ports are added to this collection when `forwardFromRemotePort()` or
	 * `streamFromRemotePort()` is called (and the other side accepts the
	 * 'tcpip-forward' request), and then are removed when the `RemotePortForwarder`
	 * is disposed (which also sends a 'cancel-tcpip-forward' message).
	 *
	 * Each forwarded port may have 0 or more active connections (channels).
	 *
	 * The collection does not include direct connections initiated via
	 * `forwardToRemotePort()` or `streamToRemotePort()`.
	 *
	 * Local forwarded ports may or may not have local TCP listeners automatically set up,
	 * depending on the value of `acceptLocalConnectionsForForwardedPorts`.
	 */
	public readonly localForwardedPorts = new ForwardedPortsCollection();

	/**
	 * Gets the collection of ports that are currently being forwarded from the local side
	 * to the remote side.
	 *
	 * Ports are added to this collection when the port-forwarding service handles a
	 * 'tcpip-forward' request message, and removed when it receives a 'cancel-tcpip-forward'
	 * request message.
	 *
	 * Each forwarded port may have 0 or more active connections (channels).
	 *
	 * The collection does not include direct connections initiated via
	 * `forwardToRemotePort()` or `streamToRemotePort()`.
	 */
	public readonly remoteForwardedPorts = new ForwardedPortsCollection();

	/**
	 * Gets or sets a factory for creating TCP listeners.
	 *
	 * Applications may override this factory to provide custom logic for selecting
	 * local port numbers to listen on for port-forwarding.
	 *
	 * This factory is not used when `acceptLocalConnectionsForForwardedPorts` is
	 * set to false.
	 */
	public tcpListenerFactory: TcpListenerFactory = new DefaultTcpListenerFactory();

	/**
	 * Gets or sets a factory for creating port-forwarding messages.
	 *
	 * A message factory enables applications to extend port-forwarding by providing custom
	 * message subclasses that may include additional properties.
	 */
	public messageFactory: PortForwardMessageFactory = new DefaultPortForwardMessageFactory();

	/**
	 * Sends a request to the remote side to listen on a port and forward incoming connections
	 * as SSH channels of type 'forwarded-tcpip', which will then be relayed to the same port
	 * number on the local side.
	 *
	 * @param remoteIPAddress IP address of the interface to bind to on the remote side.
	 * @param remotePort The port number to forward. (Must not be 0.)
	 * @param cancellation Cancellation token for the request; note this cannot cancel forwarding
	 * once it has started; use the returned disposable do do that.
	 * @returns A disposable object that when disposed will cancel forwarding the port, or `null` if
	 * the request was rejected by the remote side, possibly because the port was already in use.
	 * Disposing the returned object does not close any channels currently forwarding connections;
	 * it only sends a request to the remote side to stop listening on the remote port.
	 */
	public forwardFromRemotePort(
		remoteIPAddress: string,
		remotePort: number,
		cancellation?: CancellationToken,
	): Promise<RemotePortForwarder | null>;

	/**
	 * Sends a request to the remote side to listen on a port and forward incoming connections
	 * as SSH channels of type 'forwarded-tcpip', which will then be relayed to a specified
	 * local port.
	 *
	 * @param remoteIPAddress IP address of the interface to bind to on the remote side.
	 * @param remotePort The remote port to listen on, or 0 to choose an available port. (The
	 * chosen port can then be obtained via the `remotePort` property on the returned object.)
	 * @param localHost The destination hostname or IP address for forwarded connections, to be
	 * resolved on the local side. WARNING: Avoid using the hostname `localhost` as the destination
	 * host; use `127.0.0.1` or `::1` instead. (OpenSSH does not recognize `localhost` as a valid
	 * destination host.)
	 * @param localPort The destination port for forwarded connections. Defaults to the same as
	 * the remote port. (Must not be 0.)
	 * @param cancellation Cancellation token for the request; note this cannot cancel forwarding
	 * once it has started; use the returned disposable do do that.
	 * @returns A disposable object that when disposed will cancel forwarding the port, or `null` if
	 * the request was rejected by the remote side, possibly because the port was already in use.
	 * Disposing the returned object does not close any channels currently forwarding connections;
	 * it only sends a request to the remote side to stop listening on the remote port.
	 */
	public forwardFromRemotePort(
		remoteIPAddress: string,
		remotePort: number,
		localHost: string,
		localPort: number,
		cancellation?: CancellationToken,
	): Promise<RemotePortForwarder | null>;

	public async forwardFromRemotePort(
		remoteIPAddress: string,
		remotePort: number,
		localHostOrCancellation?: string | CancellationToken,
		localPort?: number,
		cancellation?: CancellationToken,
	): Promise<RemotePortForwarder | null> {
		let localHost =
			typeof localHostOrCancellation === 'string' ? localHostOrCancellation : '127.0.0.1';
		if (typeof localPort === 'undefined') localPort = remotePort;

		if (!remoteIPAddress) throw new TypeError('Remote IP address is required.');
		if (!Number.isInteger(remotePort) || remotePort < 0) {
			throw new TypeError('Remote port must be a non-negative integer.');
		}
		if (!localHost) throw new TypeError('Local host is required.');
		if (!Number.isInteger(localPort) || localPort <= 0) {
			throw new TypeError('Local port must be a positive integer.');
		}

		if (this.localForwardedPorts.find((p) => p.localPort === localPort)) {
			throw new Error(`Local port ${localPort} is already forwarded.`);
		} else if (
			remotePort > 0 &&
			this.localForwardedPorts.find((p) => p.remotePort === remotePort)
		) {
			throw new Error(`Remote port ${remotePort} is already forwarded.`);
		}

		const forwarder = new RemotePortForwarder(
			this,
			this.session,
			remoteIPAddress,
			remotePort,
			localHost,
			localPort,
		);

		const request = await this.messageFactory.createRequestMessageAsync(remotePort);
		if (!(await forwarder.request(request, cancellation))) {
			forwarder.dispose();
			return null;
		}

		remotePort = forwarder.remotePort;

		// The remote port is the port sent in the message to the other side,
		// so the connector is indexed on that port number, rather than the local port.
		this.remoteConnectors.set(remotePort, forwarder);

		const forwardedPort = new ForwardedPort(localPort, remotePort, false);
		this.localForwardedPorts.addPort(forwardedPort);
		forwarder.onDisposed(() => {
			this.localForwardedPorts.removePort(forwardedPort);
			this.remoteConnectors.delete(remotePort);
		});

		return forwarder;
	}

	/**
	 * Starts listening on a local port and forwards incoming connections as SSH channels of type
	 * 'direct-tcpip', which will then be relayed to the same port number on the remote side,
	 * regardless of whether the remote side has explicitly forwarded that port.
	 *
	 * @param localIPAddress IP address of the interface to bind to on the local side.
	 * @param localPort The port number to forward. (Must not be 0.)
	 * @param cancellation Cancellation token for the request; note this cannot cancel forwarding
	 * once it has started; use the returned disposable do do that.
	 * @returns A disposable object that when disposed will cancel forwarding the port.
	 * Disposing the returned object does not close any channels currently forwarding connections;
	 * it only stops listening on the local port.
	 * @throws If the local port is already in use.
	 */
	public async forwardToRemotePort(
		localIPAddress: string,
		localPort: number,
		cancellation?: CancellationToken,
	): Promise<LocalPortForwarder>;

	/**
	 * Starts listening on a local port and forwards incoming connections as SSH channels of type
	 * 'direct-tcpip', which will then be relayed to a specified remote port, regardless of whether
	 * the remote side has explicitly forwarded that port.
	 *
	 * @param localIPAddress IP address of the interface to bind to on the local side.
	 * @param localPort he local port number to lsiten on, or 0 to choose an available port.
	 * (The chosen port can then be obtained via the `localPort` property on the returned object.)
	 * @param remoteHost The destination hostname or IP address for forwarded connections, to be
	 * resolved on the remote side. WARNING: Avoid using the hostname `localhost` as the destination
	 * host; use `127.0.0.1` or `::1` instead. (OpenSSH does not recognize `localhost` as a valid
	 * destination host.)
	 * @param remotePort The destination port for forwarded connections. Defaults to the same
	 * as the local port. (Must not be 0.)
	 * @param cancellation Cancellation token for the request; note this cannot cancel forwarding
	 * once it has started; use the returned disposable do do that.
	 * @returns A disposable object that when disposed will cancel forwarding the port.
	 * Disposing the returned object does not close any channels currently forwarding connections;
	 * it only stops listening on the local port.
	 * @throws If the local port is already in use.
	 */
	public async forwardToRemotePort(
		localIPAddress: string,
		localPort: number,
		remoteHost: string,
		remotePort: number,
		cancellation?: CancellationToken,
	): Promise<LocalPortForwarder>;

	public async forwardToRemotePort(
		localIPAddress: string,
		localPort: number,
		remoteHostOrCancellation?: string | CancellationToken,
		remotePort?: number,
		cancellation?: CancellationToken,
	): Promise<LocalPortForwarder> {
		let remoteHost =
			typeof remoteHostOrCancellation === 'string' ? remoteHostOrCancellation : '127.0.0.1';
		if (typeof remotePort === 'undefined') remotePort = localPort;

		if (!localIPAddress) throw new TypeError('Local IP address is required.');
		if (!Number.isInteger(localPort) || localPort < 0) {
			throw new TypeError('Local port must be a non-negative integer.');
		}
		if (!remoteHost) throw new TypeError('Remote host is required.');
		if (!Number.isInteger(remotePort) || remotePort <= 0) {
			throw new TypeError('Remote port must be a positive integer.');
		}

		const forwarder = new LocalPortForwarder(
			this,
			this.session,
			PortForwardingService.reversePortForwardChannelType,
			localIPAddress,
			localPort,
			remoteHost,
			remotePort,
		);
		await forwarder.startForwarding(cancellation);

		// The remote port is the port sent in the message to the other side,
		// so the forwarder is indexed on that port number, rather than the local port.
		this.localForwarders.set(remotePort, forwarder);
		forwarder.onDisposed(() => {
			this.localForwarders.delete(remotePort!);
		});
		return forwarder;
	}

	/**
	 * Sends a request to the remote side to listen on a port and forward incoming connections as
	 * SSH channels of type 'forwarded-tcpip', which will then be relayed as local streams.
	 *
	 * @param remoteIPAddress IP address of the interface to bind to on the remote side.
	 * @param remotePort The remote port to listen on, or 0 to choose an available port.
	 * (The chosen port can then be obtained via the `remotePort` property on the returned object.)
	 * @param cancellation Cancellation token for the request; note this cannot cancel forwarding
	 * once it has started; use the returned disposable do do that.
	 * @returns A disposable object that when disposed will cancel forwarding the port, or `null`
	 * if the request was rejected by the remote side, possibly because the remote port was already
	 * in use. Handle the `onStreamOpened` event on this object to receive streams.
	 */
	public async streamFromRemotePort(
		remoteIPAddress: string,
		remotePort: number,
		cancellation?: CancellationToken,
	): Promise<RemotePortStreamer | null> {
		if (!remoteIPAddress) throw new TypeError('Remote IP address is required.');
		if (!Number.isInteger(remotePort) || remotePort < 0) {
			throw new TypeError('Remote port must be a non-negative integer.');
		}

		const streamer = new RemotePortStreamer(this.session, remoteIPAddress, remotePort);
		const request = await this.messageFactory.createRequestMessageAsync(remotePort);
		if (!(await streamer.request(request, cancellation))) {
			streamer.dispose();
			return null;
		}

		remotePort = streamer.remotePort;

		// The remote port is the port sent in the message to the other side,
		// so the connector is indexed on that port number. (There is no local port anyway.)
		this.remoteConnectors.set(remotePort, streamer);

		const forwardedPort = new ForwardedPort(null, remotePort, false);
		this.localForwardedPorts.addPort(forwardedPort);
		streamer.onDisposed(() => {
			this.localForwardedPorts.removePort(forwardedPort);
			this.remoteConnectors.delete(remotePort);
		});

		return streamer;
	}

	/**
	 * Opens a stream for an SSH channel of type 'direct-tcpip' that is relayed to remote port,
	 * regardless of whether the remote side has explicitly forwarded that port.
	 *
	 * @param remoteHost The destination hostname or IP address for forwarded connections, to be
	 * resolved on the remote side. WARNING: Avoid using the hostname `localhost` as the destination
	 * host; use `127.0.0.1` or `::1` instead. (OpenSSH does not recognize `localhost` as a valid
	 * destination host.)
	 * @param remotePort The destination port for the forwarded stream. (Must not be 0.)
	 * @param cancellation Cancellation token for the request; note this cannot cancel streaming
	 * once it has started; dipose the returned stream for that.
	 * @returns A stream that is relayed to the remote port.
	 * @throws `SshChannelError` if the streaming channel could not be opened, either because it
	 * was rejected by the remote side, or the remote connection failed.
	 */
	public async streamToRemotePort(
		remoteHost: string,
		remotePort: number,
		cancellation?: CancellationToken,
	): Promise<SshStream> {
		if (!remoteHost) throw new TypeError('Remote host is required.');
		if (!Number.isInteger(remotePort) || remotePort <= 0) {
			throw new TypeError('Remote port must be a positive integer.');
		}

		const channel = await this.openChannel(
			this.session,
			PortForwardingService.reversePortForwardChannelType,
			null,
			null,
			remoteHost,
			remotePort,
			cancellation,
		);

		return new SshStream(channel);
	}

	/**
	 * Opens a stream for an SSH channel of type 'forwarded-tcpip' that is relayed to a remote
	 * port. The port must have been explicitly forwarded by the remote side.
	 *
	 * It may be necessary to call `waitForForwardedPort` before this method
	 * to ensure the port is ready for connections.
	 *
	 * An error is thrown if the requested port could not be forwarded, possibly because it was
	 * rejected by the remote side, or the remote connection failed.
	 *
	 * @param forwardedPort Remote port number that was forwarded.
	 * @param cancellation Cancellation token for the request; note this cannot
	 * cancel streaming once it has started; dipose the returned stream for that.
	 * @returns A stream that is relayed to the remote forwarded port.
	 */
	public async connectToForwardedPort(
		forwardedPort: number,
		cancellation?: CancellationToken,
	): Promise<SshStream> {
		if (!Number.isInteger(forwardedPort) || forwardedPort <= 0) {
			throw new TypeError('Forwarded port must be a positive integer.');
		}

		const channel = await this.openChannel(
			this.session,
			PortForwardingService.portForwardChannelType,
			null,
			null,
			'127.0.0.1',
			forwardedPort,
			cancellation,
		);

		return new SshStream(channel);
	}

	/**
	 * Waits asynchronously for the remote side to forward an expected port number.
	 *
	 * A common pattern for some applications may be to call this method just before
	 * `ConnectToForwardedPortAsync`.
	 *
	 * @param forwardedPort Port number that is expected to be forwarded.
	 * @param cancellation Token that can be used to cancel waiting.
	 * @returns A promise that completes when the expected port number has been forwarded.
	 */
	public async waitForForwardedPort(
		forwardedPort: number,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (this.remoteForwardedPorts.find((p) => p.remotePort === forwardedPort)) {
			// It's already forwarded, so there's no need to wait.
			return;
		}

		const waitCompletion = new PromiseCompletionSource<void>();

		let cancellationRegistration: Disposable | undefined;
		if (cancellation) {
			cancellationRegistration = cancellation.onCancellationRequested(() =>
				waitCompletion.reject(new CancellationError()),
			);
		}

		let portAddedRegistration: Disposable | undefined;
		let sessionClosedRegistration: Disposable | undefined;
		try {
			portAddedRegistration = this.remoteForwardedPorts.onPortAdded((e) => {
				if (e.port.remotePort === forwardedPort) {
					waitCompletion.resolve();
				}
			});
			sessionClosedRegistration = this.session.onClosed(() => {
				waitCompletion.reject(new ObjectDisposedError('The session was closed.'));
			});

			await waitCompletion.promise;
		} finally {
			portAddedRegistration?.dispose();
			sessionClosedRegistration?.dispose();
			cancellationRegistration?.dispose();
		}
	}

	protected async onSessionRequest(
		request: SshRequestEventArgs<SessionRequestMessage>,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (!request) throw new TypeError('Request is required.');
		else if (
			request.requestType !== PortForwardingService.portForwardRequestType &&
			request.requestType !== PortForwardingService.cancelPortForwardRequestType
		) {
			throw new Error(`Unexpected request type: ${request.requestType}`);
		}

		const portForwardRequest = request.request.convertTo(new PortForwardRequestMessage());
		const localIPAddress = IPAddressConversions.fromSshAddress(portForwardRequest.addressToBind);

		if (
			request.requestType === PortForwardingService.portForwardRequestType &&
			portForwardRequest.port !== 0 &&
			this.localForwarders.has(portForwardRequest.port)
		) {
			const message =
				'PortForwardingService blocking attempt to re-forward ' +
				`already-forwarded port {portForwardRequest.port}.`;
			this.session.trace(
				TraceLevel.Warning,
				SshTraceEventIds.portForwardRequestInvalid,
				message,
			);
			request.isAuthorized = false;
			return;
		}

		const args = new SshRequestEventArgs<SessionRequestMessage>(
			request.requestType,
			portForwardRequest,
			this.session.principal,
		);

		await super.onSessionRequest(args, cancellation);

		let response: SshMessage | undefined;
		let localPort: number | null = null;
		if (args.isAuthorized) {
			if (request.requestType === PortForwardingService.portForwardRequestType) {
				try {
					localPort = await this.startForwarding(
						localIPAddress,
						portForwardRequest.port,
						cancellation,
					);
				} catch (e) {
					// The error is already traced.
				}
				if (localPort !== null) {
					// The chosen local port may be different from the requested port. Use the
					// requested port in the response, unless the request was for a random port.
					const forwardedPort =
						portForwardRequest.port === 0 ? localPort : portForwardRequest.port;
					const portResponse = await this.messageFactory.createSuccessMessageAsync(
						forwardedPort,
					);
					portResponse.port = forwardedPort;
					response = portResponse;
				}
			} else if (request.requestType === PortForwardingService.cancelPortForwardRequestType) {
				if (await this.cancelForwarding(portForwardRequest.port, cancellation)) {
					response = new SessionRequestSuccessMessage();
				}
			}
		}

		request.responsePromise = Promise.resolve(response ?? new SessionRequestFailureMessage());

		// Add to the collection (and raise event) after sending the response,
		// to ensure event-handlers can immediately open a channel.
		if (response instanceof PortForwardSuccessMessage) {
			const forwardedPort = new ForwardedPort(localPort ?? response.port, response.port, true);
			this.remoteForwardedPorts.addPort(forwardedPort);
		}
	}

	private async startForwarding(
		localIPAddress: string,
		remotePort: number,
		cancellation?: CancellationToken,
	): Promise<number | null> {
		if (typeof remotePort !== 'number') throw new TypeError('Remote port must be an integer.');
		if (this.acceptLocalConnectionsForForwardedPorts) {
			// The local port is initially set to the remote port, but it may change
			// when starting forwarding, if there was a conflict.
			let localPort = remotePort;

			const forwarder = new LocalPortForwarder(
				this,
				this.session,
				PortForwardingService.portForwardChannelType,
				localIPAddress,
				localPort,
				undefined,
				remotePort === 0 ? undefined : remotePort,
			);
			await forwarder.startForwarding(cancellation);
			localPort = forwarder.localPort;
			if (remotePort === 0) {
				// The other side requested a random port. Reply with the chosen port number.
				remotePort = localPort;
			}

			// The remote port is the port referenced in exchanged messages,
			// so the forwarder is indexed on that port number, rather than the local port.
			this.localForwarders.set(remotePort, forwarder);

			localPort = forwarder.localPort;
			forwarder.onDisposed(() => {
				const forwardedPort = new ForwardedPort(localPort, remotePort, true);
				this.remoteForwardedPorts.removePort(forwardedPort);
				this.localForwarders.delete(remotePort);
			});

			return localPort;
		} else if (remotePort !== 0) {
			return remotePort;
		} else {
			return null;
		}
	}

	private async cancelForwarding(
		forwardedPort: number,
		cancellation?: CancellationToken,
	): Promise<boolean> {
		const forwarder = this.localForwarders.get(forwardedPort);
		if (!forwarder) {
			return false;
		}

		this.localForwarders.delete(forwardedPort);
		forwarder.dispose();

		return true;
	}

	protected async onChannelOpening(
		request: SshChannelOpeningEventArgs,
		cancellation?: CancellationToken,
	): Promise<void> {
		if (!request) throw new TypeError('Request is required.');

		const channelType = request.request.channelType;
		if (
			channelType !== PortForwardingService.portForwardChannelType &&
			channelType !== PortForwardingService.reversePortForwardChannelType
		) {
			request.failureReason = SshChannelOpenFailureReason.unknownChannelType;
			return;
		}

		let remoteConnector: RemotePortConnector | null = null;
		const portForwardMessage =
			request.request instanceof PortForwardChannelOpenMessage
				? request.request
				: request.request.convertTo(new PortForwardChannelOpenMessage());
		if (request.isRemoteRequest) {
			if (channelType === PortForwardingService.portForwardChannelType) {
				const remoteIPAddress = IPAddressConversions.fromSshAddress(portForwardMessage.host);
				const remoteEndPoint = `${remoteIPAddress}:${portForwardMessage.port}`;
				remoteConnector = this.remoteConnectors.get(portForwardMessage.port) ?? null;
				if (!remoteConnector) {
					this.trace(
						TraceLevel.Error,
						SshTraceEventIds.portForwardRequestInvalid,
						`PortForwardingService received forwarding channel ` +
							`for ${remoteEndPoint} that was not requested.`,
					);
					request.failureReason = SshChannelOpenFailureReason.connectFailed;
					request.failureDescription = 'Forwarding channel was not requested.';
					return;
				}
			} else if (!this.acceptRemoteConnectionsForNonForwardedPorts) {
				const errorMessage = 'The session has disabled connections to non-forwarded ports.';
				this.session.trace(
					TraceLevel.Warning,
					SshTraceEventIds.portForwardChannelOpenFailed,
					errorMessage,
				);
				request.failureDescription = errorMessage;
				request.failureReason = SshChannelOpenFailureReason.administrativelyProhibited;
				return;
			}
		}

		const portForwardRequest = new SshChannelOpeningEventArgs(
			portForwardMessage,
			request.channel,
			request.isRemoteRequest,
		);
		await super.onChannelOpening(portForwardRequest, cancellation);

		request.failureReason = portForwardRequest.failureReason;
		request.failureDescription = portForwardRequest.failureDescription;
		if (request.failureReason !== SshChannelOpenFailureReason.none || !request.isRemoteRequest) {
			return;
		}

		if (remoteConnector) {
			// The forwarding was initiated by this session.
			await (<any>remoteConnector).onChannelOpening(request, cancellation);

			const localPort =
				remoteConnector instanceof RemotePortForwarder ? remoteConnector.localPort : null;
			const remotePort =
				remoteConnector instanceof RemotePortForwarder
					? remoteConnector.remotePort
					: portForwardMessage.port;
			const forwardedPort = new ForwardedPort(localPort, remotePort, false);
			this.localForwardedPorts.addChannel(forwardedPort, request.channel);
		} else {
			// THe forwarding was initiated by the remote session.
			await RemotePortForwarder.forwardChannel(
				this,
				request,
				portForwardMessage.host,
				portForwardMessage.port,
				this.trace,
				cancellation,
			);
		}
	}

	/* @internal */
	public async openChannel(
		session: SshSession,
		channelType: string,
		originatorIPAddress: string | null,
		originatorPort: number | null,
		host: string,
		port: number,
		cancellation?: CancellationToken,
	): Promise<SshChannel> {
		let forwardedPort: ForwardedPort | undefined = undefined;
		if (channelType === PortForwardingService.portForwardChannelType) {
			forwardedPort = this.remoteForwardedPorts.find(
				(p) => p.remotePort === port || (p.remotePort === null && p.localPort === port),
			);
			if (!forwardedPort) {
				throw new Error(`Port ${port} is not being forwarded.`);
			}
		}

		const openMessage = await this.messageFactory.createChannelOpenMessageAsync(port);
		openMessage.channelType = channelType;
		openMessage.originatorIPAddress = originatorIPAddress ?? '';
		openMessage.originatorPort = originatorPort ?? 0;
		openMessage.host = host;
		openMessage.port = port;

		const trace = this.session.trace;

		let channel: SshChannel;
		try {
			channel = await session.openChannel(openMessage, null, cancellation);
			trace(
				TraceLevel.Info,
				SshTraceEventIds.portForwardChannelOpened,
				`PortForwardingService opened ${channelType} channel #${channel.channelId} for ${host}:${port}.`,
			);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			trace(
				TraceLevel.Error,
				SshTraceEventIds.portForwardChannelOpenFailed,
				`PortForwardingService failed to open ${channelType} channel for ${host}:${port}: ${e.message}`,
				e,
			);
			throw e;
		}

		if (channelType === PortForwardingService.portForwardChannelType) {
			this.remoteForwardedPorts.addChannel(forwardedPort!, channel);
		}

		return channel;
	}

	public dispose(): void {
		const disposables: Disposable[] = [
			...this.channelForwarders,
			...this.localForwarders.values(),
			...this.remoteConnectors.values(),
		];

		this.channelForwarders.splice(0, this.channelForwarders.length);
		this.localForwarders.clear();
		this.remoteConnectors.clear();

		for (let disposable of disposables) {
			disposable.dispose();
		}

		super.dispose();
	}
}
