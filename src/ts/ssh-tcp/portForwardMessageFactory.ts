import { PortForwardChannelOpenMessage } from './messages/portForwardChannelOpenMessage';
import { PortForwardRequestMessage } from './messages/portForwardRequestMessage';
import { PortForwardSuccessMessage } from './messages/portForwardSuccessMessage';

/**
 * Enables applications to extend port-forwarding by providing custom message subclasses
 * that may include additional properties.
 *
 * Custom message subclasses must override `SshMessage.onRead` and `SshMessage.onWrite`
 * to handle serialization of any additional properties.
 */
export interface PortForwardMessageFactory {
	/**
	 * Creates a message for requesting to forward a port.
	 * @param port The port number that is requested, or 0 if a random port is requested.
	 * (The other side may choose a different port if the requested port is in use.)
	 * @returns An instance or subclass of `PortForwardRequestMessage`.
	 */
	createRequestMessageAsync(port: number): Promise<PortForwardRequestMessage>;

	/**
	 * Creates a message for a succesful response to a port-forward request.
	 * @param port The port number that was requested by the other side. This may be different
	 * from the local port that was chosen. Or if the other side requested a random port then
	 * the actual chosen port number is returned in the success message.
	 * @returns An instance or subclass of `PortForwardSuccessMessage`.
	 */
	createSuccessMessageAsync(port: number): Promise<PortForwardSuccessMessage>;

	/**
	 * Creates a message requesting to open a channel for a forwarded port.
	 * @param port The port number that the channel will connect to. All channel messages use
	 * the originally requested port number, which may be different from the actual TCP socket
	 * port number if the requested port was in use at the time of the forward request.
	 * @returns An instance or subclass of `PortForwardChannelOpenMessage`.
	 */
	createChannelOpenMessageAsync(port: number): Promise<PortForwardChannelOpenMessage>;
}

export class DefaultPortForwardMessageFactory {
	public createRequestMessageAsync(port: number): Promise<PortForwardRequestMessage> {
		return Promise.resolve(new PortForwardRequestMessage());
	}

	public createSuccessMessageAsync(port: number): Promise<PortForwardSuccessMessage> {
		return Promise.resolve(new PortForwardSuccessMessage());
	}

	public createChannelOpenMessageAsync(port: number): Promise<PortForwardChannelOpenMessage> {
		return Promise.resolve(new PortForwardChannelOpenMessage());
	}
}
