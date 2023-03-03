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
	 * @returns An instance or subclass of `PortForwardRequestMessage`.
	 */
	createRequestMessageAsync(port: number): Promise<PortForwardRequestMessage>;

	/**
	 * Creates a message for a succesful response to a port-forward request.
	 * @returns An instance or subclass of `PortForwardSuccessMessage`.
	 */
	createSuccessMessageAsync(port: number): Promise<PortForwardSuccessMessage>;

	/**
	 * Creates a message requesting to open a channel for a forwarded port.
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
