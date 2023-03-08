// Copyright (c) Microsoft. All rights reserved.

using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Enables applications to extend port-forwarding by providing custom message subclasses
/// that may include additional properties.
/// </summary>
/// <remarks>
/// Custom message subclasses must override <see cref="SshMessage.OnRead" /> and
/// <see cref="SshMessage.OnWrite" /> to handle serialization of any additional properties.
/// </remarks>
public interface IPortForwardMessageFactory
{
	/// <summary>
	/// Creates a message for requesting to forward a port.
	/// </summary>
	/// <param name="port">The port number that is requested, or 0 if a random port is requested.
	/// (The other side may choose a different port if the requested port is in use.)</param>
	/// <returns>An instance or subclass of <see cref="PortForwardRequestMessage" />.</returns>
	Task<PortForwardRequestMessage> CreateRequestMessageAsync(int port);

	/// <summary>
	/// Creates a message for a succesful response to a port-forward request.
	/// </summary>
	/// <param name="port">The port number that was requested by the other side. This may be
	/// different from the local port that was chosen. Or if the other side requested a random
	/// port then the actual chosen port number is returned in the success message.</param>
	/// <returns>An instance or subclass of <see cref="PortForwardSuccessMessage" />.</returns>
	Task<PortForwardSuccessMessage> CreateSuccessMessageAsync(int port);

	/// <summary>
	/// Creates a message requesting to open a channel for a forwarded port.
	/// </summary>
	/// <param name="port">The port number that the channel will connect to. All channel messages
	/// use the originally requested port number, which may be different from the actual TCP socket
	/// port number if the requested port was in use at the time of the forward request.</param>
	/// <returns>An instance or subclass of <see cref="PortForwardChannelOpenMessage" />.</returns>
	Task<PortForwardChannelOpenMessage> CreateChannelOpenMessageAsync(int port);
}
