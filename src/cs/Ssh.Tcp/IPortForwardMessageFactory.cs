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
	/// <returns>An instance or subclass of <see cref="PortForwardRequestMessage" />.</returns>
	Task<PortForwardRequestMessage> CreateRequestMessageAsync(int port);

	/// <summary>
	/// Creates a message for a succesful response to a port-forward request.
	/// </summary>
	/// <returns>An instance or subclass of <see cref="PortForwardSuccessMessage" />.</returns>
	Task<PortForwardSuccessMessage> CreateSuccessMessageAsync(int port);

	/// <summary>
	/// Creates a message requesting to open a channel for a forwarded port.
	/// </summary>
	/// <returns>An instance or subclass of <see cref="PortForwardChannelOpenMessage" />.</returns>
	Task<PortForwardChannelOpenMessage> CreateChannelOpenMessageAsync(int port);
}
