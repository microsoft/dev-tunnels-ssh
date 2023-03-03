// Copyright (c) Microsoft. All rights reserved.

using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Tcp;

internal class DefaultPortForwardMessageFactory : IPortForwardMessageFactory
{
	public Task<PortForwardRequestMessage> CreateRequestMessageAsync(int port) =>
		Task.FromResult(new PortForwardRequestMessage());
	public Task<PortForwardSuccessMessage> CreateSuccessMessageAsync(int port) =>
		Task.FromResult(new PortForwardSuccessMessage());
	public Task<PortForwardChannelOpenMessage> CreateChannelOpenMessageAsync(int port) =>
		Task.FromResult(new PortForwardChannelOpenMessage());
}
