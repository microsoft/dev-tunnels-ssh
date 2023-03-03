// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Services;

namespace Microsoft.DevTunnels.Ssh.Tcp;

/// <summary>
/// Base class for services that receive SSH channels forwarded from a remote port.
/// </summary>
public abstract class RemotePortConnector : SshService
{
	private bool forwarding;

	internal RemotePortConnector(
		SshSession session,
		IPAddress remoteIPAddress,
		int remotePort)
		: base(session)
	{
		RemoteIPAddress = remoteIPAddress;
		RemotePort = remotePort;
	}

	/// <summary>
	/// IP address of the network interface bound by the remote listener.
	/// </summary>
	public IPAddress RemoteIPAddress { get; }

	/// <summary>
	/// Port that the remote server is listening on.
	/// </summary>
	/// <remarks>
	/// If the request specified port 0, this property returns the actual available port
	/// that was chosen by the server.
	/// </remarks>
	public int RemotePort { get; private set; }

	internal async Task<bool> RequestAsync(
		PortForwardRequestMessage request,
		CancellationToken cancellation)
	{
		if (this.forwarding)
		{
			throw new InvalidOperationException("Already forwarding.");
		}

		request.AddressToBind = IPAddressConversions.ToString(RemoteIPAddress);
		request.Port = (uint)RemotePort;

		var response = await Session.RequestAsync<PortForwardSuccessMessage>(
			request, cancellation).ConfigureAwait(false);

		bool result = false;
		if (response != null)
		{
			if (response.Port != 0)
			{
				RemotePort = (int)response.Port;
			}

			result = true;
		}

		this.forwarding = result;
		return result;
	}

	internal new abstract Task OnChannelOpeningAsync(
		SshChannelOpeningEventArgs request,
		CancellationToken cancellation);

	protected override void Dispose(bool disposing)
	{
		if (disposing && this.forwarding)
		{
			this.forwarding = false;

			var request = new PortForwardRequestMessage
			{
				RequestType = PortForwardingService.CancelPortForwardRequestType,
				AddressToBind = IPAddressConversions.ToString(RemoteIPAddress),
				Port = (uint)RemotePort,
				WantReply = false,
			};

			try
			{
				// TODO: Implement IAsyncDisposable (requires .NET Standard 2.1).
				_ = Session.RequestAsync(request, CancellationToken.None);
			}
			catch (Exception)
			{
				// Don't throw from Dispose().
				// Exception details have already been traced.
			}
		}

		base.Dispose(disposing);
	}
}
