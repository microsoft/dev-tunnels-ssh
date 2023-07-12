// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;

namespace Microsoft.DevTunnels.Ssh.Tcp.Events;

/// <summary>
/// Tracks the list of ports that are currently being forwarded between the SSH client and server,
/// along with the set of channel connections for each forwarded port.
/// </summary>
/// <remarks>
/// Ports forwarded in either direction (client->server or server->client) are tracked in separate
/// collections. Typically within a session the forwarding is done only in one direction, though
/// the protocol supports bi-directional forwarding.
/// </remarks>
/// <seealso cref="PortForwardingService.RemoteForwardedPorts" />
/// <seealso cref="PortForwardingService.LocalForwardedPorts" />
[DebuggerDisplay("{ToString(),nq}")]
public class ForwardedPortsCollection : IReadOnlyCollection<ForwardedPort>
{
	// Concurrent dictionary allows enumerating the collection while it is concurrently modified.
	private readonly ConcurrentDictionary<ForwardedPort, ConcurrentDictionary<uint, SshChannel>>
		portChannelMap = new ();

	internal ForwardedPortsCollection()
	{
	}

	/// <inheritdoc/>
	public int Count => this.portChannelMap.Count;

	/// <inheritdoc/>
	public IEnumerator<ForwardedPort> GetEnumerator() => this.portChannelMap.Keys.GetEnumerator();

	/// <inheritdoc/>
	IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

	/// <summary>
	/// Checks whether a port is in the collection.
	/// </summary>
	public bool Contains(ForwardedPort port)
	{
		return this.portChannelMap.ContainsKey(port);
	}

	/// <summary>
	/// Gets current channels (connections) for a forwarded port.
	/// </summary>
	/// <exception cref="InvalidOperationException">The port is not in the collection.</exception>
	public IEnumerable<SshChannel> GetChannels(ForwardedPort port)
	{
		if (!this.portChannelMap.TryGetValue(port, out var channels))
		{
			throw new InvalidOperationException($"Port {port} is not in the collection.");
		}

		return channels.Values;
	}

	/// <summary>Event raised when a port is added to the collection.</summary>
	public event EventHandler<ForwardedPortEventArgs>? PortAdded;

	/// <summary>Event raised when a port in the collection is updated.</summary>
	public event EventHandler<ForwardedPortEventArgs>? PortUpdated;

	/// <summary>Event raised when a port is removed from the collection.</summary>
	public event EventHandler<ForwardedPortEventArgs>? PortRemoved;

	/// <summary>Event raised when a channel is added to the collection.</summary>
	public event EventHandler<ForwardedPortChannelEventArgs>? PortChannelAdded;

	/// <summary>Event raised when a channel is removed from the collection.</summary>
	public event EventHandler<ForwardedPortChannelEventArgs>? PortChannelRemoved;

	internal void AddOrUpdatePort(ForwardedPort port)
	{
		if (this.portChannelMap.TryAdd(port, new ConcurrentDictionary<uint, SshChannel>()))
		{
			PortAdded?.Invoke(this, new ForwardedPortEventArgs(port));
		}
		else
		{
			PortUpdated?.Invoke(this, new ForwardedPortEventArgs(port));
		}
	}

	internal void RemovePort(ForwardedPort port)
	{
		if (!this.portChannelMap.TryRemove(port, out _))
		{
			throw new InvalidOperationException($"Port {port} is not in the collection.");
		}

		PortRemoved?.Invoke(this, new ForwardedPortEventArgs(port));
	}

	internal void AddChannel(ForwardedPort port, SshChannel channel)
	{
		if (!this.portChannelMap.TryGetValue(port, out var channels))
		{
			throw new InvalidOperationException($"Port {port} is not in the collection.");
		}

		if (!channels.TryAdd(channel.ChannelId, channel))
		{
			throw new InvalidOperationException(
				$"Channel {channel.ChannelId} is already in the collection for port {port}.");
		}

		channel.Closed += (_, _) => TryRemoveChannel(port, channel);
		PortChannelAdded?.Invoke(this, new ForwardedPortChannelEventArgs(port, channel));
	}

	private void TryRemoveChannel(ForwardedPort port, SshChannel channel)
	{
		if (this.portChannelMap.TryGetValue(port, out var channels) &&
			channels.TryRemove(channel.ChannelId, out _))
		{
			PortChannelRemoved?.Invoke(this, new ForwardedPortChannelEventArgs(port, channel));
		}
	}

	public override string ToString()
	{
		return $"[{string.Join(", ", this)}]";
	}
}
