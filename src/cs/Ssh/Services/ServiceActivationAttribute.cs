// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Reflection;

namespace Microsoft.DevTunnels.Ssh.Services;

/// <summary>
/// Attribute that declares how an SSH service gets activated. One or more activation
/// attributes must be applied to subclasses of <see cref="SshService" />.
/// </summary>
[AttributeUsage(AttributeTargets.Class, AllowMultiple = true)]
public sealed class ServiceActivationAttribute : Attribute
{
	/// <summary>
	/// Activate the service when a service request is received for the specified name.
	/// </summary>
	/// <remarks>
	/// Only server-side services can be activated using a service request from the client.
	/// (Other activation methods can work in either direction.)
	/// </remarks>
	public string? ServiceRequest { get; set; }

	/// <summary>
	/// Activate the service when a session request is received for the specified request type.
	/// </summary>
	public string? SessionRequest { get; set; }

	/// <summary>
	/// Activate the service when a request is received to open a channel of the specified
	/// channel type.
	/// </summary>
	public string? ChannelType { get; set; }

	/// <summary>
	/// Activate the service when a channel request is received for the specified channel
	/// request type.
	/// </summary>
	/// <remarks>
	/// If both <see cref="ChannelType"/> and <see cref="ChannelRequest"/> are set,
	/// then the service is activated only when the specified request is received on the
	/// specified channel type.
	/// </remarks>
	public string? ChannelRequest { get; set; }

	/// <summary>
	/// Locates a service type in configuration, using a predicate to check service
	/// activation attributes.
	/// </summary>
	/// <param name="serviceConfigs">Service configuration dictionary from
	/// <see cref="SshSessionConfiguration.Services" /></param>
	/// <param name="predicate">Function to test whether a service activation attribute
	/// matches some condition.</param>
	/// <returns>Service type and service configuration object, or (null, null) if
	/// no service type satisfies the predicate.</returns>
	internal static (Type? ServiceType, object? ServiceConfig) FindService(
		IDictionary<Type, object?> serviceConfigs,
		Predicate<ServiceActivationAttribute> predicate)
	{
		foreach (var serviceTypeAndConfig in serviceConfigs)
		{
			var activationAttributes = serviceTypeAndConfig.Key
				.GetCustomAttributes<ServiceActivationAttribute>();

			bool foundAttribute = false;
			foreach (var activationAttribute in activationAttributes)
			{
				foundAttribute = true;
				if (predicate(activationAttribute))
				{
					return (serviceTypeAndConfig.Key, serviceTypeAndConfig.Value);
				}
			}

			if (!foundAttribute)
			{
				throw new MissingMethodException(
					$"SSH service type '{serviceTypeAndConfig.Key.Name}' must have one or more " +
					$"{nameof(ServiceActivationAttribute)}s.");
			}
		}

		return (null, null);
	}
}
