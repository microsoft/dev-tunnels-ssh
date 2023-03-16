// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Services;

/// <summary>
/// Base class for SSH services that handle incoming requests.
/// </summary>
/// <remarks>
/// Services can be on either the server side or the client side, because either side may
/// send requests to the other's services.
///
/// Service subclasses must have one or more <see cref="ServiceActivationAttribute" />s
/// applied to them to declare the type(s) of requests that cause the service to be activated.
/// Only one instance of each service type gets activated for a session, even if there are
/// multiple activation rules. After activation, a service remains active for the duration
/// of the session, handling any additional requests, until it is disposed when the session
/// is disposed.
///
/// To enable activation of a service, add the service type to
/// <see cref="SshSessionConfiguration.Services" />. When a service is activated, the session
/// raises a <see cref="SshSession.ServiceActivated" /> event.
/// </remarks>
public abstract class SshService : IDisposable
{
	private bool disposed;

	/// <summary>
	/// Creates a new instance of an SSH service for a session.
	/// </summary>
	/// <param name="session">The session that activated the service.</param>
	/// <remarks>
	/// Subclasses must provide a constructor that takes either a single <see cref="SshSession" />
	/// parameter, or a session parameter and a configuration parameter. The optional config
	/// object is passed in as a value in the <see cref="SshSessionConfiguration.Services"/>
	/// dictionary. The config object can be any type.
	/// </remarks>
	protected SshService(SshSession session)
	{
		if (session == null) throw new ArgumentNullException(nameof(session));

		Session = session;
	}

	/// <summary>
	/// Gets the session that activated this service.
	/// </summary>
	public SshSession Session { get; }

	/// <summary>
	/// Gets the session trace source.
	/// </summary>
	protected TraceSource Trace => Session.Trace;

	/// <summary>
	/// Services that are activated via session requests must override this method to handle
	/// incoming session requests.
	/// </summary>
	/// <remarks>
	/// Implementations must set <see cref="SshRequestEventArgs{T}.IsAuthorized" /> or
	/// <see cref="SshRequestEventArgs{T}.ResponseTask"/> to indicate whether the request
	/// was allowed.
	/// </remarks>
	protected internal virtual Task OnSessionRequestAsync(
		SshRequestEventArgs<SessionRequestMessage> request,
		CancellationToken cancellation)
	{
		if (request == null) throw new ArgumentNullException(nameof(request));

		Session.OnSessionRequest(request);
		return Task.CompletedTask;
	}

	/// <summary>
	/// Sends any message.
	/// </summary>
	protected async Task SendMessageAsync(SshMessage message, CancellationToken cancellation)
	{
		await Session.SendMessageAsync(message, cancellation).ConfigureAwait(false);
	}

	/// <summary>
	/// Services that are activated via channel types must override this method to handle
	/// incoming requests to open a channel.
	/// </summary>
	/// <remarks>
	/// Implementations may set <see cref="SshChannelOpeningEventArgs.FailureReason" /> or
	/// <see cref="SshChannelOpeningEventArgs.OpeningTask" /> to block opening of the channel.
	/// The default behavior allows the channel to open.
	///
	/// Requests on the opened channel will not be directed to <see cref="OnChannelRequestAsync"/>
	/// unless the service also declares activation on specific channel request(s). Otherwise,
	/// an implementation of this method may add any event-handlers to the
	/// <see cref="SshChannelOpeningEventArgs.Channel" /> including a request event handler.
	/// </remarks>
	protected internal virtual Task<ChannelMessage> OnChannelOpeningAsync(
		SshChannelOpeningEventArgs request,
		CancellationToken cancellation)
	{
		if (request == null) throw new ArgumentNullException(nameof(request));

		return Session.OnChannelOpeningAsync(request, cancellation, resolveService: false);
	}

	/// <summary>
	/// Services that are activated via channel requests must override this method to handle
	/// incoming channel requests.
	/// </summary>
	/// <remarks>
	/// Implementations must set <see cref="SshRequestEventArgs{T}.IsAuthorized" /> or
	/// <see cref="SshRequestEventArgs{T}.ResponseTask"/> to indicate whether the request
	/// was allowed.
	/// </remarks>
	protected internal virtual Task OnChannelRequestAsync(
		SshChannel channel,
		SshRequestEventArgs<ChannelRequestMessage> request,
		CancellationToken cancellation)
	{
		return Task.CompletedTask;
	}

	/// <summary>
	/// Diposes the service; called when the session is disposing.
	/// </summary>
	public void Dispose()
	{
		Dispose(true);
		GC.SuppressFinalize(this);
	}

	/// <summary>
	/// Subclasses may override this method to dispose any resources.
	/// </summary>
	/// <param name="disposing">True if managed objects are disposed.</param>
	protected virtual void Dispose(bool disposing)
	{
		if (this.disposed)
		{
			return;
		}

		this.disposed = true;
		try
		{
			Disposed?.Invoke(this, EventArgs.Empty);
		}
		catch (Exception)
		{
			// Ignore any exceptions thrown by disposed event handlers.
		}
	}

	/// <summary>
	/// Event raised when this service is disposed.
	/// </summary>
	public event EventHandler<EventArgs>? Disposed;

	/// <summary>
	/// Instantiates a service from a service type and optional configuration object.
	/// </summary>
	internal static SshService Activate(
		SshSession session,
		Type serviceType,
		object? serviceConfig)
	{
		// Construct built-in services non-dynamically (avoiding reflection).
		if (serviceType == typeof(KeyExchangeService))
		{
			return new KeyExchangeService(session);
		}
		else if (serviceType == typeof(AuthenticationService))
		{
			return new AuthenticationService(session);
		}
		else if (serviceType == typeof(ConnectionService))
		{
			return new ConnectionService(session);
		}
		else
		{
			return DynamicActivate(session, serviceType, serviceConfig);
		}
	}

	private static SshService DynamicActivate(
		SshSession session,
#if NET6_0_OR_GREATER
		[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
#endif
		Type serviceType,
		object? serviceConfig)
	{
		var constructors = serviceType.GetConstructors(BindingFlags.Public | BindingFlags.Instance);

		foreach (var constructor in constructors)
		{
			var parameters = constructor.GetParameters();
			if (serviceConfig == null &&
				parameters.Length == 1 &&
				parameters[0].ParameterType == typeof(SshSession))
			{
				var service = (SshService)constructor.Invoke(new object[] { session });
				return service;
			}
			else if (serviceConfig != null &&
				parameters.Length == 2 &&
				parameters[0].ParameterType == typeof(SshSession) &&
				parameters[1].ParameterType.IsAssignableFrom(serviceConfig.GetType()))
			{
				var service = (SshService)constructor.Invoke(
					new object[] { session, serviceConfig });
				return service;
			}
		}

		throw new MissingMethodException(
			$"SSH service type '{serviceType.Name}' must have a public constructor " +
			"that takes a SshSession parameter, optionally with a config parameter " +
			"matching the type of a provided configuration object.");
	}
}
