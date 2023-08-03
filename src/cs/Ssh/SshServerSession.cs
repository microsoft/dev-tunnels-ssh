// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Services;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// The server side of an SSH session. Extends the base `SshSession` class
/// to support host authentication.
/// </summary>
public class SshServerSession : SshSession
{
	private readonly ICollection<SshServerSession>? reconnectableSessions;

	/// <summary>
	/// Constructs a new server session.
	/// </summary>
	/// <param name="config">Session configuration.</param>
	/// <param name="trace">Trace source for the session.</param>
	public SshServerSession(
		SshSessionConfiguration config,
		TraceSource trace)
		: this(config, reconnectableSessions: null, trace)
	{
	}

	/// <summary>
	/// Constructs a new server session that is optionally capable of reconnecting.
	/// </summary>
	/// <param name="config">Session configuration.</param>
	/// <param name="reconnectableSessions">Collection that tracks server sessions
	/// available for reconnection.</param>
	/// <param name="trace">Trace source for the session.</param>
	public SshServerSession(
		SshSessionConfiguration config,
		ICollection<SshServerSession>? reconnectableSessions,
		TraceSource trace)
		: base(config, trace)
	{
		if (config == null) throw new ArgumentNullException(nameof(config));

		bool enableReconnect = config.ProtocolExtensions.Contains(
			SshProtocolExtensionNames.SessionReconnect);
		if (enableReconnect && reconnectableSessions == null)
		{
			throw new ArgumentException(
				"When reconnect is enabled, server sessions require a reference to a " +
					"shared collection to track reconnectable sessions.",
				nameof(reconnectableSessions));
		}
		else if (!enableReconnect && reconnectableSessions != null)
		{
			throw new ArgumentException(
				"When reconnect is not enabled, the reconnectable sessions collection " +
					"is not applicable.",
				nameof(reconnectableSessions));
		}

		this.reconnectableSessions = reconnectableSessions;
	}

	/// <summary>
	/// Gets or sets credentials and/or credential callbacks for authenticating the session.
	/// </summary>
	public SshServerCredentials Credentials { get; set; } = new SshServerCredentials();

	/// <summary>
	/// Event raised after the server has successfully authenticated the client.
	/// </summary>
	/// <remarks>
	/// This event may be used to trigger a server-initiated action after the client
	/// has authenticated.
	/// </remarks>
	public event EventHandler<EventArgs>? ClientAuthenticated;

	/// <summary>
	/// Event raised when the server session is reconnected.
	/// </summary>
	public event EventHandler<EventArgs>? Reconnected;

	/// <summary>
	/// Handles an incoming message. Can be overridden by subclasses to handle additional
	/// message types that are registered via <see cref="SshSessionConfiguration.Messages"/>.
	/// </summary>
	protected override Task HandleMessageAsync(
		SshMessage message, CancellationToken cancellation)
	{
		return message switch
		{
			ServiceRequestMessage m => HandleMessageAsync(m, cancellation),
			SessionRequestMessage m => HandleMessageAsync(m, cancellation),
			_ => base.HandleMessageAsync(message, cancellation),
		};
	}

	private async Task HandleMessageAsync(
		ServiceRequestMessage message, CancellationToken cancellation)
	{
		var service = ActivateService(message.ServiceName ?? string.Empty);
		if (service != null)
		{
			await SendMessageAsync(
				new ServiceAcceptMessage
				{
					ServiceName = message.ServiceName,
				},
				cancellation).ConfigureAwait(false);
		}
		else
		{
			throw new SshConnectionException(
				$"Service \"{message.ServiceName}\" not available.",
				SshDisconnectReason.ServiceNotAvailable);
		}
	}

	/// <summary>
	/// Handles server-specific session requests.
	/// </summary>
	internal override async Task HandleMessageAsync(
		SessionRequestMessage message, CancellationToken cancellation)
	{
		if (message.RequestType == ExtensionRequestTypes.SessionReconnect &&
			this.Config.ProtocolExtensions.Contains(SshProtocolExtensionNames.SessionReconnect))
		{
			var reconnectRequest = message.ConvertTo<SessionReconnectRequestMessage>();
			await this.ReconnectAsync(reconnectRequest, cancellation).ConfigureAwait(false);

			// ReconnectAsync() handles sending the response message.
			return;
		}

		await base.HandleMessageAsync(message, cancellation).ConfigureAwait(false);
	}

	/// <summary>
	/// Raises the ClientAuthenticated event.
	/// </summary>
	internal void HandleClientAuthenticated()
	{
		ClientAuthenticated?.Invoke(this, EventArgs.Empty);
	}

	/// <summary>
	/// Adds this session to the list of server sessions that are available
	/// for reconnection.
	/// </summary>
	internal override async Task EnableReconnectAsync(CancellationToken cancellation)
	{
		await base.EnableReconnectAsync(cancellation).ConfigureAwait(false);

		lock (this.reconnectableSessions!)
		{
			if (!this.reconnectableSessions.Contains(this))
			{
				this.reconnectableSessions.Add(this);
			}
		}
	}

	internal override bool OnDisconnected()
	{
		if (Reconnecting)
		{
			// Prevent closing the session while reconnecting.
			return true;
		}

		return base.OnDisconnected();
	}

	/// <summary>
	/// Attempts to reconnect the client to a disconnected server session.
	/// </summary>
	/// <remarks>
	/// If reconnection is successful, the current server session is disposed because the client
	/// gets reconnected to a different server session.
	/// </remarks>
	internal async Task ReconnectAsync(
		SessionReconnectRequestMessage reconnectRequest, CancellationToken cancellation)
	{
		if (this.reconnectableSessions == null)
		{
			throw new InvalidOperationException("Disconnected sessions collection " +
				"should have been initialized when reconnect is enabled.");
		}

		// Try to find the requested server session in the list of available disconnected
		// server sessions, by validating the reconnect token.
		SshServerSession? reconnectSession = null;
		lock (this.reconnectableSessions)
		{
			foreach (var reconnectableSession in this.reconnectableSessions)
			{
				if (reconnectableSession != this && VerifyReconnectToken(
					reconnectableSession.SessionId!,
					SessionId!,
					reconnectRequest.ClientReconnectToken))
				{
					reconnectSession = reconnectableSession;
					this.reconnectableSessions.Remove(reconnectSession);
					break;
				}
			}
		}

		if (reconnectSession == null || reconnectSession.IsClosed)
		{
			var message = "Requested reconnect session was not found " +
				"or the client's reconnect token was invalid.";
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ServerSessionReconnectFailed,
				$"{this} reconnect rejected: " + message);
			await SendMessageAsync(
				new SessionReconnectFailureMessage
				{
					ReasonCode = SshReconnectFailureReason.SessionNotFound,
					Description = message,
				},
				cancellation).ConfigureAwait(false);
			return;
		}

		var messagesToResend = reconnectSession.Protocol!.GetSentMessages(
			reconnectRequest.LastReceivedSequenceNumber + 1);
		if (messagesToResend == null)
		{
			// Messages are not available from requested sequence number.
			// Restore the current session protocol and put the old session back in the collection.
			lock (this.reconnectableSessions)
			{
				this.reconnectableSessions.Add(reconnectSession);
			}

			var message = "Server is unable to re-send messages requested by the client.";
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ServerSessionReconnectFailed,
				$"{this} reconnect rejected: " + message);
			await SendMessageAsync(
				new SessionReconnectFailureMessage
				{
					ReasonCode = SshReconnectFailureReason.ServerDroppedMessages,
					Description = message,
				},
				cancellation).ConfigureAwait(false);
			return;
		}

		var reconnectToken = CreateReconnectToken(reconnectSession.SessionId!, SessionId!);
		await SendMessageAsync(
			new SessionReconnectResponseMessage
			{
				ServerReconnectToken = reconnectToken,
				LastReceivedSequenceNumber = reconnectSession.Protocol!.LastIncomingSequence,
			},
			cancellation).ConfigureAwait(false);

		try
		{
			reconnectSession.Reconnecting = true;

			// Ensure the old connection is disconnected before switching over to the new one.
			reconnectSession.Protocol.Dispose();
			while (reconnectSession.IsConnected)
			{
				await Task.Delay(5, cancellation).ConfigureAwait(false);
			}

			// Move this session's protocol instance over to the reconnected session.
			reconnectSession.Protocol = Protocol;
			reconnectSession.Protocol!.KeyExchangeService =
				reconnectSession.GetService<KeyExchangeService>();
			reconnectSession.Protocol!.TraceChannelData = reconnectSession.Config.TraceChannelData;
			Protocol = null;

			// Re-send the lost messages that the client requested.
			foreach (var message in messagesToResend)
			{
				await reconnectSession.Protocol.SendMessageAsync(message, cancellation)
					.ConfigureAwait(false);
			}

			// Now this server session is invalid because the client reconnected to another one.
			Dispose(new SshConnectionException("Reconnected.", SshDisconnectReason.None));
		}
		finally
		{
			reconnectSession.Reconnecting = false;
		}

		lock (this.reconnectableSessions)
		{
			this.reconnectableSessions.Add(reconnectSession);
		}

		reconnectSession.Metrics.AddReconnection();

		// Restart the message loop for the reconnected session.
		reconnectSession.ProcessMessages();

		Trace.TraceEvent(
			TraceEventType.Information,
			SshTraceEventIds.ServerSessionReconnecting,
			$"{this} reconnected {reconnectSession}. Re-sent {messagesToResend.Count} dropped messages.");

		// Notify event listeners about the successful reconnection.
		reconnectSession.Reconnected?.Invoke(reconnectSession, EventArgs.Empty);
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			if (this.reconnectableSessions != null)
			{
				lock (this.reconnectableSessions)
				{
					this.reconnectableSessions.Remove(this);
				}
			}
		}

		base.Dispose(disposing);
	}
}
