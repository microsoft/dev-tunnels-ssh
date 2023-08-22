// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Services;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// The client side of an SSH session. Extends the base `SshSession` class
/// to support client authentication.
/// </summary>
public class SshClientSession : SshSession
{
	private TaskCompletionSource<bool>? clientAuthCompletionSource;
	private readonly Dictionary<string, TaskCompletionSource<bool>> serviceRequests;

	public SshClientSession(
		SshSessionConfiguration config,
		TraceSource trace)
		: base(config, trace)
	{
		this.serviceRequests = new Dictionary<string, TaskCompletionSource<bool>>();
	}

	/// <summary>
	/// Attempts to authenticate both the server and client.
	/// </summary>
	/// <returns>True if authentication succeeded, false if it failed.</returns>
	/// <remarks>
	/// This method must be called only after encrypting the session. It is equivalent
	/// to calling both <see cref="AuthenticateServerAsync(CancellationToken)" /> and
	/// <see cref="AuthenticateClientAsync(SshClientCredentials, CancellationToken)"/>,
	/// and waiting on both results.
	/// </remarks>
	public async Task<bool> AuthenticateAsync(
		SshClientCredentials clientCredentials,
		CancellationToken cancellation = default)
	{
		bool serverAuthenticated = await AuthenticateServerAsync(cancellation)
			.ConfigureAwait(false);
		if (!serverAuthenticated)
		{
			return false;
		}

		bool clientAuthenticated = await AuthenticateClientAsync(clientCredentials, cancellation)
			.ConfigureAwait(false);
		if (!clientAuthenticated)
		{
			return false;
		}

		return true;
	}

	/// <summary>
	/// Triggers server authentication by invoking the <see cref="SshSession.Authenticating" />
	/// event with the verified server host key.
	/// </summary>
	/// <returns>True if server host key was validated by an event listener, else false.</returns>
	/// <remarks>
	/// This method must be called only after encrypting the session. It does not wait for any
	/// further message exchange with the server, since the server host key would have already
	/// been obtained during the key-exchange.
	/// </remarks>
	public async Task<bool> AuthenticateServerAsync(
		CancellationToken cancellation = default)
	{
		var kexService = GetService<KeyExchangeService>();
		if (kexService?.HostKey == null)
		{
			throw new InvalidOperationException("Encrypt the session first.");
		}

		try
		{
			// Raise an Authenticating event that allows handlers to do verification
			// of the host key and return a principal for the server.
			Principal = await HandleAuthenticatingAsync(
				new SshAuthenticatingEventArgs(
					SshAuthenticationType.ServerPublicKey,
					publicKey: kexService.HostKey),
				cancellation).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			Trace.TraceEvent(
				TraceEventType.Error,
				SshTraceEventIds.AuthenticationException,
				ex.ToString());
			throw;
		}

		if (Principal == null)
		{
			await CloseAsync(SshDisconnectReason.HostKeyNotVerifiable)
				.ConfigureAwait(false);
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ServerAuthenticationFailed,
				$"{this} server authentication failed.");
			return false;
		}

		Trace.TraceEvent(
			TraceEventType.Verbose,
			SshTraceEventIds.SessionAuthenticated,
			$"{this} server authenticated.");
		return true;
	}

	/// <summary>
	/// Performs client authentication by sending the configured public key or
	/// password credential to the server and waiting for a response.
	/// </summary>
	/// <returns>True if authentication was successful, else false.</returns>
	/// <remarks>
	/// This method must be called only after encrypting the session.
	/// </remarks>
	public async Task<bool> AuthenticateClientAsync(
		SshClientCredentials clientCredentials,
		CancellationToken cancellation = default)
	{
		var completionSource = new TaskCompletionSource<bool>(
			TaskCreationOptions.RunContinuationsAsynchronously);
		if (cancellation.CanBeCanceled)
		{
			cancellation.Register(() => completionSource.TrySetCanceled());
			cancellation.ThrowIfCancellationRequested();
		}

		await AuthenticateClientAsync(clientCredentials, completionSource, cancellation)
			.ConfigureAwait(false);
		return await completionSource.Task.ConfigureAwait(false);
	}

	/// <summary>
	/// Performs client authentication by sending the configured public key or
	/// password credential to the server. Returns the result later via a completion source.
	/// </summary>
	/// <param name="clientCredentials">Client credentials and/or credential callbacks.</param>
	/// <param name="completion">Optional completion source that will be completed with the
	/// result of the client authentication, or with an exception if the session is disconnected
	/// before authentication completed.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <remarks>
	/// This method must be called only after encrypting the session. It waits for the
	/// authentication request message to be sent, but does not directly wait for a response.
	/// In scenarios when client authentication is non-interactive, only a single credential
	/// is used, and it is expected to be always successful in non-exceptional conditions,
	/// then this method may reduce the time required to establish a secure session by not
	/// blocking on the authentication result before sending additional messages such as
	/// channel open requests. If the authentication fails then those additional requests
	/// would likely fail also, and in that case waiting on the authentication completion
	/// may reveal the reason.
	/// </remarks>
	public async Task AuthenticateClientAsync(
		SshClientCredentials clientCredentials,
		TaskCompletionSource<bool>? completion,
		CancellationToken cancellation = default)
	{
		if (clientCredentials == null)
		{
			throw new ArgumentNullException(nameof(clientCredentials));
		}

		this.clientAuthCompletionSource = completion;

		if (cancellation.CanBeCanceled)
		{
			if (completion != null)
			{
				cancellation.Register(() => completion.TrySetCanceled());
			}

			cancellation.ThrowIfCancellationRequested();
		}

		var authService = GetService<AuthenticationService>();
		if (authService == null)
		{
			var serviceRequestMessage = new ServiceRequestMessage
			{
				ServiceName = AuthenticationService.Name,
			};
			await SendMessageAsync(serviceRequestMessage, cancellation).ConfigureAwait(false);

			// Assume the service request is accepted, without waiting for an accept message.
			// (If not, the following auth requests will fail anyway.)
			authService = ActivateService<AuthenticationService>();
		}

		await authService.AuthenticateClientAsync(clientCredentials, cancellation)
			.ConfigureAwait(false);
	}

	/// <summary>
	/// Sends a request for a service and waits for a response.
	/// </summary>
	/// <param name="serviceName">Name of the service to be requested.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>A task that completes when the service request has been accepted.</returns>
	/// <remarks>
	/// If the server does not accept the service request, it will disconnect the session.
	/// </remarks>
	public async Task RequestServiceAsync(
		string serviceName,
		CancellationToken cancellation = default)
	{
		TaskCompletionSource<bool> completion;
		bool sendRequest = false;

		lock (this.serviceRequests)
		{
			if (!this.serviceRequests.TryGetValue(serviceName, out completion!))
			{
				completion = new TaskCompletionSource<bool>();
				this.serviceRequests.Add(serviceName, completion);
				sendRequest = true;
			}
		}

		if (sendRequest)
		{
			await SendMessageAsync(
				new ServiceRequestMessage
				{
					ServiceName = serviceName,
				},
				cancellation).ConfigureAwait(false);
		}

		await completion.Task.ConfigureAwait(false);
	}

#pragma warning disable CA1801 // Remove unused parameter
	internal Task HandleMessageAsync(ServiceAcceptMessage message, CancellationToken cancellation)
#pragma warning restore CA1801 // Remove unused parameter
	{
		TaskCompletionSource<bool>? completion = null;
		lock (this.serviceRequests)
		{
			this.serviceRequests.TryGetValue(message.ServiceName ?? string.Empty, out completion);
		}

		completion?.TrySetResult(true);
		return Task.CompletedTask;
	}

	/// <summary>
	/// Handles an incoming message. Can be overridden by subclasses to handle additional
	/// message types that are registered via <see cref="SshSessionConfiguration.Messages"/>.
	/// </summary>
	protected override Task HandleMessageAsync(
		SshMessage message, CancellationToken cancellation)
	{
		return message switch
		{
			ServiceAcceptMessage m => HandleMessageAsync(m, cancellation),
			_ => base.HandleMessageAsync(message, cancellation),
		};
	}

	internal void OnAuthenticationComplete(bool isSuccess)
	{
		if (isSuccess)
		{
			Trace.TraceEvent(
				TraceEventType.Verbose,
				SshTraceEventIds.SessionAuthenticated,
				$"{this} client authenticated.");
		}
		else
		{
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ClientAuthenticationFailed,
				$"{this} client authentication failed");
		}

		this.clientAuthCompletionSource?.TrySetResult(isSuccess);
		this.clientAuthCompletionSource = null;
	}

	/// <inheritdoc/>
	public override async Task<SshChannel> OpenChannelAsync(
		ChannelOpenMessage openMessage,
		ChannelRequestMessage? initialRequest,
		CancellationToken cancellation = default)
	{
		var connectionService = GetService<ConnectionService>();
		if (connectionService == null)
		{
			// Authentication must have been skipped, meaning there was no
			// connection service request sent yet. Send it now, and assume
			// it is accepted without waiting for a response.
			await SendMessageAsync(
				new ServiceRequestMessage
				{
					ServiceName = ConnectionService.Name,
				},
				cancellation).ConfigureAwait(false);
		}

		return await base.OpenChannelAsync(openMessage, initialRequest, cancellation)
			.ConfigureAwait(false);
	}

	internal override bool OnDisconnected()
	{
		if (Reconnecting)
		{
			Reconnecting = false;
			return false;
		}

		return base.OnDisconnected();
	}

	/// <summary>
	/// Call instead of <see cref="SshSession.ConnectAsync" /> to reconnect to a prior session
	/// instead of connecting a new session.
	/// </summary>
	/// <exception cref="InvalidOperationException">Reconnect was not enabled
	/// for the session.</exception>
	/// <exception cref="SshConnectionException">There was a problem connecting to or
	/// communicating with the server; retrying may still succeed if connectivity is
	/// restored.</exception>
	/// <exception cref="SshReconnectException">Reconnect failed for some reason other than a
	/// communication issue: see the <see cref="SshReconnectException.FailureReason"/> property
	/// of the exception. Retrying is unlikely to succeed, unless the specific error condition
	/// can be addressed.</exception>
	public async Task ReconnectAsync(
		Stream stream, CancellationToken cancellation = default)
	{
		Trace.TraceEvent(
			TraceEventType.Verbose,
			SshTraceEventIds.ClientSessionStartReconnecting,
			$"{this} attempting to reconnect...");

		if (this.IsClosed)
		{
			throw new ObjectDisposedException(nameof(SshClientSession));
		}
		else if (this.IsConnected)
		{
			throw new InvalidOperationException($"{this} already connected.");
		}

		var protocol = this.Protocol;
		if (protocol == null)
		{
			throw new InvalidOperationException("The session was never previously connected.");
		}

		lock (protocol)
		{
			if (Reconnecting)
			{
				throw new InvalidOperationException($"{this} already reconnecting.");
			}

			Reconnecting = true;
		}

		try
		{
			await this.ReconnectInternalAsync(stream, cancellation).ConfigureAwait(false);
		}
		finally
		{
			Reconnecting = false;
		}
	}

	private async Task ReconnectInternalAsync(Stream stream, CancellationToken cancellation)
	{
		var previousSessionId = SessionId;
		var previousProtocolInstance = this.Protocol;
		var kexService = GetService<KeyExchangeService>();
		var previousHostKey = kexService?.HostKey;
		if (previousSessionId == null || previousProtocolInstance == null ||
			kexService == null || previousHostKey == null ||
			previousProtocolInstance!.Extensions?.ContainsKey(SshProtocolExtensionNames.SessionReconnect)
			!= true)
		{
			throw new InvalidOperationException("Reconnect was not enabled for this session.");
		}

		byte[] newSessionId;
		Buffer reconnectToken;
		try
		{
			// Reconnecting will temporarily create a new session ID.
			SessionId = null;
			await ConnectAsync(stream, cancellation).ConfigureAwait(false);

			if (SessionId == null || Algorithms == null || Algorithms.Signer == null)
			{
				throw new SshConnectionException(IsClosed ?
					"Connection lost while encrypting." : "Session is not encrypted.");
			}

			// Ensure the client is not reconnecting to a different server.
			var newHostKey = kexService.HostKey;
			if (newHostKey == null ||
				!newHostKey.GetPublicKeyBytes().Equals(previousHostKey.GetPublicKeyBytes()))
			{
				var message = "The server host key is different.";
				Trace.TraceEvent(
					TraceEventType.Warning,
					SshTraceEventIds.ClientSessionReconnectFailed,
					$"{this} reconnection failed: " + message);
				throw new SshReconnectException(
					message, SshReconnectFailureReason.DifferentServerHostKey);
			}

			newSessionId = SessionId;
			reconnectToken = CreateReconnectToken(previousSessionId, newSessionId);
		}
		catch (Exception)
		{
			// Restore the previous protocol instance so reconnect may be attempted again.
			Protocol = previousProtocolInstance;
			base.OnDisconnected();
			throw;
		}
		finally
		{
			// Restore the previous session ID and host key for the reconnected session.
			SessionId = previousSessionId;
			kexService.HostKey = previousHostKey;
		}

		var successOrFailure = await RequestAsync
			<SessionReconnectResponseMessage, SessionReconnectFailureMessage>(
			new SessionReconnectRequestMessage
			{
				RequestType = ExtensionRequestTypes.SessionReconnect,
				ClientReconnectToken = reconnectToken,
				LastReceivedSequenceNumber = previousProtocolInstance.LastIncomingSequence,
				WantReply = true,
			},
			cancellation).ConfigureAwait(false);
		if (successOrFailure.Success == null)
		{
			var failure = successOrFailure.Failure;
			var reason = failure?.ReasonCode ?? SshReconnectFailureReason.UnknownServerFailure;
			var message = failure?.Description ?? "The server rejected the reconnect request.";
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ClientSessionReconnectFailed,
				$"{this} reconnection failed: " + message);

			// Restore the previous protocol instance so reconnect may be attempted again.
			Protocol = previousProtocolInstance;
			throw new SshReconnectException(message, reason);
		}

		var response = successOrFailure.Success;
		if (!VerifyReconnectToken(previousSessionId, newSessionId, response.ServerReconnectToken))
		{
			var message = "Server's reconnect token is invalid.";
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ClientSessionReconnectFailed,
				$"{this} reconnection failed: " + message);
			throw new SshReconnectException(
				message, SshReconnectFailureReason.InvalidServerReconnectToken);
		}

		Trace.TraceEvent(
			TraceEventType.Information,
			SshTraceEventIds.ClientSessionReconnecting,
			$"{this} reconnect request was accepted by the server.");

		// Re-send lost messages.
		var messagesToResend = previousProtocolInstance.GetSentMessages(
			response.LastReceivedSequenceNumber + 1);
		if (messagesToResend == null)
		{
			var message = "Client is unable to re-send messages requested by the server.";
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.ClientSessionReconnectFailed,
				$"{this} reconnection failed: " + message);
			throw new SshReconnectException(
				message, SshReconnectFailureReason.ClientDroppedMessages);
		}

		int count = 0;
		foreach (var message in messagesToResend)
		{
			Trace.TraceEvent(
				TraceEventType.Verbose,
				SshTraceEventIds.ClientSessionReconnecting,
				$"{this} re-sending {message.GetType().Name}");
			await Protocol!.SendMessageAsync(message, cancellation).ConfigureAwait(false);
			count++;
		}

		await ContinueSendBlockedMessagesAfterReconnectAsync(cancellation).ConfigureAwait(false);

		// Now the session is fully reconnected!
		previousProtocolInstance.Dispose();

		Metrics.AddReconnection();

		Trace.TraceEvent(
			TraceEventType.Information,
			SshTraceEventIds.ClientSessionReconnecting,
			$"{this} reconnected. Re-sent {count} dropped messages.");
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			this.clientAuthCompletionSource?.TrySetException(
				new SshConnectionException("Connection closed."));
			this.clientAuthCompletionSource = null;
		}

		base.Dispose(disposing);
	}
}
