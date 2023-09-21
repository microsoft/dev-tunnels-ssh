// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.IO;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Services;

/// <summary>
/// Handles SSH protocol messages related to client authentication.
/// </summary>
[ServiceActivation(ServiceRequest = Name)]
#pragma warning disable CA1812 // Avoid Uninstantiated Internal Classes
internal class AuthenticationService : SshService
#pragma warning restore CA1812 // Avoid Uninstantiated Internal Classes
{
	public const string Name = "ssh-userauth";

	private Queue<(string Method, Func<CancellationToken, Task> Handler)>?
		clientAuthenticationMethods;
	private AuthenticationRequestMessage? currentRequestMessage;
	private int authenticationFailureCount = 0;
	private readonly CancellationTokenSource disposeCancellationSource =
		new CancellationTokenSource();

	public AuthenticationService(SshSession session)
		: base(session)
	{
		string? algorithmName = session.Algorithms?.PublicKeyAlgorithmName;
		if (algorithmName == null)
		{
			throw new InvalidOperationException("Algorithms not initialized.");
		}

		PublicKeyAlgorithmName = algorithmName;
	}

	public string PublicKeyAlgorithmName { get; }

	internal Task HandleMessageAsync(
		AuthenticationMessage message, CancellationToken cancellation)
	{
		return message switch
		{
			AuthenticationRequestMessage m => HandleMessageAsync(m, cancellation),
			AuthenticationSuccessMessage m => HandleMessageAsync(m, cancellation),
			AuthenticationFailureMessage m => HandleMessageAsync(m, cancellation),
			AuthenticationInfoRequestMessage m => HandleMessageAsync(m, cancellation),
			AuthenticationInfoResponseMessage m => HandleMessageAsync(m, cancellation),
			PublicKeyOkMessage m => Task.CompletedTask,
			_ => Task.CompletedTask, // Ignore unrecognized authentication messages.
		};
	}

	private async Task HandleMessageAsync(
		AuthenticationRequestMessage message, CancellationToken cancellation)
	{
		var methodName = message.MethodName!;
		if (!Session.Config.AuthenticationMethods.Contains(methodName))
		{
			// A failure message with enabled auth methods will be sent below.
			methodName = null;
		}

		switch (methodName)
		{
			case AuthenticationMethods.HostBased:
			case AuthenticationMethods.PublicKey:
				var publicKeyMessage = message.ConvertTo<PublicKeyRequestMessage>();
				SetCurrentRequest(publicKeyMessage);
				await HandleMessageAsync(publicKeyMessage, cancellation)
					.ConfigureAwait(false);
				break;
			case AuthenticationMethods.Password:
				var passwordMessage = message.ConvertTo<PasswordRequestMessage>();
				SetCurrentRequest(passwordMessage);
				await HandleMessageAsync(passwordMessage, cancellation)
					.ConfigureAwait(false);
				break;
			case AuthenticationMethods.KeyboardInteractive:
				SetCurrentRequest(message);
				await BeginInteractiveAuthenticationAsync(message, cancellation)
					.ConfigureAwait(false);
				break;
			case AuthenticationMethods.None:
				SetCurrentRequest(message);
				await HandleAuthenticatingAsync(
					new SshAuthenticatingEventArgs(SshAuthenticationType.ClientNone, message.Username),
					cancellation).ConfigureAwait(false);
				break;
			default:
				SetCurrentRequest(null);
				await Session.SendMessageAsync(
					new AuthenticationFailureMessage
					{
						MethodNames = Session.Config.AuthenticationMethods.ToArray(),
					},
					cancellation).ConfigureAwait(false);
				break;
		}
	}

	/// <summary>
	/// Sets the current authentication request state for the session, which affects how following
	/// authentication messages are interpreted.
	/// </summary>
	/// <param name="message">The message that began the current authentication request, or null
	/// to clear the state because the current request completed with success or failure.</param>
	private void SetCurrentRequest(AuthenticationRequestMessage? message)
	{
		this.currentRequestMessage = message;

		// Setting the message context on the protocol allows it to deserialize message numbers
		// for which the message type depends on the current authentication method.
		var protocol = Session.Protocol;
		if (protocol != null)
		{
			protocol.MessageContext = message?.MethodName;
		}
	}

	private async Task HandleMessageAsync(
		PublicKeyRequestMessage message, CancellationToken cancellation)
	{
		var algorithm = Session.Config.GetPublicKeyAlgorithm(message.KeyAlgorithmName);
		if (algorithm == null)
		{
			await HandleAuthenticationFailureAsync(
				$"Public key algorithm not supported: {message.KeyAlgorithmName}",
				cancellation).ConfigureAwait(false);
			return;
		}

		var publicKey = algorithm.CreateKeyPair();
		publicKey.SetPublicKeyBytes(message.PublicKey);

		SshAuthenticatingEventArgs args;
		if (message.MethodName == AuthenticationMethods.HostBased)
		{
			args = new SshAuthenticatingEventArgs(
				SshAuthenticationType.ClientHostBased,
				username: message.Username,
				publicKey: publicKey!,
				clientHostname: message.ClientHostname,
				clientUsername: message.ClientUsername);
		}
		else if (!message.HasSignature)
		{
			args = new SshAuthenticatingEventArgs(
				SshAuthenticationType.ClientPublicKeyQuery,
				username: message.Username,
				publicKey: publicKey!);
		}
		else
		{
			// Verify that the signature matches the public key.
			var signature = algorithm.ReadSignatureData(message.Signature);

			var sessionId = Session.SessionId;
			if (sessionId == null)
			{
				throw new InvalidOperationException("Session ID not initialized.");
			}

			var writer = new SshDataWriter();
			writer.WriteBinary(sessionId);
			writer.Write(message.PayloadWithoutSignature);
			var signedData = writer.ToBuffer();

			var verifier = algorithm.CreateVerifier(publicKey);
			var verified = verifier.Verify(signedData, signature);
			if (!verified)
			{
				await HandleAuthenticationFailureAsync(
					"Client authentication failed due to invalid signature.",
					cancellation).ConfigureAwait(false);
			}

			args = new SshAuthenticatingEventArgs(
				SshAuthenticationType.ClientPublicKey,
				username: message.Username,
				publicKey: publicKey!);
		}

		// Raise an Authenticating event that allows handlers to do additional verification
		// of the client's username and public key. Then send a response.
		await HandleAuthenticatingAsync(args, cancellation).ConfigureAwait(false);
	}

	private async Task HandleMessageAsync(
		PasswordRequestMessage message, CancellationToken cancellation)
	{
		// Raise an Authenticating event that allows handlers to do verification
		// of the client's username and password.
		var args = new SshAuthenticatingEventArgs(
			SshAuthenticationType.ClientPassword,
			username: message.Username,
			password: message.Password ?? string.Empty);
		await HandleAuthenticatingAsync(args, cancellation).ConfigureAwait(false);
	}

	private async Task BeginInteractiveAuthenticationAsync(
		AuthenticationRequestMessage message, CancellationToken cancellation)
	{
		// Raise an Authenticating event that allows the server to interactively prompt for
		// information from the client.
		var args = new SshAuthenticatingEventArgs(
			SshAuthenticationType.ClientInteractive,
			username: message.Username,
			infoRequest: null,
			infoResponse: null);
		await HandleAuthenticatingAsync(args, cancellation).ConfigureAwait(false);
	}

	private async Task HandleMessageAsync(
		AuthenticationInfoRequestMessage message, CancellationToken cancellation)
	{
		// Raise an Authenticating event that allows the client to respond to interactive prompts
		// and provide requested information to the server.
		var args = new SshAuthenticatingEventArgs(
			SshAuthenticationType.ClientInteractive,
			username: null,
			infoRequest: message,
			infoResponse: null);
		await HandleAuthenticatingAsync(args, cancellation).ConfigureAwait(false);
	}

	private async Task HandleMessageAsync(
		AuthenticationInfoResponseMessage message, CancellationToken cancellation)
	{
		// Raise an Authenticating event that allows the server to process the client's responses
		// to interactive prompts, and request further info if necessary.
		var args = new SshAuthenticatingEventArgs(
			SshAuthenticationType.ClientInteractive,
			this.currentRequestMessage?.Username,
			infoRequest: null,
			infoResponse: message,
			cancellation);
		await HandleAuthenticatingAsync(args, cancellation).ConfigureAwait(false);
	}

	private async Task HandleAuthenticatingAsync(
		SshAuthenticatingEventArgs args,
		CancellationToken cancellation)
	{
		if (this.currentRequestMessage == null)
		{
			throw new SshConnectionException(
				$"No current authentication request.",
				SshDisconnectReason.ProtocolError);
		}

		args.Cancellation = this.disposeCancellationSource.Token;

		ClaimsPrincipal? authenticatedPrincipal;
		try
		{
			authenticatedPrincipal = await Session.HandleAuthenticatingAsync(args, cancellation)
				.ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			Session.Trace.TraceEvent(
				TraceEventType.Error,
				SshTraceEventIds.AuthenticationException,
				ex.ToString());
			authenticatedPrincipal = null;
		}

		if (authenticatedPrincipal != null)
		{
			if (args.AuthenticationType == SshAuthenticationType.ClientPublicKeyQuery)
			{
				var publicKeyRequest = (PublicKeyRequestMessage)this.currentRequestMessage;
				var okMessage = new PublicKeyOkMessage
				{
					KeyAlgorithmName = publicKeyRequest.KeyAlgorithmName,
					PublicKey = publicKeyRequest.PublicKey,
				};

				SetCurrentRequest(null);
				await Session.SendMessageAsync(okMessage, cancellation).ConfigureAwait(false);
			}
			else
			{
				Session.Principal = authenticatedPrincipal;

				var serviceName = this.currentRequestMessage.ServiceName;
				if (!string.IsNullOrEmpty(serviceName))
				{
					Session.ActivateService(serviceName!);
				}

				Session.Trace.TraceEvent(
					TraceEventType.Verbose,
					SshTraceEventIds.SessionAuthenticated,
					$"{args.AuthenticationType} authentication succeeded.");

				SetCurrentRequest(null);
				await Session.SendMessageAsync(new AuthenticationSuccessMessage(), cancellation)
					.ConfigureAwait(false);

				(Session as SshServerSession)?.HandleClientAuthenticated();
			}
		}
		else if (args.AuthenticationType == SshAuthenticationType.ClientInteractive &&
			Session is SshServerSession && args.InfoRequest != null)
		{
			// Server authenticating event-handler supplied an info request.
			await Session.SendMessageAsync(args.InfoRequest, cancellation).ConfigureAwait(false);
		}
		else if (args.AuthenticationType == SshAuthenticationType.ClientInteractive &&
			Session is SshClientSession && args.InfoResponse != null)
		{
			// Client authenticating event-handler supplied an info response.
			await Session.SendMessageAsync(args.InfoResponse, cancellation).ConfigureAwait(false);
		}
		else
		{
			SetCurrentRequest(null);
			await HandleAuthenticationFailureAsync(
				$"{args.AuthenticationType} authentication failed.",
				cancellation).ConfigureAwait(false);
		}
	}

	/// <summary>
	/// Called when the rejects the client public key or password credentials.
	/// </summary>
	private async Task HandleAuthenticationFailureAsync(
		string message,
		CancellationToken cancellation)
	{
		// TODO: Move this up and skip for PK query
		this.authenticationFailureCount++;

		Session.Trace.TraceEvent(
			TraceEventType.Warning,
			SshTraceEventIds.ClientAuthenticationFailed,
			message);

		await Session.SendMessageAsync(
			new AuthenticationFailureMessage
			{
				MethodNames = Session.Config.AuthenticationMethods.ToArray(),
			},
			cancellation).ConfigureAwait(false);

		// Allow trying again with another authentication method. But prevent unlimited tries.
		if (this.authenticationFailureCount >= Session.Config.MaxClientAuthenticationAttempts)
		{
			await Session.CloseAsync(
				SshDisconnectReason.NoMoreAuthMethodsAvailable, "Authentication failed.")
				.ConfigureAwait(false);
		}
	}

	internal async Task AuthenticateClientAsync(
		SshClientCredentials credentials,
		CancellationToken cancellation)
	{
		this.clientAuthenticationMethods = new Queue<(string, Func<CancellationToken, Task>)>();
		var configuredMethods = Session.Config.AuthenticationMethods;

		if (configuredMethods.Contains(AuthenticationMethods.PublicKey))
		{
			foreach (var publicKey in credentials.PublicKeys ?? Enumerable.Empty<IKeyPair>())
			{
				if (publicKey == null)
				{
					continue;
				}

				var username = credentials.Username ?? string.Empty;
				IKeyPair? privateKey = publicKey;
				var privateKeyProvider = credentials.PrivateKeyProvider;

				this.clientAuthenticationMethods.Enqueue(
					(AuthenticationMethods.PublicKey, async (cancellation) =>
					{
						if (!privateKey.HasPrivateKey)
						{
							if (privateKeyProvider == null)
							{
								throw new InvalidOperationException("A private key provider is required.");
							}

							privateKey = await privateKeyProvider(privateKey, cancellation)
								.ConfigureAwait(false);
						}

						if (privateKey != null)
						{
							await RequestAuthenticationAsync(username, privateKey, cancellation)
								.ConfigureAwait(false);
						}
						else
						{
							await Session.CloseAsync(SshDisconnectReason.AuthCancelledByUser)
								.ConfigureAwait(false);
						}
					}));
			}
		}

		if (configuredMethods.Contains(AuthenticationMethods.Password))
		{
			var passwordCredentialProvider = credentials.PasswordProvider;
			if (passwordCredentialProvider != null)
			{
				this.clientAuthenticationMethods.Enqueue(
					(AuthenticationMethods.Password, async (cancellation) =>
					{
						var passwordCredentialTask = passwordCredentialProvider(cancellation);
						var passwordCredential = passwordCredentialTask != null
							? await passwordCredentialTask.ConfigureAwait(false) : null;
						if (passwordCredential != null)
						{
							await RequestAuthenticationAsync(
								passwordCredential.Value.Item1 ?? string.Empty,
								passwordCredential.Value.Item2,
								cancellation).ConfigureAwait(false);
						}
						else
						{
							await Session.CloseAsync(SshDisconnectReason.AuthCancelledByUser)
								.ConfigureAwait(false);
						}
					}));
			}
			else if (credentials.Password != null)
			{
				var username = credentials.Username ?? string.Empty;
				var password = credentials.Password;
				this.clientAuthenticationMethods.Enqueue(
					(AuthenticationMethods.Password, async (cancellation) =>
					{
						await RequestAuthenticationAsync(username, password, cancellation)
							.ConfigureAwait(false);
					}));
			}
		}

		// Only add None or Interactive methods if no client credentials were supplied.
		if (this.clientAuthenticationMethods.Count == 0)
		{
			var username = credentials.Username ?? string.Empty;

			if (configuredMethods.Contains(AuthenticationMethods.None))
			{
				this.clientAuthenticationMethods.Enqueue(
					(AuthenticationMethods.None, async (cancellation) =>
					{
						await RequestAuthenticationAsync(username, cancellation).ConfigureAwait(false);
					}));
			}

			if (configuredMethods.Contains(AuthenticationMethods.KeyboardInteractive))
			{
				this.clientAuthenticationMethods.Enqueue(
					(AuthenticationMethods.KeyboardInteractive, async (cancellation) =>
					{
						await RequestInteractiveAuthenticationAsync(username, cancellation)
							.ConfigureAwait(false);
					}));
			}

			if (this.clientAuthenticationMethods.Count == 0)
			{
				throw new InvalidOperationException(
					$"Could not prepare request for authentication method(s): " +
					string.Join(", ", configuredMethods) +
					". Supply client credentials or enable None or Interactive authentication methods.");
			}
		}

		// Auth request messages all include a request the for the server to activate the connection
		// service . Go ahead and activate it on the client side too; if authentication fails then
		// a following channel open request will fail anyway.
		Session.ActivateService<ConnectionService>();

		var firstAuthMethod = this.clientAuthenticationMethods.Dequeue();
		await firstAuthMethod.Handler(cancellation).ConfigureAwait(false);
	}

	private async Task RequestAuthenticationAsync(
		string username,
		CancellationToken cancellation)
	{
		var authMessage = new AuthenticationRequestMessage(
			ConnectionService.Name,
			AuthenticationMethods.None,
			username);
		SetCurrentRequest(authMessage);
		await Session.SendMessageAsync(authMessage, cancellation).ConfigureAwait(false);
	}

	private async Task RequestAuthenticationAsync(
		string username,
		IKeyPair key,
		CancellationToken cancellation)
	{
		var algorithm = Session.Config.PublicKeyAlgorithms.FirstOrDefault(
			(a) => a?.KeyAlgorithmName == key.KeyAlgorithmName);
		if (algorithm == null)
		{
			throw new InvalidOperationException(
				$"Public key algorithm '{key.KeyAlgorithmName}' is not in session config.");
		}

		var authMessage = new PublicKeyRequestMessage(
			ConnectionService.Name, username, algorithm, key);
		authMessage.Signature = CreateAuthenticationSignature(authMessage, algorithm, key);
		SetCurrentRequest(authMessage);
		await Session.SendMessageAsync(authMessage, cancellation).ConfigureAwait(false);
	}

	private async Task RequestAuthenticationAsync(
		string username,
		string? password,
		CancellationToken cancellation)
	{
		var authMessage = new PasswordRequestMessage(
			ConnectionService.Name,
			username,
			password);
		SetCurrentRequest(authMessage);
		await Session.SendMessageAsync(authMessage, cancellation).ConfigureAwait(false);
	}

	private async Task RequestInteractiveAuthenticationAsync(
		string username,
		CancellationToken cancellation)
	{
		var authMessage = new AuthenticationRequestMessage(
			ConnectionService.Name,
			AuthenticationMethods.KeyboardInteractive,
			username);
		SetCurrentRequest(authMessage);
		await Session.SendMessageAsync(authMessage, cancellation).ConfigureAwait(false);
	}

#pragma warning disable CA1801 // Remove unused parameter
	private async Task HandleMessageAsync(
		AuthenticationFailureMessage message, CancellationToken cancellation)
#pragma warning restore CA1801 // Remove unused parameter
	{
		SetCurrentRequest(null);

		while (this.clientAuthenticationMethods!.Count > 0)
		{
			var nextAuthMethod = this.clientAuthenticationMethods.Dequeue();

			// Skip client auth methods that the server did not suggest.
			if (message.MethodNames?.Contains(nextAuthMethod.Method) == true)
			{
				await nextAuthMethod.Handler(cancellation).ConfigureAwait(false);
				return;
			}
		}

		// Revert the optimistic service registration.
		Session.UnregisterService<ConnectionService>();

		((SshClientSession)Session).OnAuthenticationComplete(false);
	}

#pragma warning disable CA1801 // Remove unused parameter
	private Task HandleMessageAsync(
		AuthenticationSuccessMessage message, CancellationToken cancellation)
#pragma warning restore CA1801 // Remove unused parameter
	{
		SetCurrentRequest(null);
		((SshClientSession)Session).OnAuthenticationComplete(true);
		return Task.CompletedTask;
	}

	private Buffer CreateAuthenticationSignature(
		PublicKeyRequestMessage requestMessage,
		PublicKeyAlgorithm algorithm,
		IKeyPair key)
	{
		var sessionId = Session.SessionId;
		if (sessionId == null)
		{
			throw new InvalidOperationException("Session ID not initialized.");
		}

		var writer = new SshDataWriter();
		writer.WriteBinary(sessionId);
		writer.Write(AuthenticationRequestMessage.MessageNumber);
		writer.Write(requestMessage.Username ?? string.Empty, Encoding.UTF8);
		writer.Write(requestMessage.ServiceName ?? string.Empty, Encoding.ASCII);
		writer.Write(AuthenticationMethods.PublicKey, Encoding.ASCII);
		writer.Write(true);
		writer.Write(requestMessage.KeyAlgorithmName!, Encoding.ASCII);
		writer.WriteBinary(requestMessage.PublicKey);

		var signer = algorithm.CreateSigner(key);
		var signature = new Buffer(signer.DigestLength);
		signer.Sign(writer.ToBuffer(), signature);
		return algorithm.CreateSignatureData(signature);
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			try
			{
				disposeCancellationSource.Cancel();
				disposeCancellationSource.Dispose();
			}
			catch (ObjectDisposedException)
			{
			}
		}

		base.Dispose(disposing);
	}
}
