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

	private static readonly string[] SupportedAuthMethods = new[]
	{
		AuthenticationMethods.PublicKey,
		AuthenticationMethods.Password,
		AuthenticationMethods.HostBased,
	};

	private Queue<Func<CancellationToken, Task>>? clientAuthenticationMethods;
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
			PublicKeyOkMessage => Task.CompletedTask,
			_ => Task.CompletedTask, // Ignore unrecognized authentication messages.
		};
	}

	private async Task HandleMessageAsync(
		AuthenticationRequestMessage message, CancellationToken cancellation)
	{
		switch (message.MethodName)
		{
			case AuthenticationMethods.HostBased:
			case AuthenticationMethods.PublicKey:
				await HandleMessageAsync(message.ConvertTo<PublicKeyRequestMessage>(), cancellation)
					.ConfigureAwait(false);
				break;
			case AuthenticationMethods.Password:
				await HandleMessageAsync(message.ConvertTo<PasswordRequestMessage>(), cancellation)
					.ConfigureAwait(false);
				break;
			case AuthenticationMethods.None:
				await HandleAuthenticatingAsync(
					message,
					new SshAuthenticatingEventArgs(
						SshAuthenticationType.ClientNone, message.Username),
					cancellation).ConfigureAwait(false);
				break;
			default:
				await Session.SendMessageAsync(
					new AuthenticationFailureMessage
					{
						MethodNames = SupportedAuthMethods,
					},
					cancellation).ConfigureAwait(false);
				break;
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
		await HandleAuthenticatingAsync(message, args, cancellation).ConfigureAwait(false);
	}

	private async Task HandleMessageAsync(
		PasswordRequestMessage message, CancellationToken cancellation)
	{
		// Raise an Authenticating event that allows handlers to do verification
		// of the client's username and password.
		var args = new SshAuthenticatingEventArgs(
			SshAuthenticationType.ClientPassword,
			username: message.Username!,
			password: message.Password ?? string.Empty);
		await HandleAuthenticatingAsync(message, args, cancellation)
			.ConfigureAwait(false);
	}

	private async Task HandleAuthenticatingAsync(
		AuthenticationRequestMessage requestMessage,
		SshAuthenticatingEventArgs args,
		CancellationToken cancellation)
	{
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
				var publicKeyRequest = (PublicKeyRequestMessage)requestMessage;
				var okMessage = new PublicKeyOkMessage
				{
					KeyAlgorithmName = publicKeyRequest.KeyAlgorithmName,
					PublicKey = publicKeyRequest.PublicKey,
				};
				await Session.SendMessageAsync(okMessage, cancellation).ConfigureAwait(false);
			}
			else
			{
				Session.Principal = authenticatedPrincipal;

				if (!string.IsNullOrEmpty(requestMessage.ServiceName))
				{
					Session.ActivateService(requestMessage.ServiceName!);
				}

				Session.Trace.TraceEvent(
					TraceEventType.Verbose,
					SshTraceEventIds.SessionAuthenticated,
					$"{args.AuthenticationType} authentication succeeded.");

				await Session.SendMessageAsync(new AuthenticationSuccessMessage(), cancellation)
					.ConfigureAwait(false);

				(Session as SshServerSession)?.HandleClientAuthenticated();
			}
		}
		else
		{
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
		this.authenticationFailureCount++;

		Session.Trace.TraceEvent(
			TraceEventType.Warning,
			SshTraceEventIds.ClientAuthenticationFailed,
			message);

		await Session.SendMessageAsync(
			new AuthenticationFailureMessage
			{
				MethodNames = SupportedAuthMethods,
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
		this.clientAuthenticationMethods = new Queue<Func<CancellationToken, Task>>();

		foreach (var publicKey in credentials.PublicKeys ?? Enumerable.Empty<IKeyPair>())
		{
			if (publicKey == null)
			{
				continue;
			}

			var username = credentials.Username ?? string.Empty;
			IKeyPair? privateKey = publicKey;
			var privateKeyProvider = credentials.PrivateKeyProvider;

			this.clientAuthenticationMethods.Enqueue(async (cancellation) =>
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
			});
		}

		var passwordCredentialProvider = credentials.PasswordProvider;
		if (passwordCredentialProvider != null)
		{
			this.clientAuthenticationMethods.Enqueue(async (cancellation) =>
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
			});
		}
		else if (credentials.Password != null)
		{
			var username = credentials.Username ?? string.Empty;
			var password = credentials.Password;
			this.clientAuthenticationMethods.Enqueue(async (cancellation) =>
			{
				await RequestAuthenticationAsync(username, password, cancellation)
					.ConfigureAwait(false);
			});
		}

		if (this.clientAuthenticationMethods.Count == 0)
		{
			var username = credentials.Username ?? string.Empty;
			this.clientAuthenticationMethods.Enqueue(async (cancellation) =>
			{
				await RequestAuthenticationAsync(username, cancellation).ConfigureAwait(false);
			});
		}

		var firstAuthMethod = this.clientAuthenticationMethods.Dequeue();
		await firstAuthMethod(cancellation).ConfigureAwait(false);
	}

	private async Task RequestAuthenticationAsync(
		string username,
		CancellationToken cancellation)
	{
		var authMessage = new AuthenticationRequestMessage(
			ConnectionService.Name,
			AuthenticationMethods.None,
			username);
		await Session.SendMessageAsync(authMessage, cancellation).ConfigureAwait(false);

		// Assume the included service request succeeds, without waiting for an auth success
		// message. If not, a following channel open request will fail anyway.
		Session.ActivateService<ConnectionService>();
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
		await Session.SendMessageAsync(authMessage, cancellation).ConfigureAwait(false);

		if (this.clientAuthenticationMethods!.Count == 0)
		{
			// There are no remaining auth methods. Assume the service request
			// included here succeeds, without waiting for an auth success message
			// If not, a following channel open request will fail anyway.
			Session.ActivateService<ConnectionService>();
		}
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
		await Session.SendMessageAsync(authMessage, cancellation).ConfigureAwait(false);

		// Assume the included service request succeeds, without waiting for an auth success
		// message. If not, a following channel open request will fail anyway.
		Session.ActivateService<ConnectionService>();
	}

#pragma warning disable CA1801 // Remove unused parameter
	private async Task HandleMessageAsync(
		AuthenticationFailureMessage message, CancellationToken cancellation)
#pragma warning restore CA1801 // Remove unused parameter
	{
		if (this.clientAuthenticationMethods!.Count > 0)
		{
			var nextAuthMethod = this.clientAuthenticationMethods.Dequeue();
			await nextAuthMethod(cancellation).ConfigureAwait(false);
		}
		else
		{
			// Revert the optimistic service registration.
			Session.UnregisterService<ConnectionService>();

			((SshClientSession)Session).OnAuthenticationComplete(false);
		}
	}

#pragma warning disable CA1801 // Remove unused parameter
	private Task HandleMessageAsync(
		AuthenticationSuccessMessage message, CancellationToken cancellation)
#pragma warning restore CA1801 // Remove unused parameter
	{
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
