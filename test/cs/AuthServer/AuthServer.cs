using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Tcp;
using Microsoft.Identity.Client;

namespace Microsoft.DevTunnels.Ssh.Test;

public static class AuthServer
{
	private const string ServiceAppId = "46da2f7e-b5ef-422a-88d4-2a7f9de6a0b2";
	private const string ClientAppId = "c0df98ca-23b4-4bce-bb9f-72039b28d3a5";
	private const string ClientAppName = "SSH AAD Auth Demo";
	private static readonly string[] AADScopes = { ServiceAppId + "/.default" };

	private static readonly PublicClientApplicationOptions ClientAppOptions =
		new PublicClientApplicationOptions
	{
		LogLevel = LogLevel.Verbose,
		ClientId = ClientAppId,
		ClientName = ClientAppName,
		ClientVersion = Assembly.GetEntryAssembly()!.GetName().Version!.ToString(),
		AzureCloudInstance = AzureCloudInstance.AzurePublic,
		AadAuthorityAudience = AadAuthorityAudience.AzureAdAndPersonalMicrosoftAccount,
	};
	private static readonly IPublicClientApplication PublicClientApp =
		PublicClientApplicationBuilder.CreateWithApplicationOptions(ClientAppOptions).Build();

	private static readonly Dictionary<SshSession, Task<AuthenticationResult>> PendingAuthentications =
		new Dictionary<SshSession, Task<AuthenticationResult>>();

	public static async Task Main(string[] args)
	{
		var trace = new TraceSource(nameof(AuthServer));
		trace.Listeners.Add(new ConsoleTraceListener());
		trace.Switch.Level = SourceLevels.All;

		var server = new SshServer(SshSessionConfiguration.Default, trace);
		server.Credentials.PublicKeys.Add(SshAlgorithms.PublicKey.ECDsaSha2Nistp384.GenerateKeyPair());
		server.SessionAuthenticating += OnServerSessionAuthenticating;
		await server.AcceptSessionsAsync(2222);
	}

	private static void OnServerSessionAuthenticating(object sender, SshAuthenticatingEventArgs e)
	{
		var session = (SshServerSession)sender;

		if (e.AuthenticationType != SshAuthenticationType.ClientInteractive)
		{
			// Other auth methods are not supported in this demo.
			return;
		}

		if (e.InfoResponse == null)
		{
			e.AuthenticationTask = BeginAuthenticateUserAsync(session, e);
		}
		else if (PendingAuthentications.TryGetValue(session, out var authenticationTask))
		{
			e.AuthenticationTask = Task.Run<ClaimsPrincipal>(async () =>
			{
				var authResult = await authenticationTask;

				// The AAD token is also available on the auth result.
				Console.WriteLine();
				Console.WriteLine($"Authenticated as {authResult.Account.Username}");
				Console.WriteLine($"Tenant ID: {authResult.TenantId}");
				Console.WriteLine($"Object ID: {authResult.UniqueId}");
				Console.WriteLine();

				var usernameClaim = new Claim(ClaimTypes.Upn, authResult.Account.Username);
				return new ClaimsPrincipal(new ClaimsIdentity(new[] { usernameClaim }));
			});
		}
	}

	private static Task<ClaimsPrincipal> BeginAuthenticateUserAsync(
		SshServerSession session, SshAuthenticatingEventArgs e)
	{
		var promptCompletion = new TaskCompletionSource<ClaimsPrincipal>();
		PendingAuthentications[session] = PublicClientApp.AcquireTokenWithDeviceCode(
			 AADScopes,
			 (deviceCodeResult) =>
			 {
				 e.InfoRequest = new AuthenticationInfoRequestMessage(ClientAppName)
				 {
					 Instruction = deviceCodeResult.Message,
				 };
				 promptCompletion.TrySetResult(null);
				 return Task.CompletedTask;
			 }).ExecuteAsync(CancellationToken.None);
		return promptCompletion.Task;
	}
}
