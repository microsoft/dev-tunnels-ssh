using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Keys;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Tcp;
using Xunit;

namespace Microsoft.DevTunnels.Ssh.Test;

public class InteropTests
{
	private static readonly TraceSource TestTS = new TraceSource(nameof(SessionTests));
	private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

	private const string TestUsername = "testuser";
	private const string TestCommand = "testcommand";

	private readonly IKeyPair serverRsaKey;
	private readonly IKeyPair clientRsaKey;

	private readonly Lazy<int> testPort = new Lazy<int>(() => GetAvailableLocalTcpPort());

	private int TestPort => this.testPort.Value;

	private readonly Lazy<int> jumpPort = new Lazy<int>(() => GetAvailableLocalTcpPort());

	private int JumpPort => this.jumpPort.Value;

	private string SshTsCli => Path.Combine(
		GetRepoRoot(),
		@"out\lib\ssh-test\cli.js".Replace('\\', Path.DirectorySeparatorChar));

	public InteropTests()
	{
		TestTS.Switch.Level = SourceLevels.All;
		////TestTS.Listeners.Add(new TextWriterTraceListener(Console.Out));

		this.clientRsaKey = SshAlgorithms.PublicKey.RsaWithSha512.GenerateKeyPair();
		this.serverRsaKey = SshAlgorithms.PublicKey.RsaWithSha512.GenerateKeyPair();
	}

	/// <summary>
	/// Starts an ssh server using the library, then launches an external ssh client
	/// and validates that the client can connect, encrypt and authenticate the session,
	/// and send a command.
	/// </summary>
	/// <remarks>
	/// This test case will be skipped on Windows if ssh.exe is not found.
	/// </remarks>
	[SkippableTheory(typeof(PlatformNotSupportedException))]
	[InlineData("diffie-hellman-group14-sha256", Rsa.RsaWithSha512, "hmac-sha2-512")]
	[InlineData("diffie-hellman-group16-sha512", Rsa.RsaWithSha512, "hmac-sha2-512-etm@openssh.com")]
	[InlineData("diffie-hellman-group14-sha256", ECDsa.ECDsaSha2Nistp384, "hmac-sha2-512")]
	[InlineData("diffie-hellman-group14-sha256", ECDsa.ECDsaSha2Nistp521, "hmac-sha2-512")]
#if SSH_ENABLE_ECDH
	[InlineData("ecdh-sha2-nistp384", ECDsa.ECDsaSha2Nistp384, "hmac-sha2-512")]
	[InlineData("ecdh-sha2-nistp521", ECDsa.ECDsaSha2Nistp521, "hmac-sha2-512-etm@openssh.com")]
#endif
	public Task InteropWithSshClientTool(string kexAlg, string pkAlg, string hmacAlg)
	{
		return InteropWithSshClient(FindSshExePath("ssh"), string.Empty, kexAlg, pkAlg, hmacAlg);
	}

	/// <summary>
	/// Starts an ssh server using the library, then launches an external ssh client
	/// using the SSH TS lib and validates that the client can connect, encrypt and
	/// authenticate the session, and send a command.
	/// </summary>
	[SkippableTheory(typeof(PlatformNotSupportedException))]
	[InlineData("diffie-hellman-group14-sha256", ECDsa.ECDsaSha2Nistp521, "hmac-sha2-512", false)]
	[InlineData("diffie-hellman-group14-sha256", Rsa.RsaWithSha512, "hmac-sha2-512", true)]
	[InlineData("diffie-hellman-group16-sha512", Rsa.RsaWithSha512, "hmac-sha2-512-etm@openssh.com", false)]
	[InlineData("diffie-hellman-group16-sha512", Rsa.RsaWithSha512, "hmac-sha2-512-etm@openssh.com", true)]
	public Task InteropWithSshClientTSLib(string kexAlg, string pkAlg, string hmacAlg, bool reconnect)
	{
		return InteropWithSshClient("node", $"\"{SshTsCli}\" ssh ", kexAlg, pkAlg, hmacAlg, reconnect);
	}

	private async Task InteropWithSshClient(
		string exePath,
		string prefixArgs,
		string kexAlgorithmName,
		string publicKeyAlgorithmName,
		string hmacAlgorithmName,
		bool reconnect = false)
	{
		var config = new SshSessionConfiguration();
#if SSH_ENABLE_ECDH
		config.KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.EcdhNistp521);
#endif
		config.PublicKeyAlgorithms.Add(SshAlgorithms.PublicKey.ECDsaSha2Nistp521);

		var kexAlgorithm = config.KeyExchangeAlgorithms.Single((a) => a?.Name == kexAlgorithmName);
		config.KeyExchangeAlgorithms.Clear();
		config.KeyExchangeAlgorithms.Add(kexAlgorithm);

		var pkAlgorithm = config.PublicKeyAlgorithms.Single((a) => a?.Name == publicKeyAlgorithmName);
		config.PublicKeyAlgorithms.Clear();
		config.PublicKeyAlgorithms.Add(pkAlgorithm);
		var clientKey = pkAlgorithm is Rsa ? this.clientRsaKey : pkAlgorithm.GenerateKeyPair();
		var serverKey = pkAlgorithm is Rsa ? this.serverRsaKey : pkAlgorithm.GenerateKeyPair();

		var hmacAlgorithm = config.HmacAlgorithms.Single((a) => a?.Name == hmacAlgorithmName);
		config.HmacAlgorithms.Clear();
		config.HmacAlgorithms.Add(hmacAlgorithm);

		if (reconnect)
		{
			config.ProtocolExtensions.Add(SshProtocolExtensionNames.SessionReconnect);
			config.ProtocolExtensions.Add(SshProtocolExtensionNames.SessionLatency);
		}

#if SSH_ENABLE_AESGCM
		// Enable AES-GCM for a subset of test cases. Not all, to keep coverage of HMAC algs.
		if (publicKeyAlgorithmName.StartsWith("ecdsa-"))
		{
			config.EncryptionAlgorithms.Clear();
			config.EncryptionAlgorithms.Add(SshAlgorithms.Encryption.Aes256Gcm);
		}
#endif

		var server = new SshServer(config, TestTS);
		server.Credentials = new[] { serverKey };
		server.ExceptionRasied += (sender, ex) => { Assert.Null(ex); };
		var serverTask = server.AcceptSessionsAsync(TestPort);

		Process sshProcess = null;
		string clientKeyFile = Path.GetTempFileName();
		string knownHostsFile = Path.GetTempFileName();

		try
		{
			var authenticateCompletion = new TaskCompletionSource<bool>();
			var requestCompletion = new TaskCompletionSource<CommandRequestMessage>();
			var disconnectCompletion = new TaskCompletionSource<bool>();
			var reconnectCompletion = new TaskCompletionSource<bool>();
			bool isFirstSession = true;

			SshServerSession session = null;
			server.SessionOpened += (_, s) =>
			{
				if (isFirstSession)
				{
					isFirstSession = false;
				}
				else
				{
						// Ignore reconnecting (non-first) server sessions.
						return;
				}

				session = s;
				session.Closed += (__, e) =>
				{
					if (e.Exception != null)
					{
						authenticateCompletion.TrySetException(e.Exception);
						requestCompletion.TrySetException(e.Exception);
						disconnectCompletion.TrySetException(e.Exception);
						reconnectCompletion.TrySetException(e.Exception);
					}
					else
					{
						disconnectCompletion.TrySetResult(false);
						reconnectCompletion.TrySetResult(false);
					}
				};

				session.Disconnected += (_, e) =>
				{
					disconnectCompletion.TrySetResult(true);
				};
				session.Reconnected += (_, e) =>
				{
					reconnectCompletion.TrySetResult(true);
				};
			};

			server.SessionAuthenticating += (s, e) =>
			{
				var session = s as SshSession;
				if (session == null || !session.RemoteIPAddress.ToString().Contains("127.0.0.1"))
				{
					return;
				}

				if (e.AuthenticationType == SshAuthenticationType.ClientPublicKey)
				{
					if (e.PublicKey.GetPublicKeyBytes().Equals(clientKey.GetPublicKeyBytes()))
					{
						e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
						authenticateCompletion.TrySetResult(true);
					}
					else
					{
						authenticateCompletion.TrySetResult(false);
					}
				}
			};
			server.ChannelRequest += (___, e) =>
			{
				if (e.RequestType == ChannelRequestTypes.Command)
				{
					var request = e.Request.ConvertTo<CommandRequestMessage>();
					requestCompletion.TrySetResult(request);
					e.IsAuthorized = true;
				}
			};

			KeyPair.ExportPrivateKeyFile(clientKey, clientKeyFile, null, KeyFormat.Pkcs1);

			string keyAlg = serverKey.KeyAlgorithmName;
			var serverPublicKey = serverKey.GetPublicKeyBytes();
			File.WriteAllText(
				knownHostsFile,
				$"[localhost]:{TestPort} {keyAlg} {serverPublicKey.ToBase64()}\n");

			var processOutput = new StringBuilder();
			string args =
				prefixArgs +
				$" -v" +
				$" -o \"IdentityFile={clientKeyFile}\"" +
				$" -o \"UserKnownHostsFile={knownHostsFile}\"" +
				(reconnect ? $" -o \"Reconnect=true\"" : string.Empty) +
				$" -p {TestPort}" +
				$" -l {TestUsername}" +
				$" localhost {TestCommand}";
			TestTS.TraceInformation($"{exePath} {args}");
			processOutput.AppendLine($"{exePath} {args}");

			var startInfo = new ProcessStartInfo(exePath, args)
			{
				RedirectStandardOutput = true,
				RedirectStandardError = true,
			};

			DataReceivedEventHandler dataReceivedHandler = (sender, e) =>
			{
				if (e.Data != null)
				{
					processOutput.AppendLine(e.Data);
					TestTS.TraceEvent(TraceEventType.Verbose, 0, e.Data);
				}
			};

			sshProcess = Process.Start(startInfo);
			sshProcess.OutputDataReceived += dataReceivedHandler;
			sshProcess.ErrorDataReceived += dataReceivedHandler;
			sshProcess.BeginOutputReadLine();
			sshProcess.BeginErrorReadLine();

			try
			{
				bool authenticated = await authenticateCompletion.Task.WithTimeout(Timeout);
				Assert.True(authenticated);

				var commandRequest = await requestCompletion.Task.WithTimeout(Timeout);
				Assert.NotNull(commandRequest);
				Assert.Equal(TestCommand, commandRequest.Command);

				if (reconnect)
				{
					Assert.True(await disconnectCompletion.Task.WithTimeout(Timeout));
					Assert.True(await reconnectCompletion.Task.WithTimeout(Timeout));

					Assert.Equal(1, session.Metrics.Reconnections);
					Assert.NotEqual(0, session.Metrics.LatencyMinMs);
					Assert.NotEqual(0, session.Metrics.LatencyAverageMs);
					Assert.NotEqual(0, session.Metrics.LatencyMaxMs);
				}
			}
			catch (Exception ex)
			{
				throw new Exception(
					ex.Message + "\nssh process output follows:\n" + processOutput, ex);
			}

			sshProcess.OutputDataReceived -= dataReceivedHandler;
			sshProcess.ErrorDataReceived -= dataReceivedHandler;
		}
		finally
		{
			if (sshProcess != null && !sshProcess.HasExited) sshProcess.Kill();
			File.Delete(clientKeyFile);
			File.Delete(knownHostsFile);

			server.Dispose();
			serverTask.WithTimeout(Timeout).Wait();
		}
	}

	/// <summary>
	/// Launches an external sshd server, then connects to it using the library and
	/// validates that the client can connect, encrypt, and authenticate the session.
	/// </summary>
	/// <remarks>
	/// This test case will be skipped on Windows if sshd.exe is not found.
	/// </remarks>
	[SkippableTheory(typeof(PlatformNotSupportedException))]
	[InlineData("diffie-hellman-group14-sha256", Rsa.RsaWithSha512, "hmac-sha2-512")]
	[InlineData("diffie-hellman-group16-sha512", Rsa.RsaWithSha512, "hmac-sha2-512-etm@openssh.com")]
	[InlineData("diffie-hellman-group14-sha256", ECDsa.ECDsaSha2Nistp384, "hmac-sha2-512")]
	[InlineData("diffie-hellman-group14-sha256", ECDsa.ECDsaSha2Nistp521, "hmac-sha2-512")]
#if SSH_ENABLE_ECDH
	[InlineData("ecdh-sha2-nistp384", ECDsa.ECDsaSha2Nistp384, "hmac-sha2-512")]
	[InlineData("ecdh-sha2-nistp521", ECDsa.ECDsaSha2Nistp521, "hmac-sha2-512-etm@openssh.com")]
#endif
	public Task InteropWithSshServerTool(string kexAlg, string pkAlg, string hmacAlg)
	{
		return InteropWithSshServer(FindSshExePath("sshd"), string.Empty, kexAlg, pkAlg, hmacAlg);
	}

	/// <summary>
	/// Launches an external server using the TS SSH lib, then connects to it using this library
	/// and validates that the client can connect, encrypt, and authenticate the session.
	/// </summary>
	/// <param name="reconnect">True to test interop of the session reconnect protocol.</param>
	[Theory]
	[InlineData("diffie-hellman-group14-sha256", ECDsa.ECDsaSha2Nistp521, "hmac-sha2-512", false)]
	[InlineData("diffie-hellman-group14-sha256", Rsa.RsaWithSha512, "hmac-sha2-512", true)]
	[InlineData("diffie-hellman-group16-sha512", Rsa.RsaWithSha512, "hmac-sha2-512-etm@openssh.com", false)]
	[InlineData("diffie-hellman-group16-sha512", Rsa.RsaWithSha512, "hmac-sha2-512-etm@openssh.com", true)]
#if SSH_ENABLE_ECDH
	[InlineData("ecdh-sha2-nistp384", ECDsa.ECDsaSha2Nistp384, "hmac-sha2-512", false)]
	[InlineData("ecdh-sha2-nistp521", ECDsa.ECDsaSha2Nistp521, "hmac-sha2-512-etm@openssh.com", true)]
#endif
	public Task InteropWithSshServerTSLib(string kexAlg, string pkAlg, string hmacAlg, bool reconnect)
	{
		return InteropWithSshServer("node", $"\"{SshTsCli}\" sshd ", kexAlg, pkAlg, hmacAlg, reconnect);
	}

	private async Task InteropWithSshServer(
		string exePath,
		string prefixArgs,
		string kexAlgorithmName,
		string publicKeyAlgorithmName,
		string hmacAlgorithmName,
		bool reconnect = false)
	{
		SshSessionConfiguration config;
		PublicKeyAlgorithm pkAlgorithm;
		InitializeSshConfiguration(kexAlgorithmName,
			publicKeyAlgorithmName,
			hmacAlgorithmName,
			reconnect,
			out config,
			out pkAlgorithm);
		var clientKey = pkAlgorithm is Rsa ? this.clientRsaKey : pkAlgorithm.GenerateKeyPair();
		var serverKey = pkAlgorithm is Rsa ? this.serverRsaKey : pkAlgorithm.GenerateKeyPair();

		var client = new DisconnectableSshClient(config, TestTS);

		Process sshdProcess = null;
		string configFile = Path.GetTempFileName();
		string hostKeyFile = Path.GetTempFileName();
		string pidFile = Path.GetTempFileName();
		string authorizedKeysFile = Path.GetTempFileName();

		var processOutput = new StringBuilder();
		try
		{
			KeyPair.ExportPrivateKeyFile(serverKey, hostKeyFile, null, KeyFormat.Pkcs1);
			KeyPair.ExportPublicKeyFile(clientKey, authorizedKeysFile, KeyFormat.Ssh);

			string args =
				prefixArgs +
				$" -D" + // Do not detach
				$" -e" + // Log to stderr
				$" -o \"LogLevel=VERBOSE\"" +
				$" -p {TestPort}" +
				$" -f \"{configFile}\"" +
				$" -o \"AuthorizedKeysFile={authorizedKeysFile}\"" +
				$" -o \"PidFile={pidFile}\"" +
				$" -o \"HostKey={hostKeyFile}\"";
			TestTS.TraceInformation($"{exePath} {args}");
			processOutput.AppendLine($"{exePath} {args}");

			var startInfo = new ProcessStartInfo(exePath, args)
			{
				RedirectStandardOutput = true,
				RedirectStandardError = true,
			};

			DataReceivedEventHandler dataReceivedHandler = (sender, e) =>
			{
				if (e.Data != null)
				{
					processOutput.AppendLine(e.Data);
					TestTS.TraceEvent(TraceEventType.Verbose, 0, e.Data);
				}
			};

			sshdProcess = Process.Start(startInfo);
			sshdProcess.OutputDataReceived += dataReceivedHandler;
			sshdProcess.ErrorDataReceived += dataReceivedHandler;
			sshdProcess.BeginOutputReadLine();
			sshdProcess.BeginErrorReadLine();

			SshClientSession session = null;
			for (int i = 0; session == null; i++)
			{
				try
				{
					session = await client.OpenSessionAsync(
						IPAddress.Loopback.ToString(), TestPort).WithTimeout(Timeout);
				}
				catch (Exception ex) when (ex is SocketException ||
					(ex is SshConnectionException ce &&
					ce.DisconnectReason == SshDisconnectReason.ConnectionLost) ||
					ex.Message.Contains("connection", StringComparison.OrdinalIgnoreCase))
				{
					if (i >= 9) throw;

					// The server probably isn't listening yet. Wait a bit and try again.
					await Task.Delay(200 * (i + 1));
				}
			}

			session.Authenticating += (s, e) =>
			{
				var session = s as SshSession;
				if (session == null || !session.RemoteIPAddress.ToString().Contains("127.0.0.1"))
				{
					return;
				}

				if (e.AuthenticationType == SshAuthenticationType.ServerPublicKey &&
					e.PublicKey.GetPublicKeyBytes().Equals(serverKey.GetPublicKeyBytes()))
				{
					e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
				}
			};

			bool serverAuthenticated = await session.AuthenticateServerAsync().WithTimeout(Timeout);
			Assert.True(serverAuthenticated);
			bool clientAuthenticated = await session.AuthenticateClientAsync(
				new SshClientCredentials(Environment.UserName, clientKey)).WithTimeout(Timeout);
			Assert.True(clientAuthenticated);

			await ForwardPortToServer(session);
			await ForwardPortFromServer(session);

			if (reconnect)
			{
				await ReconnectToServer(client);

				Assert.Equal(1, session.Metrics.Reconnections);
				Assert.NotEqual(0, session.Metrics.LatencyMinMs);
				Assert.NotEqual(0, session.Metrics.LatencyAverageMs);
				Assert.NotEqual(0, session.Metrics.LatencyMaxMs);
			}
		}
		catch (Exception ex)
		{
			throw new Exception(
				ex.Message + "\nsshd process output follows:\n" + processOutput, ex);
		}
		finally
		{
			client.Dispose();

			if (sshdProcess != null && !sshdProcess.HasExited)
			{
				sshdProcess.Kill();
				sshdProcess.WaitForExit(5000);
				Assert.True(sshdProcess.HasExited);
			}

			File.Delete(hostKeyFile);
			File.Delete(configFile);
			File.Delete(pidFile);
			File.Delete(authorizedKeysFile);
		}
	}

	/// <summary>
	/// Starts an ssh server using the library, and another sshd service
	/// and uses the VSSsh server as jump host to connect to sshd.
	/// </summary>
	/// <remarks>
	/// This test case will be skipped on Windows if ssh.exe is not found.
	/// </remarks>
	[SkippableFact(typeof(PlatformNotSupportedException))]
	public void InteropJumpHostTest()
	{
		InteropJumpHost(FindSshExePath("ssh"), FindSshExePath("sshd"));
	}

	private void InteropJumpHost(
		string sshExePath,
		string sshdExePath)
	{
		SshSessionConfiguration config;
		PublicKeyAlgorithm pkAlgorithm;
		InitializeSshConfiguration(
			"diffie-hellman-group14-sha256",
			Rsa.RsaWithSha512, "hmac-sha2-512",
			false,
			out config,
			out pkAlgorithm);
		var clientKey = pkAlgorithm is Rsa ? this.clientRsaKey : pkAlgorithm.GenerateKeyPair();
		var serverKey = pkAlgorithm is Rsa ? this.serverRsaKey : pkAlgorithm.GenerateKeyPair();

		var client = new DisconnectableSshClient(config, TestTS);

		Process sshdProcess = null, sshProcess = null;
		string configFile = Path.GetTempFileName();
		string hostKeyFile = Path.GetTempFileName();
		string pidFile = Path.GetTempFileName();
		string authorizedKeysFile = Path.GetTempFileName();
		string knownHostsFile = Path.GetTempFileName();
		string clientKeyFile = Path.GetTempFileName();
		string sshConfigFile = Path.GetTempFileName();

		var sshdProcessOutput = new StringBuilder();
		var sshProcessOutput = new StringBuilder();
		try
		{
			KeyPair.ExportPrivateKeyFile(serverKey, hostKeyFile, null, KeyFormat.Pkcs1);
			KeyPair.ExportPublicKeyFile(clientKey, authorizedKeysFile, KeyFormat.Ssh);

			string args =
				$" -D" + // Do not detach
				$" -e" + // Log to stderr
				$" -o \"LogLevel=VERBOSE\"" +
				$" -p {TestPort}" +
				$" -f \"{configFile}\"" +
				$" -o \"AuthorizedKeysFile={authorizedKeysFile}\"" +
				$" -o \"PidFile={pidFile}\"" +
				$" -o \"HostKey={hostKeyFile}\"";
			TestTS.TraceInformation($"{sshdExePath} {args}");
			sshdProcessOutput.AppendLine($"{sshdExePath} {args}");

			var startInfo = new ProcessStartInfo(sshdExePath, args)
			{
				RedirectStandardOutput = true,
				RedirectStandardError = true,
			};

			DataReceivedEventHandler dataReceivedHandler = (sender, e) =>
			{
				if (e.Data != null)
				{
					sshdProcessOutput.AppendLine(e.Data);
					TestTS.TraceEvent(TraceEventType.Verbose, 0, e.Data);
				}
			};

			sshdProcess = Process.Start(startInfo);
			sshdProcess.OutputDataReceived += dataReceivedHandler;
			sshdProcess.ErrorDataReceived += dataReceivedHandler;
			sshdProcess.BeginOutputReadLine();
			sshdProcess.BeginErrorReadLine();

			var authenticateCompletion = new TaskCompletionSource<bool>();

			var server = new SshServer(config, TestTS);
			server.Credentials = new[] { serverKey };
			server.ExceptionRasied += (sender, ex) => { Assert.Null(ex); };
			var serverTask = server.AcceptSessionsAsync(JumpPort);

			server.SessionAuthenticating += (__, e) =>
			{
				if (e.AuthenticationType == SshAuthenticationType.ClientPublicKey)
				{
					if (e.PublicKey.GetPublicKeyBytes().Equals(clientKey.GetPublicKeyBytes()))
					{
						e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
						authenticateCompletion.TrySetResult(true);
					}
					else
					{
						authenticateCompletion.TrySetResult(false);
					}
				}
			};

			KeyPair.ExportPrivateKeyFile(clientKey, clientKeyFile, null, KeyFormat.Pkcs1);
			string keyAlg = serverKey.KeyAlgorithmName;
			var serverPublicKey = serverKey.GetPublicKeyBytes();
			File.WriteAllText(
				knownHostsFile,
				$"[localhost]:{TestPort} {keyAlg} {serverPublicKey.ToBase64()}\n[localhost]:{JumpPort} {keyAlg} {serverPublicKey.ToBase64()}\n");
			File.WriteAllText(
				sshConfigFile,
				$"Host VSSsh\n  HostName localhost\n  Port {JumpPort}\n  IdentityFile {clientKeyFile}\n  UserKnownHostsFile {knownHostsFile}\n  User {TestUsername}\n\n" +
				$"Host TargetSsh\n  HostName localhost\n  Port {TestPort}\n  IdentityFile {clientKeyFile}\n  UserKnownHostsFile {knownHostsFile}\n  ProxyJump VSSsh\n");

			sshProcessOutput = new StringBuilder();
			string sshArgs =
				$" -v" +
				$" -F \"{sshConfigFile}\"" +
				$" TargetSsh \"echo abc\"";
			TestTS.TraceInformation($"{sshExePath} {sshArgs}");
			sshProcessOutput.AppendLine($"{sshExePath} {sshArgs}");

			var sshStartInfo = new ProcessStartInfo(sshExePath, sshArgs)
			{
				RedirectStandardOutput = true,
				RedirectStandardError = true,
			};

			bool foundTestCommand = false;
			DataReceivedEventHandler sshDataReceivedHandler = (sender, e) =>
			{
				if (e.Data != null)
				{
					if (e.Data.Length > 0 && e.Data == "abc")
					{
						foundTestCommand = true;
					}
					sshProcessOutput.AppendLine(e.Data);
					TestTS.TraceEvent(TraceEventType.Verbose, 0, e.Data);
				}
			};

			sshProcess = Process.Start(sshStartInfo);
			sshProcess.OutputDataReceived += sshDataReceivedHandler;
			sshProcess.ErrorDataReceived += sshDataReceivedHandler;
			sshProcess.BeginOutputReadLine();
			sshProcess.BeginErrorReadLine();

			sshProcess.WaitForExit(5000);
			if (!sshProcess.HasExited)
			{
				throw new Exception("SSH Process did not exit");
			}
			if (!foundTestCommand)
			{
				throw new Exception("Did not execute test command \"echo abc\"");
			}
		}
		catch (Exception ex)
		{
			throw new Exception(
				ex.Message + "\nsshd process output follows:\n" + sshdProcessOutput + "\nssh process output follows:\n" + sshProcessOutput, ex);
		}
		finally
		{
			client.Dispose();

			if (sshdProcess != null && !sshdProcess.HasExited)
			{
				sshdProcess.Kill();
				sshdProcess.WaitForExit(5000);
				Assert.True(sshdProcess.HasExited);
			}

			if (sshProcess != null && !sshProcess.HasExited)
			{
				sshProcess.Kill();
				sshProcess.WaitForExit(5000);
				Assert.True(sshProcess.HasExited);
			}

			File.Delete(hostKeyFile);
			File.Delete(configFile);
			File.Delete(pidFile);
			File.Delete(authorizedKeysFile);
			File.Delete(knownHostsFile);
			File.Delete(clientKeyFile);
			File.Delete(sshConfigFile);
		}
	}

	private static void InitializeSshConfiguration(
		string kexAlgorithmName,
		string publicKeyAlgorithmName,
		string hmacAlgorithmName,
		bool reconnect,
		out SshSessionConfiguration config,
		out PublicKeyAlgorithm pkAlgorithm)
	{
		config = new SshSessionConfiguration();
		config.AddService(typeof(PortForwardingService));

#if SSH_ENABLE_ECDH
		config.KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.EcdhNistp521);
#endif
		config.PublicKeyAlgorithms.Add(SshAlgorithms.PublicKey.ECDsaSha2Nistp521);

		var kexAlgorithm = config.KeyExchangeAlgorithms.Single((a) => a?.Name == kexAlgorithmName);
		config.KeyExchangeAlgorithms.Clear();
		config.KeyExchangeAlgorithms.Add(kexAlgorithm);

		pkAlgorithm = config.PublicKeyAlgorithms.Single((a) => a?.Name == publicKeyAlgorithmName);
		config.PublicKeyAlgorithms.Clear();
		config.PublicKeyAlgorithms.Add(pkAlgorithm);

		var hmacAlgorithm = config.HmacAlgorithms.Single((a) => a?.Name == hmacAlgorithmName);
		config.HmacAlgorithms.Clear();
		config.HmacAlgorithms.Add(hmacAlgorithm);

		if (reconnect)
		{
			config.ProtocolExtensions.Add(SshProtocolExtensionNames.SessionReconnect);
			config.ProtocolExtensions.Add(SshProtocolExtensionNames.SessionLatency);
		}

#if SSH_ENABLE_AESGCM
		// Enable AES-GCM for a subset of test cases. Not all, to keep coverage of HMAC algs.
		if (publicKeyAlgorithmName.StartsWith("ecdsa-"))
		{
			config.EncryptionAlgorithms.Clear();
			config.EncryptionAlgorithms.Add(SshAlgorithms.Encryption.Aes256Gcm);
		}
#endif
	}

	private async Task ForwardPortToServer(SshClientSession session)
	{
		var serverListener = new TcpListener(IPAddress.Loopback, 0);
		serverListener.Start();
		try
		{
			var serverPort = ((IPEndPoint)serverListener.LocalEndpoint).Port;
			using var forwarder = await session.ForwardToRemotePortAsync(
				IPAddress.Loopback, 0, IPAddress.Loopback.ToString(), serverPort);

			var acceptTask = serverListener.AcceptTcpClientAsync();

			using var clientConnection = new TcpClient();
			await clientConnection.ConnectAsync(forwarder.LocalIPAddress, forwarder.LocalPort);
			var clientStream = clientConnection.GetStream();

			using var serverConnection = await acceptTask.WithTimeout(Timeout);
			var serverStream = serverConnection.GetStream();

			var writeBuffer = new byte[] { 1, 2, 3 };
			await clientStream.WriteAsync(writeBuffer, 0, writeBuffer.Length);
			await serverStream.WriteAsync(writeBuffer, 0, writeBuffer.Length);

			var readBuffer = new byte[10];
			var count = await serverStream.ReadAsync(readBuffer, 0, readBuffer.Length)
				.WithTimeout(Timeout);
			Assert.Equal(writeBuffer.Length, count);
			count = await clientStream.ReadAsync(readBuffer, 0, readBuffer.Length)
				.WithTimeout(Timeout);
			Assert.Equal(writeBuffer.Length, count);
		}
		finally
		{
			serverListener.Stop();
		}
	}

	private async Task ForwardPortFromServer(SshClientSession session)
	{
		var clientListener = new TcpListener(IPAddress.Loopback, 0);
		clientListener.Start();
		try
		{
			var clientPort = ((IPEndPoint)clientListener.LocalEndpoint).Port;
			using var forwarder = await session.ForwardFromRemotePortAsync(
				IPAddress.Loopback, 0, IPAddress.Loopback.ToString(), clientPort);

			var acceptTask = clientListener.AcceptTcpClientAsync();

			using var serverConnection = new TcpClient();
			await TaskExtensions.WaitUntil(async () =>
			{
				try
				{
					await serverConnection.ConnectAsync(IPAddress.Loopback, forwarder.RemotePort);
					return true;
				}
				catch
				{
					return false;
				}
			}).WithTimeout(Timeout);
			var serverStream = serverConnection.GetStream();

			using var clientConnection = await acceptTask.WithTimeout(Timeout);
			var clientStream = clientConnection.GetStream();

			var writeBuffer = new byte[] { 1, 2, 3 };
			await clientStream.WriteAsync(writeBuffer, 0, writeBuffer.Length);
			await serverStream.WriteAsync(writeBuffer, 0, writeBuffer.Length);

			var readBuffer = new byte[10];
			var count = await serverStream.ReadAsync(readBuffer, 0, readBuffer.Length)
				.WithTimeout(Timeout);
			Assert.Equal(writeBuffer.Length, count);
			count = await clientStream.ReadAsync(readBuffer, 0, readBuffer.Length)
				.WithTimeout(Timeout);
			Assert.Equal(writeBuffer.Length, count);
		}
		finally
		{
			clientListener.Stop();
		}
	}

	private async Task ReconnectToServer(DisconnectableSshClient client)
	{
		SshClientSession session = client.Sessions.Single();

		// Reconnect is not enabled until a few messages are exchanged.
		await TaskExtensions.WaitUntil(() =>
			session.ProtocolExtensions?.ContainsKey(
				SshProtocolExtensionNames.SessionReconnect) == true).WithTimeout(Timeout);

		client.Disconnect();

		// Wait for async processing of the disconnection.
		await TaskExtensions.WaitUntil(() => !session.IsConnected).WithTimeout(Timeout);

		Assert.False(session.IsConnected);

		await client.ReconnectSessionAsync(
			session, IPAddress.Loopback.ToString(), TestPort).WithTimeout(Timeout);
	}

	private static string FindSshExePath(string name)
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
			foreach (string dir in pathEnv.Split(
				Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
			{
				var dirAndName = Path.Combine(dir, name);
				if (File.Exists(dirAndName))
				{
					return dirAndName;
				}
			}

			throw new PlatformNotSupportedException(name + "executable not found.");
		}
		else
		{
			/*
			var devPath = $@"D:\openssh-portable\bin\x64\Debug\{name}.exe";
			if (File.Exists(devPath))
			{
				return devPath;
			}
			*/

			// OpenSSH tools are not typically in %PATH% on Windows.
			// Look for them in common installation locations.
			string relativePath = $"OpenSSH\\{name}.exe";

			foreach (var specialFolder in new[]
			{
					Environment.SpecialFolder.System,
					Environment.SpecialFolder.ProgramFiles,
					Environment.SpecialFolder.ProgramFilesX86,
				})
			{
				string sshPath = Path.Combine(
					Environment.GetFolderPath(specialFolder), relativePath);
				if (File.Exists(sshPath))
				{
					return sshPath;
				}
			}

			throw new PlatformNotSupportedException(
				name + ".exe not found. Install OpenSSH from " +
				"https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH");
		}
	}

	private static string GetRepoRoot()
	{
		var rootDir = Path.GetDirectoryName(typeof(InteropTests).Assembly.Location);
		while (!File.Exists(Path.Combine(rootDir, "SSH.sln")))
		{
			rootDir = Path.GetDirectoryName(rootDir);
		}

		return rootDir;
	}

	private static int GetAvailableLocalTcpPort()
	{
		// Get any available local tcp port
		var listener = new TcpListener(IPAddress.Loopback, 0);
		listener.Start();
		int port = ((IPEndPoint)listener.LocalEndpoint).Port;
		listener.Stop();
		return port;
	}

	private class DisconnectableSshClient : SshClient
	{
		private Stream stream;

		public DisconnectableSshClient(SshSessionConfiguration config, TraceSource trace)
			: base(config, trace)
		{
		}

		protected override async Task<(Stream Stream, IPAddress RemomoteIPAddress)> OpenConnectionAsync(
			string host, int port, CancellationToken cancellation)
		{
			(this.stream, var ipAddress) = await base.OpenConnectionAsync(host, port, cancellation);
			return (this.stream, ipAddress);
		}

		public void Disconnect()
		{
			this.stream.Close();
		}
	}
}
