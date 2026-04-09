// Copyright (c) Microsoft Corporation. All rights reserved.
// Minimal SSH server/client helper for Go interop testing.
// Usage: dotnet run -- <server|client> <port> <kex> <pk> <enc> <hmac>
//
// Protocol:
//   Server prints "LISTENING" when ready, "ECHOED <n>" when echoing data.
//   Client prints "AUTHENTICATED", "CHANNEL_OPEN", "ECHO_OK", "DONE".

using System;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.Tcp;

class Program
{
	static async Task<int> Main(string[] args)
	{
		if (args.Length < 6)
		{
			Console.Error.WriteLine(
				"Usage: InteropHelper <server|client> <port> <kex> <pk> <enc> <hmac>");
			return 1;
		}

		string mode = args[0];
		int port = int.Parse(args[1]);
		string kex = args[2];
		string pk = args[3];
		string enc = args[4];
		string hmac = args[5];

		try
		{
			var config = CreateConfig(kex, pk, enc, hmac);

			if (mode == "server")
				return await RunServer(config, port, pk);
			else if (mode == "client")
				return await RunClient(config, port);
			else
			{
				Console.Error.WriteLine($"Unknown mode: {mode}");
				return 1;
			}
		}
		catch (Exception ex)
		{
			Console.Error.WriteLine($"ERROR: {ex}");
			return 1;
		}
	}

	static SshSessionConfiguration CreateConfig(
		string kexName, string pkName, string encName, string hmacName)
	{
		// Create a default config to get the full set of available algorithms.
		var refConfig = new SshSessionConfiguration();
#if SSH_ENABLE_ECDH
		if (!refConfig.KeyExchangeAlgorithms.Any(a => a?.Name == "ecdh-sha2-nistp256"))
			refConfig.KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.EcdhNistp256);
		if (!refConfig.KeyExchangeAlgorithms.Any(a => a?.Name == "ecdh-sha2-nistp384"))
			refConfig.KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.EcdhNistp384);
		if (!refConfig.KeyExchangeAlgorithms.Any(a => a?.Name == "ecdh-sha2-nistp521"))
			refConfig.KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.EcdhNistp521);
#endif
		if (!refConfig.PublicKeyAlgorithms.Any(a => a?.Name == "ecdsa-sha2-nistp521"))
			refConfig.PublicKeyAlgorithms.Add(SshAlgorithms.PublicKey.ECDsaSha2Nistp521);
#if SSH_ENABLE_AESGCM
		if (!refConfig.EncryptionAlgorithms.Any(a => a?.Name == "aes256-gcm@openssh.com"))
			refConfig.EncryptionAlgorithms.Add(SshAlgorithms.Encryption.Aes256Gcm);
#endif

		// Look up algorithms by name.
		var kexAlg = refConfig.KeyExchangeAlgorithms.SingleOrDefault(a => a?.Name == kexName)
			?? throw new ArgumentException($"KEX algorithm '{kexName}' not found");
		var pkAlg = refConfig.PublicKeyAlgorithms.SingleOrDefault(a => a?.Name == pkName)
			?? throw new ArgumentException($"PK algorithm '{pkName}' not found");
		var encAlg = refConfig.EncryptionAlgorithms.SingleOrDefault(a => a?.Name == encName)
			?? throw new ArgumentException($"Encryption algorithm '{encName}' not found");
		var hmacAlg = refConfig.HmacAlgorithms.SingleOrDefault(a => a?.Name == hmacName)
			?? throw new ArgumentException($"HMAC algorithm '{hmacName}' not found");

		// Create a new config with only the specified algorithms.
		var config = new SshSessionConfiguration();
		config.KeyExchangeAlgorithms.Clear();
		config.KeyExchangeAlgorithms.Add(kexAlg);
		config.PublicKeyAlgorithms.Clear();
		config.PublicKeyAlgorithms.Add(pkAlg);
		config.EncryptionAlgorithms.Clear();
		config.EncryptionAlgorithms.Add(encAlg);
		config.HmacAlgorithms.Clear();
		config.HmacAlgorithms.Add(hmacAlg);

		return config;
	}

	static async Task<int> RunServer(SshSessionConfiguration config, int port, string pkName)
	{
		var pkAlg = config.PublicKeyAlgorithms.First(a => a != null);
		var hostKey = pkAlg!.GenerateKeyPair();

		var server = new SshServer(config);
		server.Credentials = new[] { hostKey };

		var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
		var sessionDone = new TaskCompletionSource<bool>();

		server.SessionAuthenticating += (_, e) =>
		{
			// Accept all authentication.
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		};

		server.SessionOpened += (_, session) =>
		{
			session.ChannelOpening += (__, e) =>
			{
				var channel = e.Channel;
				channel.DataReceived += async (___, data) =>
				{
					try
					{
						var copy = data.ToArray();
						await channel.SendAsync(
							new Buffer(copy), cts.Token);
						Console.WriteLine($"ECHOED {copy.Length}");
						Console.Out.Flush();
					}
					catch (Exception ex)
					{
						Console.Error.WriteLine($"Echo error: {ex.Message}");
					}
				};
			};

			session.Closed += (__, e) =>
			{
				sessionDone.TrySetResult(true);
			};
		};

		_ = server.AcceptSessionsAsync(port, IPAddress.Loopback);
		Console.WriteLine("LISTENING");
		Console.Out.Flush();

		// Wait for session to complete or timeout.
		try
		{
			await Task.WhenAny(sessionDone.Task, Task.Delay(TimeSpan.FromSeconds(25)));
		}
		catch { }

		server.Dispose();
		return 0;
	}

	static async Task<int> RunClient(SshSessionConfiguration config, int port)
	{
		var cts = new CancellationTokenSource(TimeSpan.FromSeconds(25));
		var client = new SshClient(config);
		var session = await client.OpenSessionAsync("127.0.0.1", port);

		session.Authenticating += (_, e) =>
		{
			// Auto-approve server host key.
			e.AuthenticationTask = Task.FromResult(new ClaimsPrincipal());
		};

		bool authenticated = await session.AuthenticateAsync(
			new SshClientCredentials("testuser"));
		if (!authenticated)
		{
			Console.Error.WriteLine("Authentication failed");
			return 1;
		}

		Console.WriteLine("AUTHENTICATED");
		Console.Out.Flush();

		var channel = await session.OpenChannelAsync();
		Console.WriteLine("CHANNEL_OPEN");
		Console.Out.Flush();

		// Send test data.
		var testData = Encoding.UTF8.GetBytes("INTEROP_TEST_DATA");
		var recvDone = new TaskCompletionSource<byte[]>();

		channel.DataReceived += (_, received) =>
		{
			recvDone.TrySetResult(received.ToArray());
		};

		await channel.SendAsync(new Buffer(testData), cts.Token);

		// Wait for echo.
		var echoed = await Task.WhenAny(recvDone.Task, Task.Delay(TimeSpan.FromSeconds(10)));
		if (echoed == recvDone.Task)
		{
			var echoData = await recvDone.Task;
			if (Encoding.UTF8.GetString(echoData) == "INTEROP_TEST_DATA")
			{
				Console.WriteLine("ECHO_OK");
			}
			else
			{
				Console.Error.WriteLine("Echo mismatch");
				return 1;
			}
		}
		else
		{
			Console.Error.WriteLine("Echo timeout");
			return 1;
		}

		Console.Out.Flush();
		await channel.CloseAsync();
		session.Dispose();
		Console.WriteLine("DONE");
		Console.Out.Flush();
		return 0;
	}
}
