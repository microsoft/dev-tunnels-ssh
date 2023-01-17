// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.IO;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Services;
#pragma warning disable SA1117 // Parameters should be on same line or separate lines

/// <summary>
/// Handles SSH protocol messages related to key-exchange and algorithm negotiation.
/// </summary>
[ServiceActivation(ServiceRequest = Name)]
#pragma warning disable CA1812 // Avoid Uninstantiated Internal Classes
internal class KeyExchangeService : SshService
#pragma warning restore CA1812 // Avoid Uninstantiated Internal Classes
{
	public const string Name = "ssh-keyexchange";

	private const string ServerExtensionInfoSignal = "ext-info-s";
	private const string ClientExtensionInfoSignal = "ext-info-c";

	private bool isInitialExchange;
	private ExchangeContext? exchangeContext;

	public KeyExchangeService(SshSession session)
		: base(session)
	{
	}

	internal IKeyPair? HostKey { get; set; }

	internal bool Exchanging => this.exchangeContext != null;

	internal (KeyExchangeInitMessage InitMessage, KeyExchangeDhInitMessage? GuessMessage) StartKeyExchange(
		bool isInitialExchange)
	{
		this.isInitialExchange = isInitialExchange;
		this.exchangeContext = new ExchangeContext();
		var kexInitMessage = CreateKeyExchangeInitMessage();
		KeyExchangeDhInitMessage? kexGuessMessage = null;

		if (Session is SshClientSession)
		{
			if (isInitialExchange && Session.Config.EnableKeyExchangeGuess)
			{
				kexGuessMessage = CreateKeyExchangeGuessMessage();
				kexInitMessage.FirstKexPacketFollows = (kexGuessMessage != null);
			}

			this.exchangeContext.ClientKexInitPayload = kexInitMessage.ToBuffer().ToArray();
		}
		else
		{
			this.exchangeContext.ServerKexInitPayload = kexInitMessage.ToBuffer().ToArray();
		}

		return (kexInitMessage, kexGuessMessage);
	}

	internal SshSessionAlgorithms FinishKeyExchange()
	{
		if (this.exchangeContext == null)
		{
			throw new SshConnectionException(
				"Key exchange not started.", SshDisconnectReason.ProtocolError);
		}

		if (this.exchangeContext.NewAlgorithms == null)
		{
			throw new SshConnectionException(
				"Key exchange not completed.", SshDisconnectReason.ProtocolError);
		}

		SshSessionAlgorithms newAlgorithms = this.exchangeContext.NewAlgorithms;
		this.exchangeContext = null;
		return newAlgorithms;
	}

	internal void AbortKeyExchange()
	{
		this.exchangeContext = null;
	}

	internal Task HandleMessageAsync(SshMessage message, CancellationToken cancellation)
	{
		return message switch
		{
			KeyExchangeInitMessage m => HandleMessageAsync(m, cancellation),
			KeyExchangeDhInitMessage m => HandleMessageAsync(m, cancellation),
			KeyExchangeDhReplyMessage m => HandleMessageAsync(m, cancellation),
			_ => Task.CompletedTask, // Ignore unrecognized key-exchange messages.
		};
	}

	private KeyExchangeInitMessage CreateKeyExchangeInitMessage()
	{
		// Reference RFC 8308: Signaling of Extension Negotiation in Key Exchange.
		var extinfo = Session is SshServerSession ?
			ServerExtensionInfoSignal : ClientExtensionInfoSignal;

		var message = new KeyExchangeInitMessage
		{
			KeyExchangeAlgorithms = Session.Config.AvailableKeyExchangeAlgorithms
				.Concat(new[] { extinfo }).ToArray(),
			ServerHostKeyAlgorithms = GetPublicKeyAlgorithms().ToArray(),
		};
		message.EncryptionAlgorithmsClientToServer = message.EncryptionAlgorithmsServerToClient =
			Session.Config.AvailableEncryptionAlgorithms.ToArray();
		message.MacAlgorithmsClientToServer = message.MacAlgorithmsServerToClient =
			Session.Config.AvailableHmacAlgorithms.ToArray();
		message.CompressionAlgorithmsClientToServer = message.CompressionAlgorithmsServerToClient =
			Session.Config.AvailableCompressionAlgorithms.ToArray();
		message.LanguagesClientToServer = new[] { string.Empty };
		message.LanguagesServerToClient = new[] { string.Empty };
		message.FirstKexPacketFollows = false;
		message.Reserved = 0;

		return message;
	}

	/// <summary>
	/// Gets the list of public key algorithms that the current session can support.
	/// For a server session the list is filtered based on the available private keys.
	/// </summary>
	private IEnumerable<string> GetPublicKeyAlgorithms()
	{
		IEnumerable<PublicKeyAlgorithm?> publicKeyAlgorithms =
			new List<PublicKeyAlgorithm?>(Session.Config.PublicKeyAlgorithms);

		if (Session is SshServerSession serverSession && publicKeyAlgorithms.Count() > 1)
		{
			var privateKeyAlgorithms = serverSession.Credentials?.PublicKeys?.Select(
				(k) => k?.KeyAlgorithmName);
			if (privateKeyAlgorithms != null)
			{
				publicKeyAlgorithms = publicKeyAlgorithms.Where(
					(a) => a != null && privateKeyAlgorithms.Contains(a.KeyAlgorithmName));
			}
		}

		var publicKeyAlgorithmNames = SshSessionConfiguration.GetAlgorithmNamesList(
			publicKeyAlgorithms).ToArray();
		return publicKeyAlgorithmNames;
	}

	private KeyExchangeDhInitMessage? CreateKeyExchangeGuessMessage()
	{
		if (this.exchangeContext == null)
		{
			throw new SshConnectionException(
				"Key exchange not started.", SshDisconnectReason.ProtocolError);
		}

		// Select the first key exchange algorithm as the "guess". (They are in preferential order.)
		var kexAlgorithm = Session.Config.KeyExchangeAlgorithms
			.FirstOrDefault((a) => a?.IsAvailable == true);
		if (kexAlgorithm == null)
		{
			return null;
		}

		this.exchangeContext.KeyExchange = kexAlgorithm.Name;

		this.exchangeContext.Exchange = kexAlgorithm.CreateKeyExchange();
		this.exchangeContext.ExchangeValue =
			this.exchangeContext.Exchange.StartKeyExchange().ToArray();

		var guess = new KeyExchangeDhInitMessage
		{
			E = this.exchangeContext.ExchangeValue,
		};
		return guess;
	}

	private async Task HandleMessageAsync(
		KeyExchangeInitMessage message, CancellationToken cancellation)
	{
		if (this.exchangeContext == null)
		{
			throw new SshConnectionException(
				"Key exchange not started.", SshDisconnectReason.ProtocolError);
		}

		this.exchangeContext.KeyExchange = ChooseAlgorithm(
			nameof(ExchangeContext.KeyExchange),
			Session.Config.AvailableKeyExchangeAlgorithms,
			message.KeyExchangeAlgorithms);

		if (this.exchangeContext.KeyExchange == "none")
		{
			Session.Trace.TraceEvent(
				TraceEventType.Verbose,
				SshTraceEventIds.AlgorithmNegotiation,
				$"Client and server negotiated no security. Cancelling key-exchange.");

			this.exchangeContext.NewAlgorithms = new SshSessionAlgorithms();
			await Session.HandleMessageAsync(new NewKeysMessage(), cancellation)
				.ConfigureAwait(false);
		}
		else
		{
			this.exchangeContext.PublicKey = ChooseAlgorithm(
				nameof(ExchangeContext.PublicKey),
				GetPublicKeyAlgorithms(),
				message.ServerHostKeyAlgorithms);
			this.exchangeContext.ClientEncryption = ChooseAlgorithm(
				nameof(ExchangeContext.ClientEncryption),
				Session.Config.AvailableEncryptionAlgorithms,
				message.EncryptionAlgorithmsClientToServer);
			this.exchangeContext.ServerEncryption = ChooseAlgorithm(
				nameof(ExchangeContext.ServerEncryption),
				Session.Config.AvailableEncryptionAlgorithms,
				message.EncryptionAlgorithmsServerToClient);
			this.exchangeContext.ClientHmac = ChooseAlgorithm(
				nameof(ExchangeContext.ClientHmac),
				Session.Config.AvailableHmacAlgorithms,
				message.MacAlgorithmsClientToServer);
			this.exchangeContext.ServerHmac = ChooseAlgorithm(
				nameof(ExchangeContext.ServerHmac),
				Session.Config.AvailableHmacAlgorithms,
				message.MacAlgorithmsServerToClient);
			this.exchangeContext.ClientCompression = ChooseAlgorithm(
				nameof(ExchangeContext.ClientCompression),
				Session.Config.AvailableCompressionAlgorithms,
				message.CompressionAlgorithmsClientToServer);
			this.exchangeContext.ServerCompression = ChooseAlgorithm(
				nameof(ExchangeContext.ServerCompression),
				Session.Config.AvailableCompressionAlgorithms,
				message.CompressionAlgorithmsServerToClient);
		}

		string extensionInfoSignal;
		if (Session is SshClientSession)
		{
			if (this.exchangeContext != null)
			{
				this.exchangeContext.ServerKexInitPayload = message.ToBuffer().ToArray();

				// If the exchange value is already initialized then this side sent a guess.
				bool alreadySentGuess = this.exchangeContext.ExchangeValue != null;

				// Check if the negotiated algorithm is the one preferred by THIS side.
				// This means if there was a "guess" at kex initialization then it was correct.
				bool negotiatedKexAlgorthmIsPreferred =
					this.exchangeContext.KeyExchange ==
					Session.Config.AvailableKeyExchangeAlgorithms.FirstOrDefault();

				// If a guess was not sent, or the guess was wrong, send the init message now.
				if (!alreadySentGuess || !negotiatedKexAlgorthmIsPreferred)
				{
					var kexAlgorithm = Session.Config.GetKeyExchangeAlgorithm(
						this.exchangeContext!.KeyExchange);
					if (kexAlgorithm != null)
					{
						this.exchangeContext.Exchange = kexAlgorithm!.CreateKeyExchange();
						this.exchangeContext.ExchangeValue =
							this.exchangeContext.Exchange.StartKeyExchange().ToArray();

						var reply = new KeyExchangeDhInitMessage
						{
							E = this.exchangeContext.ExchangeValue,
						};
						await Session.SendMessageAsync(reply, cancellation).ConfigureAwait(false);
					}
				}
			}

			extensionInfoSignal = ServerExtensionInfoSignal;
		}
		else
		{
			if (this.exchangeContext != null)
			{
				if (message.FirstKexPacketFollows)
				{
					// The remote side indicated it is sending a guess immediately following.
					// Check if the negotiated algorithm is the one preferred by the OTHER side.
					// If so, the following "guess" will be correct. Otherwise it must be ignored.
					bool negotiatedKexAlgorthmIsPreferred =
						this.exchangeContext.KeyExchange ==
						message.KeyExchangeAlgorithms?.FirstOrDefault();
					var guessResult = (negotiatedKexAlgorthmIsPreferred ? "correct" : "incorrect");
					var traceMessage = $"Client's {nameof(ExchangeContext.KeyExchange)} guess " +
						$"({this.exchangeContext.KeyExchange}) was {guessResult}.";
					Session.Trace.TraceEvent(
						TraceEventType.Verbose,
						SshTraceEventIds.AlgorithmNegotiation,
						traceMessage);
					this.exchangeContext.DiscardGuessedInit = !negotiatedKexAlgorthmIsPreferred;
				}

				this.exchangeContext.ClientKexInitPayload = message.ToBuffer().ToArray();
			}

			extensionInfoSignal = ClientExtensionInfoSignal;
		}

		if (this.isInitialExchange &&
			message.KeyExchangeAlgorithms?.Contains(extensionInfoSignal) == true)
		{
			// The extension info message will be blocked in the queue
			// until immediately after the key-exchange is done.
			await Session.SendExtensionInfoAsync(cancellation).ConfigureAwait(false);
		}
	}

	/// <summary>
	/// Handle server side key exchange.
	/// </summary>
	/// <param name="message">Key exchange init message sent by the client</param>
	/// <param name="cancellation">Cancellation token</param>
	private async Task HandleMessageAsync(
		KeyExchangeDhInitMessage message, CancellationToken cancellation)
	{
		var serverSession = Session as SshServerSession;
		if (serverSession == null)
		{
			return;
		}

		if (this.exchangeContext == null || this.exchangeContext.PublicKey == null)
		{
			throw new SshConnectionException(
				"Key exchange not started.", SshDisconnectReason.ProtocolError);
		}

		if (this.exchangeContext.DiscardGuessedInit)
		{
			// Algorithm negotiation determined that an incorrect guess would be received.
			this.exchangeContext.DiscardGuessedInit = false;
			return;
		}

		var kexAlg = Session.Config.GetKeyExchangeAlgorithm(this.exchangeContext.KeyExchange);
		if (kexAlg == null)
		{
			throw new NotSupportedException(
				"Key exchange not supported for algorithm: " + this.exchangeContext.KeyExchange);
		}

		var publicKeyAlg = Session.Config.GetPublicKeyAlgorithm(this.exchangeContext.PublicKey);
		if (publicKeyAlg == null)
		{
			throw new NotSupportedException("Public key algorithm not supported: " + this.exchangeContext.PublicKey);
		}

		IKeyPair? privateKey = null;
		if (serverSession.Credentials?.PublicKeys != null)
		{
			var publicKey = serverSession.Credentials.PublicKeys.FirstOrDefault(
				(k) => k != null && k.KeyAlgorithmName == publicKeyAlg.KeyAlgorithmName);
			privateKey = publicKey;
			if (privateKey?.HasPrivateKey == false)
			{
				var privateKeyProvider = serverSession.Credentials?.PrivateKeyProvider;
				if (privateKeyProvider == null)
				{
					throw new InvalidOperationException("A private key provider is required.");
				}

				privateKey = await privateKeyProvider(publicKey!, cancellation).ConfigureAwait(false);
			}
		}

		if (privateKey == null)
		{
			throw new InvalidOperationException(
				"Private key not found for algorithm: " + this.exchangeContext.PublicKey);
		}

		var clientEncryption = Session.Config.GetEncryptionAlgorithm(this.exchangeContext.ClientEncryption);
		var serverEncryption = Session.Config.GetEncryptionAlgorithm(this.exchangeContext.ServerEncryption);
		var serverHmac = Session.Config.GetHmacAlgorithm(this.exchangeContext.ServerHmac);
		var clientHmac = Session.Config.GetHmacAlgorithm(this.exchangeContext.ClientHmac);

		var keyExchange = kexAlg.CreateKeyExchange();
		var clientExchangeValue = message.E;
		var serverExchangeValue = keyExchange.StartKeyExchange();
		var sharedSecret = keyExchange.DecryptKeyExchange(clientExchangeValue);
		var hostKeyAndCerts = privateKey.GetPublicKeyBytes(publicKeyAlg.Name);
		var exchangeHash = ComputeExchangeHash(
			keyExchange, hostKeyAndCerts, clientExchangeValue, serverExchangeValue, sharedSecret);

		if (Session.SessionId == null)
		{
			Session.SessionId = exchangeHash.ToArray();
		}

		ComputeKeys(
			keyExchange, sharedSecret, exchangeHash,
			clientEncryption, serverEncryption, clientHmac, serverHmac,
			out Buffer clientCipherIV, out Buffer serverCipherIV,
			out Buffer clientCipherKey, out Buffer serverCipherKey,
			out Buffer clientHmacKey, out Buffer serverHmacKey);

		var cipher = serverEncryption?.CreateCipher(true, serverCipherKey, serverCipherIV);
		var decipher = clientEncryption?.CreateCipher(false, clientCipherKey, clientCipherIV);
		var signer = serverHmac?.CreateSigner(serverHmacKey);
		var verifier = clientHmac?.CreateVerifier(clientHmacKey);

		this.exchangeContext.NewAlgorithms = new SshSessionAlgorithms
		{
			PublicKeyAlgorithmName = this.exchangeContext.PublicKey,
			Cipher = cipher,
			Decipher = decipher,
			Signer = signer,
			Verifier = verifier,
			MessageSigner = cipher as IMessageSigner ?? signer,
			MessageVerifier = decipher as IMessageVerifier ?? verifier,
			Compressor = Session.Config.GetCompressionAlgorithm(this.exchangeContext.ServerCompression),
			Decompressor = Session.Config.GetCompressionAlgorithm(this.exchangeContext.ClientCompression),
		};

		clientCipherIV.Clear();
		clientCipherKey.Clear();
		clientHmacKey.Clear();
		serverCipherIV.Clear();
		serverCipherKey.Clear();
		serverHmacKey.Clear();

		var exchangeSigner = publicKeyAlg.CreateSigner(privateKey);
		var signature = new Buffer(exchangeSigner.DigestLength);
		exchangeSigner.Sign(exchangeHash, signature);
		signature = publicKeyAlg.CreateSignatureData(signature);

		var reply = new KeyExchangeDhReplyMessage
		{
			HostKey = hostKeyAndCerts,
			F = serverExchangeValue,
			Signature = signature,
		};

		await Session.SendMessageAsync(reply, cancellation).ConfigureAwait(false);
		await Session.SendMessageAsync(new NewKeysMessage(), cancellation).ConfigureAwait(false);
	}

	/// <summary>
	/// Handle client side key exchange.
	/// </summary>
	/// <param name="message">Key exchange reply sent by the server</param>
	/// <param name="cancellation">Cancellation token</param>
	private async Task HandleMessageAsync(
		KeyExchangeDhReplyMessage message, CancellationToken cancellation)
	{
		if (!(Session is SshClientSession))
		{
			return;
		}

		if (this.exchangeContext == null)
		{
			throw new SshConnectionException(
				"Key exchange not started.", SshDisconnectReason.ProtocolError);
		}

		var keyExchange = this.exchangeContext.Exchange;
		var publicKeyAlg = Session.Config.GetPublicKeyAlgorithm(this.exchangeContext.PublicKey);
		var clientEncryption = Session.Config.GetEncryptionAlgorithm(this.exchangeContext.ClientEncryption);
		var serverEncryption = Session.Config.GetEncryptionAlgorithm(this.exchangeContext.ServerEncryption);
		var serverHmac = Session.Config.GetHmacAlgorithm(this.exchangeContext.ServerHmac);
		var clientHmac = Session.Config.GetHmacAlgorithm(this.exchangeContext.ClientHmac);

		var clientExchangeValue = this.exchangeContext.ExchangeValue;
		var serverExchangeValue = message.F;

		if (keyExchange == null || publicKeyAlg == null || clientExchangeValue == null)
		{
			throw new SshConnectionException(
				"Failed to initialize crypto after key exchange.", SshDisconnectReason.KeyExchangeFailed);
		}

		// Load the server's public key bytes into a key pair object.
		HostKey = publicKeyAlg.CreateKeyPair();
		HostKey.SetPublicKeyBytes(message.HostKey);

		var sharedSecret = keyExchange.DecryptKeyExchange(serverExchangeValue);
		var hostKeyAndCerts = message.HostKey;
		var exchangeHash = ComputeExchangeHash(
			keyExchange,
			hostKeyAndCerts,
			clientExchangeValue,
			serverExchangeValue,
			sharedSecret);

		var signature = publicKeyAlg.ReadSignatureData(message.Signature);
		var exchangeVerifier = publicKeyAlg.CreateVerifier(HostKey);
		bool verified = exchangeVerifier.Verify(exchangeHash, signature);
		if (!verified)
		{
			throw new SshConnectionException(
				$"Host key verification failed for public-key algorithm: {publicKeyAlg.Name}",
				SshDisconnectReason.HostKeyNotVerifiable);
		}

		if (Session.SessionId == null)
		{
			Session.SessionId = exchangeHash.ToArray();
		}

		ComputeKeys(
			keyExchange, sharedSecret, exchangeHash,
			clientEncryption, serverEncryption, clientHmac, serverHmac,
			out Buffer clientCipherIV, out Buffer serverCipherIV,
			out Buffer clientCipherKey, out Buffer serverCipherKey,
			out Buffer clientHmacKey, out Buffer serverHmacKey);

		var cipher = clientEncryption?.CreateCipher(true, clientCipherKey, clientCipherIV);
		var decipher = serverEncryption?.CreateCipher(false, serverCipherKey, serverCipherIV);
		var signer = clientHmac?.CreateSigner(clientHmacKey);
		var verifier = serverHmac?.CreateVerifier(serverHmacKey);

		this.exchangeContext.NewAlgorithms = new SshSessionAlgorithms
		{
			PublicKeyAlgorithmName = this.exchangeContext.PublicKey,
			Cipher = cipher,
			Decipher = decipher,
			Signer = signer,
			Verifier = verifier,
			MessageSigner = cipher as IMessageSigner ?? signer,
			MessageVerifier = decipher as IMessageVerifier ?? verifier,
			Compressor = Session.Config.GetCompressionAlgorithm(this.exchangeContext.ClientCompression),
			Decompressor = Session.Config.GetCompressionAlgorithm(this.exchangeContext.ServerCompression),
		};

		clientCipherIV.Clear();
		clientCipherKey.Clear();
		clientHmacKey.Clear();
		serverCipherIV.Clear();
		serverCipherKey.Clear();
		serverHmacKey.Clear();

		await Session.SendMessageAsync(new NewKeysMessage(), cancellation).ConfigureAwait(false);
	}

	private string ChooseAlgorithm(
		string label,
		IEnumerable<string> localAlgorithms,
		IEnumerable<string>? remoteAlgorithms)
	{
		// Ensure consistent results if the client and server list the same algorithms
		// in different order of preference.
		IEnumerable<string> serverAlgorithms;
		IEnumerable<string> clientAlgorithms;
		if (Session is SshServerSession)
		{
			serverAlgorithms = localAlgorithms;
			clientAlgorithms = remoteAlgorithms ?? Array.Empty<string>();
		}
		else
		{
			serverAlgorithms = remoteAlgorithms ?? Array.Empty<string>();
			clientAlgorithms = localAlgorithms;
		}

		var negotiationDetail = $"{label} negotiation: " +
			$"Server ({string.Join(", ", serverAlgorithms)}) " +
			$"Client ({string.Join(", ", clientAlgorithms)})";

		foreach (var client in clientAlgorithms)
		{
			foreach (var server in serverAlgorithms)
			{
				if (server == client)
				{
					var result = server;
					Session.Trace.TraceEvent(
						TraceEventType.Verbose,
						SshTraceEventIds.AlgorithmNegotiation,
						$"{negotiationDetail} => {result}");
					return result;
				}
			}
		}

		throw new SshConnectionException(
			"Failed " + negotiationDetail, SshDisconnectReason.KeyExchangeFailed);
	}

	private Buffer ComputeExchangeHash(
		IKeyExchange keyExchange,
		Buffer hostKeyAndCerts,
		Buffer clientExchangeValue,
		Buffer serverExchangeValue,
		Buffer sharedSecret)
	{
		if (Session.RemoteVersion == null)
		{
			throw new InvalidOperationException("Version exchange not completed.");
		}

		var writer = new SshDataWriter();

		if (Session is SshClientSession)
		{
			writer.Write(SshSession.LocalVersion.ToString(), Encoding.ASCII);
			writer.Write(Session.RemoteVersion.ToString(), Encoding.ASCII);
		}
		else
		{
			writer.Write(Session.RemoteVersion.ToString(), Encoding.ASCII);
			writer.Write(SshSession.LocalVersion.ToString(), Encoding.ASCII);
		}

		writer.WriteBinary(this.exchangeContext?.ClientKexInitPayload ?? Array.Empty<byte>());
		writer.WriteBinary(this.exchangeContext?.ServerKexInitPayload ?? Array.Empty<byte>());
		writer.WriteBinary(hostKeyAndCerts);

		// These values are formatted as bigints (with leading zeroes if the first bit is high)
		// even though they might not really be bigints, depending on the key-exchange algorithm.
		writer.Write(BigInt.FromByteArray(clientExchangeValue.ToArray(), unsigned: true));
		writer.Write(BigInt.FromByteArray(serverExchangeValue.ToArray(), unsigned: true));
		writer.Write(BigInt.FromByteArray(sharedSecret.ToArray(), unsigned: true));

		Buffer result = new Buffer(keyExchange.DigestLength);
		keyExchange.Sign(writer.ToBuffer(), result);
		return result;
	}

	private void ComputeKeys(
		IKeyExchange keyExchange,
		Buffer sharedSecret,
		Buffer exchangeHash,
		EncryptionAlgorithm? clientEncryption,
		EncryptionAlgorithm? serverEncryption,
		HmacAlgorithm? clientHmac,
		HmacAlgorithm? serverHmac,
		out Buffer clientCipherIV,
		out Buffer serverCipherIV,
		out Buffer clientCipherKey,
		out Buffer serverCipherKey,
		out Buffer clientHmacKey,
		out Buffer serverHmacKey)
	{
		var writer = new SshDataWriter(new Buffer(
			4 + sharedSecret.Count + exchangeHash.Count +
			Math.Max(1 /* letter */ + (Session.SessionId?.Length ?? 0), keyExchange.DigestLength)));
		writer.WriteBinary(sharedSecret);
		writer.Write(exchangeHash);
		var offset = writer.Position;

		clientCipherIV = clientEncryption == null ? Buffer.Empty : ComputeKey(
			keyExchange, writer, offset, clientEncryption.BlockLength, 'A');
		serverCipherIV = serverEncryption == null ? Buffer.Empty : ComputeKey(
			keyExchange, writer, offset, serverEncryption.BlockLength, 'B');
		clientCipherKey = clientEncryption == null ? Buffer.Empty : ComputeKey(
			keyExchange, writer, offset, clientEncryption.KeyLength, 'C');
		serverCipherKey = serverEncryption == null ? Buffer.Empty : ComputeKey(
			keyExchange, writer, offset, serverEncryption.KeyLength, 'D');
		clientHmacKey = clientHmac == null ? Buffer.Empty : ComputeKey(
			keyExchange, writer, offset, clientHmac.KeyLength, 'E');
		serverHmacKey = serverHmac == null ? Buffer.Empty : ComputeKey(
			keyExchange, writer, offset, serverHmac.KeyLength, 'F');
	}

	private Buffer ComputeKey(
		IKeyExchange keyExchange,
		SshDataWriter writer,
		int writerOffset,
		int blockSize,
		char letter)
	{
		if (Session.SessionId == null)
		{
			throw new InvalidOperationException("Session ID not established.");
		}

		var keyBuffer = new Buffer(blockSize);
		var keyBufferIndex = 0;
		var currentHash = Buffer.Empty;

		while (keyBufferIndex < blockSize)
		{
			writer.Position = writerOffset;

			if (currentHash.Count == 0)
			{
				writer.Write((byte)letter);
				writer.Write(Session.SessionId);
			}
			else
			{
				writer.Write(currentHash);
			}

			currentHash = new Buffer(keyExchange.DigestLength);
			keyExchange.Sign(writer.ToBuffer(), currentHash);

			var currentHashLength = Math.Min(currentHash.Count, blockSize - keyBufferIndex);
			currentHash.Slice(0, currentHashLength).CopyTo(keyBuffer, keyBufferIndex);

			keyBufferIndex += currentHashLength;
		}

		currentHash.Clear();

		return keyBuffer;
	}

	private class ExchangeContext
	{
		public bool DiscardGuessedInit { get; set; }

		public string? KeyExchange { get; set; }

		public string? PublicKey { get; set; }

		public string? ClientEncryption { get; set; }

		public string? ServerEncryption { get; set; }

		public string? ClientHmac { get; set; }

		public string? ServerHmac { get; set; }

		public string? ClientCompression { get; set; }

		public string? ServerCompression { get; set; }

		public byte[]? ClientKexInitPayload { get; set; }

		public byte[]? ServerKexInitPayload { get; set; }

		public byte[]? ExchangeValue { get; set; }

		public IKeyExchange? Exchange { get; set; }

		public SshSessionAlgorithms? NewAlgorithms { get; set; }
	}
}
