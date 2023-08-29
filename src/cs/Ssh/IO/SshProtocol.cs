// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Metrics;
using Microsoft.DevTunnels.Ssh.Services;

namespace Microsoft.DevTunnels.Ssh.IO;

/// <summary>
/// Implements the base SSH protocol (sending and receiving messages) over a Stream.
/// </summary>
internal class SshProtocol : IDisposable
{
	private const uint MaxPacketLength = 1024 * 1024; // 1 MB
	private const byte PacketLengthSize = 4;
	private const byte PaddingLengthSize = 1;
	private const byte SequenceNumberSize = 4;

	private static readonly TimeSpan LongTimeout = TimeSpan.FromDays(1);

	private Stream? stream;
	private readonly SshSessionConfiguration config;
	private readonly SessionMetrics metrics;

#pragma warning disable CA2213 // Disposable fields should be disposed
	private readonly SemaphoreSlim sessionSemaphore;
#pragma warning restore CA2213 // Disposable fields should be disposed

	private readonly TraceSource trace;

	private ulong inboundPacketSequence;
	private ulong outboundPacketSequence;
	private uint inboundFlow;
	private uint outboundFlow;
	private long lastIncomingTimestamp;

	private struct SequencedMessage
	{
		public SequencedMessage(ulong sequence, SshMessage message)
		{
			Sequence = sequence;
			Message = message;
			SentTime = 0;
		}

		public ulong Sequence { get; }
		public SshMessage Message { get; }
		public long SentTime { get; set; }
	}

	// Sent messages are kept for a short time, until the other side acknowledges
	// that they have been received. This enables re-sending lost messages on reconnect.
	private readonly Queue<SequencedMessage> recentSentMessages =
		new Queue<SequencedMessage>();

	// Initialize buffers that are re-used for each sent/received message.
	// The buffers will be automatically expanded as necessary.
	private SshDataWriter sendWriter = new SshDataWriter(new Buffer(1024));
	private SshDataReader receiveReader = new SshDataReader(new Buffer(1024));
	private readonly Buffer sendHmacBuffer = new Buffer(128);
	private readonly Buffer receiveHmacBuffer = new Buffer(128);

	public SshProtocol(
		Stream stream,
		SshSessionConfiguration config,
		SessionMetrics metrics,
		TraceSource trace)
	{
		this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
		this.config = config ?? throw new ArgumentNullException(nameof(config));
		this.metrics = metrics ?? throw new ArgumentNullException(nameof(metrics));
		this.trace = trace ?? throw new ArgumentNullException(nameof(trace));
		this.sessionSemaphore = new SemaphoreSlim(1);

		if (stream.CanTimeout)
		{
			stream.ReadTimeout = (int)LongTimeout.TotalMilliseconds;
			stream.WriteTimeout = (int)LongTimeout.TotalMilliseconds;
		}
	}

	internal bool TraceChannelData { get; set; }

	internal Dictionary<string, string>? Extensions { get; set; }

	internal KeyExchangeService? KeyExchangeService { get; set; }

	internal SshSessionAlgorithms? Algorithms { get; private set; }

	internal string? MessageContext { get; set; }

	internal bool OutgoingMessagesHaveLatencyInfo { get; set; }
	internal bool IncomingMessagesHaveLatencyInfo { get; set; }
	internal bool OutgoingMessagesHaveReconnectInfo { get; set; }
	internal bool IncomingMessagesHaveReconnectInfo { get; set; }
	internal ulong LastIncomingSequence => this.inboundPacketSequence - 1;

	internal IList<SshMessage>? GetSentMessages(ulong startingSequenceNumber)
	{
		if (startingSequenceNumber == this.outboundPacketSequence + 1)
		{
			// The recipient is already up-to-date.
			return Array.Empty<SshMessage>();
		}

		if (this.recentSentMessages.Count > 0 &&
			startingSequenceNumber < this.recentSentMessages.Peek().Sequence)
		{
			// The cached recent messages do not go back as far as the requested sequence number.
			// This should never happen because messages are not dropped from this list until
			// the other side acknowledges they have been received, so they should not be
			// requested again after reconnecting.
			return null;
		}

		// Return all messages starting with the requested sequence number.
		// Exclude key exchange messages because they cannot be retransmitted; a reconnected
		// session will do key exchange separately. Also exclude any disconnect messages that
		// may have been attempted when the connection was lost.
		return this.recentSentMessages
			.Where((m) => m.Sequence >= startingSequenceNumber)
			.Select((m) => m.Message)
			.Where((m) => !(m is KeyExchangeMessage || m is DisconnectMessage))
			.ToArray();
	}

	internal async Task<string> ReadProtocolVersionAsync(CancellationToken cancellation)
	{
		var stream = this.stream;
		if (stream == null)
		{
			throw new ObjectDisposedException(nameof(Stream));
		}

		// http://tools.ietf.org/html/rfc4253#section-4.2
		var buffer = new Buffer(255).Array;
		int lineCount = 0;
		for (int i = 0; i < buffer.Length; i++)
		{
#if SSH_ENABLE_SPAN
			int len = await stream.ReadAsync(buffer.AsMemory(i, 1), cancellation)
#else
			int len = await stream.ReadAsync(buffer, i, 1, cancellation)
#endif
					.ConfigureAwait(false);
			if (len == 0)
			{
				break;
			}

			const byte CarriageReturn = 0x0d;
			const byte LineFeed = 0x0a;
			if (i > 0 && buffer[i - 1] == CarriageReturn && buffer[i] == LineFeed)
			{
				var line = Encoding.UTF8.GetString(buffer, 0, i - 1);
				if (line.StartsWith("SSH-", StringComparison.Ordinal))
				{
					this.metrics.AddMessageReceived(i + 1);
					return line;
				}
				else if (lineCount > 20)
				{
					// Give up if a version string was not found after 20 lines.
					break;
				}
				else
				{
					// Ignore initial lines before the version line.
					lineCount++;
					i = -1;
				}
			}
		}

		throw new SshConnectionException(
			"Failed to read the protocol version", SshDisconnectReason.ProtocolError);
	}

	internal async Task WriteProtocolVersionAsync(
		string version, CancellationToken cancellation)
	{
		var stream = this.stream;
		if (stream == null)
		{
			throw new ObjectDisposedException(nameof(Stream));
		}

		byte[] data = Encoding.ASCII.GetBytes(version + "\r\n");
#if SSH_ENABLE_SPAN
		await stream.WriteAsync(data.AsMemory(), cancellation)
#else
		await stream.WriteAsync(data, 0, data.Length, cancellation)
#endif
				.ConfigureAwait(false);
		await stream.FlushAsync(cancellation).ConfigureAwait(false);

		this.metrics.AddMessageSent(data.Length);
	}

	/// <summary>
	/// Attempts to read from the stream until the buffer is full.
	/// </summary>
	/// <returns>True if the read succeeded, false if the stream was disposed.</returns>
	/// <exception cref="SshConnectionException">The read failed for any other
	/// reason.</exception>
	private async Task<bool> ReadAsync(Buffer buffer, CancellationToken cancellation)
	{
		var stream = this.stream;
		if (stream == null)
		{
			return false;
		}

		int offset = 0;
		while (offset < buffer.Count)
		{
			try
			{
#if SSH_ENABLE_SPAN
				var count = await stream.ReadAsync(
					buffer.Memory.Slice(offset),
#else
				var count = await stream.ReadAsync(
					buffer.Array,
					buffer.Offset + offset,
					buffer.Count - offset,
#endif
					cancellation).ConfigureAwait(false);
				if (count == 0)
				{
					return false;
				}

				offset += count;
			}
			catch (ObjectDisposedException)
			{
				this.stream = null;
				return false;
			}
			catch (Exception ex)
			{
				stream.Dispose();
				this.stream = null;
				this.trace.TraceEvent(
					TraceEventType.Verbose, SshTraceEventIds.StreamReadError, ex.ToString());
				throw new SshConnectionException(
					"Connection lost.", SshDisconnectReason.ConnectionLost, ex);
			}
		}

		return true;
	}

	/// <summary>
	/// Attempts to write a buffer to the stream.
	/// </summary>
	/// <returns>True if the write succeeded, false if the stream was disposed.</returns>
	/// <exception cref="SshConnectionException">The write failed for any other
	/// reason.</exception>
	private async Task<bool> WriteAsync(Buffer data, bool flush, CancellationToken cancellation)
	{
		var stream = this.stream;
		if (stream == null)
		{
			return false;
		}

		try
		{
#if SSH_ENABLE_SPAN
			await stream.WriteAsync(data.Memory, cancellation)
#else
			await stream.WriteAsync(data.Array, data.Offset, data.Count, cancellation)
#endif
					.ConfigureAwait(false);
			if (flush)
			{
				await stream.FlushAsync(cancellation).ConfigureAwait(false);
			}

			return true;
		}
		catch (ObjectDisposedException)
		{
			this.stream = null;
			return false;
		}
		catch (Exception ex)
		{
			stream.Dispose();
			this.stream = null;
			this.trace.TraceEvent(
				TraceEventType.Verbose, SshTraceEventIds.StreamWriteError, ex.ToString());
			throw new SshConnectionException(
				"Connection lost.", SshDisconnectReason.ConnectionLost, ex);
		}
	}

	internal async Task HandleNewKeysMessageAsync(CancellationToken cancellation)
	{
		await this.sessionSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			this.inboundFlow = 0;
			this.outboundFlow = 0;

			Algorithms = KeyExchangeService!.FinishKeyExchange();
		}
		finally
		{
			this.sessionSemaphore.Release();
		}
	}

	/// <summary>
	/// Attemps to read one message from the stream.
	/// </summary>
	/// <returns>The message, or null if the stream was disposed.</returns>
	/// <exception cref="SshConnectionException">Reading from the stream failed for
	/// any other reason.</exception>
	internal async Task<SshMessage?> ReceiveMessageAsync(CancellationToken cancellation)
	{
		var algorithms = this.Algorithms;
		var compression = algorithms?.Decompressor;
		var encryption = algorithms?.Decipher;
		var hmac = algorithms?.MessageVerifier;

		// The packet length is not encrypted when in EtM or AEAD mode.
		// So read only the length bytes first, separate from the remaining payload.
		var isLengthEncrypted = !(hmac?.EncryptThenMac == true ||
			hmac?.AuthenticatedEncryption == true);

		var firstBlockSize = (byte)(!isLengthEncrypted ? PacketLengthSize
			: Math.Max(8, encryption?.BlockLength ?? 8));

		Buffer firstBlock = this.receiveReader.Buffer.Slice(SequenceNumberSize, firstBlockSize);
		if (!(await ReadAsync(firstBlock, cancellation).ConfigureAwait(false)))
		{
			return null;
		}

		var receivedTime = this.metrics.Time;

		if (encryption != null && isLengthEncrypted)
		{
			try
			{
				encryption.Transform(firstBlock, firstBlock);
			}
			catch (ObjectDisposedException)
			{
				return null; // The protocol and algorithms were disposed while receiving.
			}
		}

		this.receiveReader.Position = SequenceNumberSize;
		uint packetLength = this.receiveReader.ReadUInt32();

		if (packetLength > MaxPacketLength)
		{
			throw new SshConnectionException(
				"Invalid packet length.", SshDisconnectReason.ProtocolError);
		}

		Buffer packet;
		int packetBufferSize = (int)(SequenceNumberSize + PacketLengthSize + packetLength);
		if (this.receiveReader.Buffer.Count < packetBufferSize)
		{
			var expandedBuffer = this.receiveReader.Buffer;
			Buffer.Expand(ref expandedBuffer, packetBufferSize);
			this.receiveReader = new SshDataReader(expandedBuffer);
		}

		var packetWithSequence = this.receiveReader.Buffer.Slice(0, packetBufferSize);
		packet = packetWithSequence.Slice(
			SequenceNumberSize, packetWithSequence.Count - SequenceNumberSize);

		var followingBlocks = packet.Slice(firstBlockSize, packet.Count - firstBlockSize);
		if (followingBlocks.Count > 0)
		{
			if (!(await ReadAsync(followingBlocks, cancellation).ConfigureAwait(false)))
			{
				return null;
			}

			if (hmac?.EncryptThenMac == true)
			{
				// In EtM mode, read and verify the MAC before decrypting.
				if (!(await ReadAndVerifyHmacAsync(hmac, packetWithSequence, cancellation)
					.ConfigureAwait(false)))
				{
					return null;
				}
			}

			if (encryption != null)
			{
				if (hmac?.AuthenticatedEncryption == true)
				{
					// With a GCM cipher, the MAC is required for decryption.
					var gcmTag = this.receiveHmacBuffer.Slice(0, hmac.DigestLength);
					if (!(await ReadAsync(gcmTag, cancellation).ConfigureAwait(false)))
					{
						return null;
					}

					// This doesn't actually verify anything yet (hence the return value is not checked);
					// it sets the tag that will be used for verification in the following Transform call.
					hmac.Verify(followingBlocks, gcmTag);
				}

				try
				{
					encryption.Transform(followingBlocks, followingBlocks);
				}
				catch (CryptographicException ex) when (hmac?.AuthenticatedEncryption == true)
				{
					// GCM decryption failed to verify data + tag.
					throw new SshConnectionException("Invalid MAC", SshDisconnectReason.MacError, ex);
				}
				catch (ObjectDisposedException)
				{
					return null; // The protocol and algorithms were disposed while receiving.
				}
			}
		}

		this.receiveReader.Position = SequenceNumberSize + PacketLengthSize;
		byte paddingLength = this.receiveReader.ReadByte();
		var payload = packet.Slice(
			PacketLengthSize + PaddingLengthSize,
			(int)(packetLength - PaddingLengthSize - paddingLength));

		if (hmac?.EncryptThenMac == false && hmac?.AuthenticatedEncryption == false)
		{
			if (!(await ReadAndVerifyHmacAsync(hmac, packetWithSequence, cancellation)
				.ConfigureAwait(false)))
			{
				return null;
			}
		}

		if (compression != null)
		{
			payload = compression.Decompress(payload);
		}

		if (IncomingMessagesHaveReconnectInfo)
		{
			// Read the extension info from the end of the payload.
			ulong lastSequenceSeenByRemote;
			uint remoteTimeSinceLastReceived;

			if (IncomingMessagesHaveLatencyInfo)
			{
				var reader = new SshDataReader(payload.Slice(payload.Count - 12, 12));
				lastSequenceSeenByRemote = reader.ReadUInt64();
				remoteTimeSinceLastReceived = reader.ReadUInt32();
				payload = payload.Slice(0, payload.Count - 12);
			}
			else
			{
				var reader = new SshDataReader(payload.Slice(payload.Count - 8, 8));
				lastSequenceSeenByRemote = reader.ReadUInt64();
				remoteTimeSinceLastReceived = 0;
				payload = payload.Slice(0, payload.Count - 8);
			}

			lock (this.recentSentMessages)
			{
				// Discard any recently sent messages that were acknowledged.
				while (this.recentSentMessages.Count > 0)
				{
					var oldestSequenceMessage = this.recentSentMessages.Peek();
					if (oldestSequenceMessage.Sequence > lastSequenceSeenByRemote)
					{
						break;
					}

					if (this.stream != null && IncomingMessagesHaveLatencyInfo &&
						oldestSequenceMessage.Sequence == lastSequenceSeenByRemote)
					{
						// Compute the time since the message with the last-seen sequence was sent.
						// Subtract the time (already in microseconds) between when the remote side
						// received the msg with the last-seen sequence and sent the current message.
						var timeSinceSent = receivedTime - oldestSequenceMessage.SentTime;
						var roundTripLatency = (int)Math.Min(
							int.MaxValue, timeSinceSent - remoteTimeSinceLastReceived);

						this.metrics.UpdateLatency(roundTripLatency, this.trace);
					}

					this.recentSentMessages.Dequeue();
				}
			}
		}

		var messageType = payload[0];
		SshMessage? message = SshMessage.TryCreate(this.config, messageType, MessageContext);
		if (message != null)
		{
			var reader = new SshDataReader(payload);
			message.Read(ref reader);
		}
		else
		{
			message = new UnimplementedMessage
			{
				SequenceNumber = unchecked((uint)this.inboundPacketSequence),
				UnimplementedMessageType = messageType,
			};
		}

		await this.sessionSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			this.lastIncomingTimestamp = receivedTime;
			this.inboundPacketSequence++;
			this.inboundFlow += packetLength;
		}
		finally
		{
			this.sessionSemaphore.Release();
		}

		this.metrics.AddMessageReceived(
			PacketLengthSize + (int)packetLength + hmac?.DigestLength ?? 0);

		if (!(message is ChannelDataMessage))
		{
			this.trace.TraceEvent(
				TraceEventType.Verbose,
				SshTraceEventIds.ReceivingMessage,
				$"Receiving #{this.inboundPacketSequence - 1} {message}");
		}
		else if (TraceChannelData)
		{
			this.trace.TraceEvent(
				TraceEventType.Verbose,
				SshTraceEventIds.ReceivingChannelData,
				$"Receiving #{this.inboundPacketSequence - 1} {message}");
		}

		await ConsiderReExchangeAsync(initial: false, cancellation).ConfigureAwait(false);

		return message;
	}

	/// <summary>
	/// Attemps to write one message to the stream.
	/// </summary>
	/// <returns>True if writing succeeded, false if the stream was disposed.</returns>
	/// <exception cref="SshConnectionException">Writing to the stream failed for
	/// any other reason.</exception>
	internal async Task<bool> SendMessageAsync(SshMessage message, CancellationToken cancellation)
	{
		var algorithms = this.Algorithms;
		var compression = algorithms?.Compressor;
		var encryption = algorithms?.Cipher;
		var hmac = algorithms?.MessageSigner;

		bool result;
		await this.sessionSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			var blockSize = (byte)Math.Max(8, encryption?.BlockLength ?? 8);

			// Start by writing the uncompressed payload to the buffer at the correct offset.
			int payloadOffset = SequenceNumberSize + PacketLengthSize + PaddingLengthSize;
			this.sendWriter.Position = payloadOffset;
			message.Write(ref this.sendWriter);

			if (OutgoingMessagesHaveReconnectInfo)
			{
				// Write the sequence number of the last inbound packet processed.
				this.sendWriter.Write(LastIncomingSequence);

				if (OutgoingMessagesHaveLatencyInfo)
				{
					// Write the time in microseconds since last packet was received.
					var timeSinceLastReceivedMessage = (uint)Math.Min(
						uint.MaxValue, this.metrics.Time - this.lastIncomingTimestamp);
					this.sendWriter.Write(timeSinceLastReceivedMessage);
				}
			}

			var payload = this.sendWriter.Buffer.Slice(
				payloadOffset, this.sendWriter.Position - payloadOffset);

			if (compression != null)
			{
				payload = compression.Compress(payload);
			}

			// The packet length is not encrypted when in EtM or AEAD mode.
			var isLengthEncrypted = !(hmac?.EncryptThenMac == true ||
				hmac?.AuthenticatedEncryption == true);

			// http://tools.ietf.org/html/rfc4253
			// 6.  Binary Packet Protocol
			// the total length of (packet_length || padding_length || payload || padding)
			// is a multiple of the cipher block size or 8,
			// padding length must between 4 and 255 bytes.
			var paddingLength = (byte)(blockSize - (((isLengthEncrypted ? PacketLengthSize : 0)
				+ PaddingLengthSize + payload.Count) % blockSize));
			if (paddingLength < 4)
			{
				paddingLength += blockSize;
			}

			var packetLength = PaddingLengthSize + (uint)payload.Count + paddingLength;

			this.sendWriter.Position = SequenceNumberSize;
			this.sendWriter.Write(packetLength);
			this.sendWriter.Write(paddingLength);

			// The uncompressed payload was already written at the correct offset.
			// When compression is enabled, rewrite the compressed payload.
			if (compression != null)
			{
				this.sendWriter.Write(payload);
			}
			else
			{
				this.sendWriter.Position += payload.Count;
			}

			this.sendWriter.WriteRandom(paddingLength);
			var packetWithSequence = this.sendWriter.ToBuffer();
			var packet = packetWithSequence.Slice(
				SequenceNumberSize, packetWithSequence.Count - SequenceNumberSize);

			if (!(message is ChannelDataMessage))
			{
				this.trace.TraceEvent(
					TraceEventType.Verbose,
					SshTraceEventIds.SendingMessage,
					$"Sending #{this.outboundPacketSequence} {message}");
			}
			else if (TraceChannelData)
			{
				this.trace.TraceEvent(
					TraceEventType.Verbose,
					SshTraceEventIds.SendingChannelData,
					$"Sending #{this.outboundPacketSequence} {message}");
			}

			var sequence = this.outboundPacketSequence;
			var sequencedMessage = new SequencedMessage(sequence, message);
			this.outboundPacketSequence++;
			this.outboundFlow += packetLength;

			Buffer mac = default;
			try
			{
				if (hmac?.EncryptThenMac == true && encryption != null)
				{
					// In EtM mode, compute the MAC after encrypting. And don't encrypt the length.
					var packetWithoutLength = packet.Slice(
						PacketLengthSize, packet.Count - PacketLengthSize);
					encryption!.Transform(packetWithoutLength, packetWithoutLength);
					mac = ComputeHmac(hmac, packetWithSequence, sequence, this.sendHmacBuffer);
				}
				else if (hmac?.AuthenticatedEncryption == true)
				{
					// With a GCM cipher, the packet length is not included in the plaintext.
					var packetWithoutLength = packet.Slice(
						PacketLengthSize, packet.Count - PacketLengthSize);
					encryption!.Transform(packetWithoutLength, packetWithoutLength);

					// The GCM tag was already generated during the Transform call above;
					// this just retrieves it.
					mac = this.sendHmacBuffer.Slice(0, hmac.DigestLength);
					hmac.Sign(packetWithoutLength, mac);
				}
				else
				{
					if (hmac != null)
					{
						mac = ComputeHmac(hmac, packetWithSequence, sequence, this.sendHmacBuffer);
					}

					if (encryption != null)
					{
						encryption.Transform(packet, packet);
					}
				}
			}
			catch (ObjectDisposedException)
			{
				return false; // The protocol and algorithms were disposed while receiving.
			}

			sequencedMessage.SentTime = this.metrics.Time;
			if (this.IncomingMessagesHaveReconnectInfo)
			{
				lock (this.recentSentMessages)
				{
					// Save sent messages in case they need to be re-sent after reconnect.
					// They'll be discarded soon, after the other side acknowledges them.
					this.recentSentMessages.Enqueue(sequencedMessage);
				}
			}

			if (mac.Count == 0)
			{
				result = await WriteAsync(packet, flush: true, cancellation).ConfigureAwait(false);
			}
			else
			{
				result = await WriteAsync(packet, flush: false, cancellation).ConfigureAwait(false);
				if (result)
				{
					result = await WriteAsync(mac, flush: true, cancellation).ConfigureAwait(false);
				}
			}

			this.metrics.AddMessageSent(
				PacketLengthSize + (int)packetLength + hmac?.DigestLength ?? 0);
		}
		finally
		{
			this.sessionSemaphore.TryRelease();
		}

		await ConsiderReExchangeAsync(initial: false, cancellation).ConfigureAwait(false);
		return result;
	}

	private static Buffer ComputeHmac(
		ISigner signer,
		Buffer packetWithSequence,
		ulong seq,
		Buffer hmacBuffer)
	{
		if (signer == null)
		{
			return Buffer.Empty;
		}

		var writer = new SshDataWriter(packetWithSequence);
		writer.Write(unchecked((uint)seq));

		Buffer mac = hmacBuffer.Slice(0, signer.DigestLength);
		signer.Sign(packetWithSequence, mac);
		return mac;
	}

	private static bool VerifyHmac(
		IVerifier verifier, Buffer packetWithSequence, ulong seq, Buffer signature)
	{
		if (verifier == null)
		{
			return true;
		}

		var writer = new SshDataWriter(packetWithSequence);
		writer.Write(unchecked((uint)seq));

		return verifier.Verify(packetWithSequence, signature);
	}

	private async Task<bool> ReadAndVerifyHmacAsync(
		IVerifier hmac,
		Buffer packetWithSequence,
		CancellationToken cancellation)
	{
		var mac = this.receiveHmacBuffer.Slice(0, hmac.DigestLength);
		if (!(await ReadAsync(mac, cancellation).ConfigureAwait(false)))
		{
			return false;
		}

		try
		{
			bool verified = VerifyHmac(hmac, packetWithSequence, this.inboundPacketSequence, mac);
			if (!verified)
			{
				throw new SshConnectionException("Invalid MAC", SshDisconnectReason.MacError);
			}
		}
		catch (ObjectDisposedException)
		{
			return false; // The protocol and algorithms were disposed while receiving.
		}

		return true;
	}

	internal async Task ConsiderReExchangeAsync(bool initial, CancellationToken cancellation)
	{
		var kexService = KeyExchangeService;
		if (kexService == null)
		{
			return;
		}

		KeyExchangeInitMessage? kexMessage = null;
		KeyExchangeDhInitMessage? kexGuessMessage = null;
		await this.sessionSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			if (!kexService.Exchanging && (initial ||
				(this.inboundFlow + this.outboundFlow) > this.config.KeyRotationThreshold))
			{
				(kexMessage, kexGuessMessage) = kexService.StartKeyExchange(initial);
			}
		}
		finally
		{
			this.sessionSemaphore.Release();
		}

		if (kexMessage != null)
		{
			await SendMessageAsync(kexMessage, cancellation).ConfigureAwait(false);

			if (kexGuessMessage != null)
			{
				await SendMessageAsync(kexGuessMessage, cancellation).ConfigureAwait(false);
			}
		}
	}

	public void Disconnect()
	{
		try
		{
			this.stream?.Close();
		}
		catch (Exception ex)
		{
			this.trace.TraceEvent(
				TraceEventType.Error, SshTraceEventIds.StreamCloseError, ex.ToString());
		}

		// Lock on the collection while resetting the stream and latency, to avoid
		// a timing issue that could otherwise prevent latency from being reset.
		lock (this.recentSentMessages)
		{
			this.stream = null;
			this.metrics.UpdateLatency(0);
		}
	}

	public void Dispose()
	{
		this.Disconnect();
		Algorithms?.Dispose();

		// SemaphoreSlim.Dispose() is not thread-safe and may cause WaitAsync(CancellationToken) not being cancelled
		// when SemaphoreSlim.Dispose is invoked immediately after CancellationTokenSource.Cancel.
		// See https://github.com/dotnet/runtime/issues/59639
		// SemaphoreSlim.Dispose() only disposes it's wait handle, which is not initialized unless its AvailableWaitHandle
		// property is read, which we don't use.

		// this.sessionSemaphore.Dispose();
	}
}
