// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Services;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Specifies the sets of algorithms and other configuration for an SSH session.
/// </summary>
/// <remarks>
/// Each collection of algorithms is in order of preference. Server and client
/// negotiate the most-preferred algorithm that is supported by both.
/// </remarks>
public class SshSessionConfiguration
{
	public static readonly SshSessionConfiguration Default =
		new SshSessionConfiguration(useSecurity: true).Lock();

	public static readonly SshSessionConfiguration DefaultWithReconnect =
		new SshSessionConfiguration(
			useSecurity: true, enableCompression: false, enableReconnect: true).Lock();

	public static readonly SshSessionConfiguration NoSecurity =
		new SshSessionConfiguration(useSecurity: false).Lock();

	private bool locked;
	private bool enableKeyExchangeGuess;
	private int maxClientAuthenticationAttempts = 5;
	private int keepAliveTimeoutInSeconds = 0;

	public SshSessionConfiguration(
		bool useSecurity = true,
		bool enableCompression = false,
		bool enableReconnect = false)
	{
		ProtocolExtensions = new SortedSet<string>();
		ProtocolExtensions.Add(SshProtocolExtensionNames.ServerSignatureAlgorithms);
		ProtocolExtensions.Add(SshProtocolExtensionNames.OpenChannelRequest);

		if (enableReconnect)
		{
			if (!useSecurity)
			{
				throw new ArgumentException(
					"Reconnecting requires security to be enabled.",
					nameof(enableReconnect));
			}

			ProtocolExtensions.Add(SshProtocolExtensionNames.SessionReconnect);
			ProtocolExtensions.Add(SshProtocolExtensionNames.SessionLatency);
		}

		Services = new Dictionary<Type, object?>();
		Services.Add(typeof(KeyExchangeService), null);
		Services.Add(typeof(ConnectionService), null);
		Services.Add(typeof(AuthenticationService), null);

		AuthenticationMethods = new List<string>
		{
			Ssh.Messages.AuthenticationMethods.None,
			Ssh.Messages.AuthenticationMethods.Password,
			Ssh.Messages.AuthenticationMethods.PublicKey,
			Ssh.Messages.AuthenticationMethods.KeyboardInteractive,
		};

		Messages = new Dictionary<byte, Type>(capacity: 40);
		ContextualMessages = new Dictionary<(byte, string), Type>(capacity: 4);
		RegisterMessages();

		KeyExchangeAlgorithms = new List<KeyExchangeAlgorithm?>();
		PublicKeyAlgorithms = new List<PublicKeyAlgorithm?>();
		EncryptionAlgorithms = new List<EncryptionAlgorithm?>();
		HmacAlgorithms = new List<HmacAlgorithm?>();
		CompressionAlgorithms = new List<CompressionAlgorithm?>();

		if (useSecurity)
		{
#if SSH_ENABLE_ECDH
			KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.EcdhNistp384);
			KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.EcdhNistp256);
#endif
			KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.DHGroup16Sha512);
			KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.DHGroup14Sha256);
			PublicKeyAlgorithms.Add(SshAlgorithms.PublicKey.RsaWithSha512);
			PublicKeyAlgorithms.Add(SshAlgorithms.PublicKey.RsaWithSha256);
			PublicKeyAlgorithms.Add(SshAlgorithms.PublicKey.ECDsaSha2Nistp384);
			PublicKeyAlgorithms.Add(SshAlgorithms.PublicKey.ECDsaSha2Nistp256);
#if SSH_ENABLE_AESGCM
			EncryptionAlgorithms.Add(SshAlgorithms.Encryption.Aes256Gcm);
#endif
			EncryptionAlgorithms.Add(SshAlgorithms.Encryption.Aes256Cbc);
			EncryptionAlgorithms.Add(SshAlgorithms.Encryption.Aes256Ctr);
			HmacAlgorithms.Add(SshAlgorithms.Hmac.HmacSha512Etm);
			HmacAlgorithms.Add(SshAlgorithms.Hmac.HmacSha256Etm);
			HmacAlgorithms.Add(SshAlgorithms.Hmac.HmacSha512);
			HmacAlgorithms.Add(SshAlgorithms.Hmac.HmacSha256);
		}
		else
		{
			KeyExchangeAlgorithms.Add(SshAlgorithms.KeyExchange.None);
			PublicKeyAlgorithms.Add(SshAlgorithms.PublicKey.None);
			EncryptionAlgorithms.Add(SshAlgorithms.Encryption.None);
			HmacAlgorithms.Add(SshAlgorithms.Hmac.None);
		}

		CompressionAlgorithms.Add(SshAlgorithms.Compression.None);
		if (enableCompression)
		{
			// TODO: Add compression algorithm(s).
		}
	}

	private void RegisterMessages()
	{
		// Adding these messages by number avoids use of reflection to retrieve the message number
		// from each type's [SssMessage] attribute. Message subclasses that do not have distinct
		// message numbers are not registered here.

		AddMessage(typeof(DisconnectMessage), DisconnectMessage.MessageNumber);
		AddMessage(typeof(IgnoreMessage), IgnoreMessage.MessageNumber);
		AddMessage(typeof(UnimplementedMessage), UnimplementedMessage.MessageNumber);
		AddMessage(typeof(DebugMessage), DebugMessage.MessageNumber);
		AddMessage(typeof(ServiceRequestMessage), ServiceRequestMessage.MessageNumber);
		AddMessage(typeof(ServiceAcceptMessage), ServiceAcceptMessage.MessageNumber);
		AddMessage(typeof(ExtensionInfoMessage), ExtensionInfoMessage.MessageNumber);

		AddMessage(typeof(KeyExchangeInitMessage), KeyExchangeInitMessage.MessageNumber);
		AddMessage(typeof(NewKeysMessage), NewKeysMessage.MessageNumber);
		AddMessage(typeof(KeyExchangeDhInitMessage), KeyExchangeDhInitMessage.MessageNumber);
		AddMessage(typeof(KeyExchangeDhReplyMessage), KeyExchangeDhReplyMessage.MessageNumber);

		AddMessage(typeof(AuthenticationRequestMessage), AuthenticationRequestMessage.MessageNumber);
		AddMessage(typeof(AuthenticationFailureMessage), AuthenticationFailureMessage.MessageNumber);
		AddMessage(typeof(AuthenticationSuccessMessage), AuthenticationSuccessMessage.MessageNumber);

		// Some authentication message numbers (60-69) may be re-used for different message types
		// depending on the current authentication context.
		AddMessage(
			typeof(PublicKeyOkMessage),
			PublicKeyOkMessage.MessageNumber,
			Ssh.Messages.AuthenticationMethods.PublicKey);
		AddMessage(
			typeof(AuthenticationInfoRequestMessage),
			AuthenticationInfoRequestMessage.MessageNumber,
			Ssh.Messages.AuthenticationMethods.KeyboardInteractive);
		AddMessage(
			typeof(AuthenticationInfoResponseMessage),
			AuthenticationInfoResponseMessage.MessageNumber,
			Ssh.Messages.AuthenticationMethods.KeyboardInteractive);

		AddMessage(typeof(SessionRequestMessage), SessionRequestMessage.MessageNumber);
		AddMessage(typeof(SessionRequestSuccessMessage), SessionRequestSuccessMessage.MessageNumber);
		AddMessage(typeof(SessionRequestFailureMessage), SessionRequestFailureMessage.MessageNumber);

		AddMessage(typeof(ChannelOpenMessage), ChannelOpenMessage.MessageNumber);
		AddMessage(typeof(ChannelOpenConfirmationMessage), ChannelOpenConfirmationMessage.MessageNumber);
		AddMessage(typeof(ChannelOpenFailureMessage), ChannelOpenFailureMessage.MessageNumber);
		AddMessage(typeof(ChannelWindowAdjustMessage), ChannelWindowAdjustMessage.MessageNumber);
		AddMessage(typeof(ChannelDataMessage), ChannelDataMessage.MessageNumber);
		AddMessage(typeof(ChannelEofMessage), ChannelEofMessage.MessageNumber);
		AddMessage(typeof(ChannelCloseMessage), ChannelCloseMessage.MessageNumber);
		AddMessage(typeof(ChannelRequestMessage), ChannelRequestMessage.MessageNumber);
		AddMessage(typeof(ChannelSuccessMessage), ChannelSuccessMessage.MessageNumber);
		AddMessage(typeof(ChannelFailureMessage), ChannelFailureMessage.MessageNumber);
	}

	/// <summary>
	/// Locks this configuration instance to prevent further modifications.
	/// </summary>
	/// <returns>The same instance.</returns>
	private SshSessionConfiguration Lock()
	{
		ProtocolExtensions = new List<string>(ProtocolExtensions).AsReadOnly();
		Services = new ReadOnlyDictionary<Type, object?>(Services);
		KeyExchangeAlgorithms = new ReadOnlyCollection<KeyExchangeAlgorithm?>(
			(IList<KeyExchangeAlgorithm?>)KeyExchangeAlgorithms);
		PublicKeyAlgorithms = new ReadOnlyCollection<PublicKeyAlgorithm?>(
			(IList<PublicKeyAlgorithm?>)PublicKeyAlgorithms);
		EncryptionAlgorithms = new ReadOnlyCollection<EncryptionAlgorithm?>(
			(IList<EncryptionAlgorithm?>)EncryptionAlgorithms);
		HmacAlgorithms = new ReadOnlyCollection<HmacAlgorithm?>(
			(IList<HmacAlgorithm?>)HmacAlgorithms);
		CompressionAlgorithms =
			new ReadOnlyCollection<CompressionAlgorithm?>(
				(IList<CompressionAlgorithm?>)CompressionAlgorithms);
		this.locked = true;
		return this;
	}

	/// <summary>
	/// Throws an exception if this configuration instance is locked.
	/// </summary>
	/// <returns>The same instance.</returns>
	internal SshSessionConfiguration EnsureUnlocked()
	{
		if (this.locked)
		{
			throw new InvalidOperationException(
				"The configuration instance is locked.");
		}

		return this;
	}

	/// <summary>
	/// Gets the protocol extensions that are enabled for the session.
	/// </summary>
	public ICollection<string> ProtocolExtensions { get; private set; }

	/// <summary>
	/// Gets a dictionary that maps from service types to service configuration objects.
	/// </summary>
	/// <remarks>
	/// Service types must extend the <see cref="SshService" /> abstract class and have a
	/// public constructor that takes a <see cref="SshSession"/> parameter and optionally
	/// a configuration parameter.
	/// <para/>
	/// The type of each service configuration object (value in the dictionary) must match the
	/// type of the service constructor's configuration parameter, or must be null if the service
	/// constructor does not accept a configuration parameter.
	/// <para/>
	/// Applications that enable member-level trimming must call <see cref="AddService"/> instead
	/// of adding directly to this dictionary.
	/// </remarks>
	public IDictionary<Type, object?> Services { get; private set; }

	/// <summary>
	/// Adds a service type to the configuration.
	/// </summary>
	/// <param name="serviceType">Service type that extends the <see cref="SshService" /> abstract
	/// class and has a public constructor that takes a <see cref="SshSession"/> parameter and
	/// optionally a configuration parameter.</param>
	/// <param name="serviceConfig">Configuration object passed to the service constructor on
	/// activation; must match the type of the service constructor's configuration parameter, or
	/// must be null if the service constructor does not accept a configuration parameter.</param>
	/// <remarks>
	/// Applications that enable member-level trimming must use this method to add services
	/// instead of adding directly to the <see cref="Services"/> dictionary.
	/// </remarks>
	public void AddService(
#if NET6_0_OR_GREATER
		[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
#endif
		Type serviceType,
		object? serviceConfig = null)
	{
		if (serviceType == null) throw new ArgumentNullException(nameof(serviceType));

		if (!typeof(SshService).IsAssignableFrom(serviceType))
		{
			throw new ArgumentException(
				"Service type must be a subclass of SshService.", nameof(serviceType));
		}

		Services.Add(serviceType, serviceConfig);
	}

	/// <summary>
	/// Gets the list of enabled authentication methods.
	/// </summary>
	/// <remarks>
	/// Add or remove constants from <see cref="Ssh.Messages.AuthenticationMethods" /> to restrict
	/// which client authentication methods the client will try or the server will allow. In any
	/// case, the client or server must handle the <see cref="SshSession.Authenticating" /> event
	/// to perform authentication.
	/// </remarks>
	public ICollection<string> AuthenticationMethods { get; private set; }

	/// <summary>
	/// Gets a dictionary that maps from known message numbers to message types.
	/// </summary>
	/// <remarks>
	/// Message types must extend the <see cref="SshMessage"/> abstract class and have a
	/// public parameter-less constructor.
	/// <para/>
	/// Message subclasses that do not have a distinct message type from their base class
	/// must not be included in this dictionary.
	/// </remarks>
	public IDictionary<byte, Type> Messages { get; }

	/// <summary>
	/// Gets a dictionary that maps from message number and context tuples to message types.
	/// </summary>
	/// <remarks>
	/// Services like <see cref="AuthenticationService" /> may set the current message context
	/// to disambiguate when the same message number may be re-used in different contexts.
	/// </remarks>
	public IDictionary<(byte MessageType, string MessageContext), Type> ContextualMessages { get; }

	/// <summary>
	/// Adds a message to the configuration.
	/// </summary>
	/// <param name="messageType">Message type that extends <see cref="SshMessage"/>.</param>
	/// <remarks>
	/// The message type must be decorated with a <see cref="SshMessageAttribute"/> that
	/// specifies the message number.
	/// </remarks>
	public void AddMessage(
#if NET6_0_OR_GREATER
		[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
#endif
		Type messageType)
	{
		if (messageType == null) throw new ArgumentNullException(nameof(messageType));

		if (!typeof(SshMessage).IsAssignableFrom(messageType))
		{
			throw new ArgumentException(
				"Message type must be a subclass of SshMessage.", nameof(messageType));
		}

		var messageAttribute = (SshMessageAttribute?)messageType.GetCustomAttributes(
			typeof(SshMessageAttribute), false).FirstOrDefault();
		if (messageAttribute == null)
		{
			throw new ArgumentException(
				"Message type must have an SshMessage attribute.");
		}

		AddMessage(messageType, messageAttribute.Number);
	}

	/// <summary>
	/// Adds a message type to the configuration, with a known message number.
	/// </summary>
	private void AddMessage(
#if NET6_0_OR_GREATER
		[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
#endif
		Type messageType,
		byte messageNumber)
	{
		Messages.Add(messageNumber, messageType);
	}

	private void AddMessage(
#if NET6_0_OR_GREATER
		[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
#endif
		Type messageType,
		byte messageNumber,
		string messageContext)
	{
		ContextualMessages.Add((messageNumber, messageContext), messageType);
	}

	/// <summary>
	/// Gets the collection of algorithms that are enabled for key exchange.
	/// </summary>
	/// <remarks>
	/// Client and server sides negotiate which of these algorithms will be used.
	///
	/// If this collection includes `null`, and if negotiation selects it, then the session is
	/// allowed to skip key exchange and connect with no security of any kind: No key exchange,
	/// no authentication, no encryption, no HMAC, and no compression.
	/// </remarks>
	public ICollection<KeyExchangeAlgorithm?> KeyExchangeAlgorithms { get; private set; }

	/// <summary>
	/// Gets the collection of algorithms that are enabled for server (host) and client
	/// public-key authentication.
	/// </summary>
	/// <remarks>
	/// Client and server sides negotiate which of these algorithms will be used.
	/// </remarks>
	public ICollection<PublicKeyAlgorithm?> PublicKeyAlgorithms { get; private set; }

	/// <summary>
	/// Gets the collection of algorithms that are enabled for encryption.
	/// </summary>
	/// <remarks>
	/// Client and server sides negotiate which of these algorithms will be used.
	/// </remarks>
	public ICollection<EncryptionAlgorithm?> EncryptionAlgorithms { get; private set; }

	/// <summary>
	/// Gets the collection of algorithms that are enabled for message integrity (HMAC).
	/// </summary>
	/// <remarks>
	/// Client and server sides negotiate which of these algorithms will be used.
	/// </remarks>
	public ICollection<HmacAlgorithm?> HmacAlgorithms { get; private set; }

	/// <summary>
	/// Gets the collection of algorithms that are enabled for message compression.
	/// </summary>
	/// <remarks>
	/// Client and server sides negotiate which of these algorithms will be used.
	/// </remarks>
	public ICollection<CompressionAlgorithm?> CompressionAlgorithms { get; private set; }

	internal static IEnumerable<string> GetAlgorithmNamesList<T>(IEnumerable<T?> algorithms)
		where T : SshAlgorithm
	{
		return algorithms.Select((a) => a?.Name ?? "none").Distinct();
	}

	internal KeyExchangeAlgorithm? GetKeyExchangeAlgorithm(string? name)
	 => GetAlgorithm(KeyExchangeAlgorithms, name);

	internal PublicKeyAlgorithm? GetPublicKeyAlgorithm(string? name)
		=> GetAlgorithm(PublicKeyAlgorithms, name);

	internal EncryptionAlgorithm? GetEncryptionAlgorithm(string? name)
		=> GetAlgorithm(EncryptionAlgorithms, name);

	internal HmacAlgorithm? GetHmacAlgorithm(string? name)
		=> GetAlgorithm(HmacAlgorithms, name);

	internal CompressionAlgorithm? GetCompressionAlgorithm(string? name)
		=> GetAlgorithm(CompressionAlgorithms, name);

	private static T? GetAlgorithm<T>(
		ICollection<T?> algorithms, string? name) where T : SshAlgorithm
	{
		var alg = algorithms.FirstOrDefault(a => (a?.Name ?? "none") == name);
		if (name != "none" && (alg == null || alg?.IsAvailable == false))
		{
			throw new NotSupportedException($"{typeof(T).Name} not supported: {name}");
		}

		return alg;
	}

	internal IEnumerable<string> AvailableKeyExchangeAlgorithms =>
		GetAvailableAlgorithmNames(KeyExchangeAlgorithms);

	internal IEnumerable<string> AvailablePublicKeyAlgorithms =>
		GetAvailableAlgorithmNames(PublicKeyAlgorithms);

	internal IEnumerable<string> AvailableEncryptionAlgorithms =>
		GetAvailableAlgorithmNames(EncryptionAlgorithms);

	internal IEnumerable<string> AvailableHmacAlgorithms =>
		GetAvailableAlgorithmNames(HmacAlgorithms);

	internal IEnumerable<string> AvailableCompressionAlgorithms =>
		GetAvailableAlgorithmNames(CompressionAlgorithms);

	private static IEnumerable<string> GetAvailableAlgorithmNames<T>(
		ICollection<T?> algorithms) where T : SshAlgorithm
	{
		return algorithms.Where((a) => a?.IsAvailable != false)
			.Select((a) => a?.Name ?? "none");
	}

	/// <summary>
	/// Enables tracing of all channel data messages.
	/// </summary>
	/// <remarks>
	/// Unlike other configuration, this option may be adjusted any time while the session
	/// is active. Channel data tracing produces a large volume of trace events, so
	/// it is primarily meant only for debugging.
	/// </remarks>
	public bool TraceChannelData
	{
		get => this.traceChannelData;
		set
		{
			if (value != this.traceChannelData)
			{
				this.traceChannelData = value;
				ConfigurationChanged?.Invoke(this, EventArgs.Empty);
			}
		}
	}

	private bool traceChannelData;

	internal event EventHandler<EventArgs>? ConfigurationChanged;

	/// <summary>
	/// Gets or sets the number of times the server will allow a client to attempt to
	/// authenticate.
	/// </summary>
	/// <remarks>
	/// The default value is 5.
	///
	/// This setting applies only to server sessions. If the client has failed to authenticate
	/// after the maximum number of atttempts, the server will close the session.
	///
	/// The SSH protocol allows a client to make multiple attempts to authenticate with
	/// the server, e.g. to find which public key algorithm a server will support, or to
	/// retry a mis-typed password. This maximum prevents unlimited retries, which would
	/// make it easier to "guess" a password.
	///
	/// In certain applications the server may only support a single authentication method
	/// (which is not a typed password). Then it could be appropriate to set this value to 1.
	/// </remarks>
	public int MaxClientAuthenticationAttempts
	{
		get => this.maxClientAuthenticationAttempts;
		set => EnsureUnlocked().maxClientAuthenticationAttempts = value;
	}

	/// <summary>
	/// Gets or sets whether the client sends a key-exchange "guess" message before receiving
	/// the server's key-exchange algorithm preferences, slightly reducing the time to connect.
	/// </summary>
	/// <remarks>
	/// This setting only applies to client sessions. (The server always supports the option when
	/// used by a client.)
	///
	/// The "guess" mechanism is somewhat ambiguously defined in the SSH protocol spec, and as
	/// a result is not implemented or incorrectly implemented by some server implementations,
	/// including older versions of this library. Therefore it is disabled in the default
	/// configuration, and should only be enabled when connecting to a known-good server.
	/// </remarks>
	public bool EnableKeyExchangeGuess
	{
		get => this.enableKeyExchangeGuess;
		set => EnsureUnlocked().enableKeyExchangeGuess = value;
	}

	/// <summary>
	/// Gets or sets the timeout duration for keeping a connection alive in seconds. Ensures the connection is unlocked
	/// before setting the value.
	/// </summary>
	public int KeepAliveTimeoutInSeconds
	{
		get => this.keepAliveTimeoutInSeconds;
		set => EnsureUnlocked().keepAliveTimeoutInSeconds = value;
	}

	/// <summary>
	/// Gets or sets a value that determines how often keys will be rotated during a session.
	/// </summary>
	/// <remarks>
	/// This should only be changed for testing purposes.
	/// </remarks>
	internal int KeyRotationThreshold { get; set; } = 512 * 1024 * 1024; // 0.5 GiB
}
