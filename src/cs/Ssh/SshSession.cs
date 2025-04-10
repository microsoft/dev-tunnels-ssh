// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Events;
using Microsoft.DevTunnels.Ssh.IO;
using Microsoft.DevTunnels.Ssh.Messages;
using Microsoft.DevTunnels.Ssh.Metrics;
using Microsoft.DevTunnels.Ssh.Services;

namespace Microsoft.DevTunnels.Ssh;

/// <summary>
/// Base class for an SSH server or client connection; coordinates high-level SSH
/// protocol details and dispatches messages to registered internal services.
/// Enables opening and accepting `SshChannel` instances.
/// </summary>
[DebuggerDisplay("{ToString(),nq}")]
#pragma warning disable CA1506 // 'SshSession' is coupled with too many types.
public class SshSession : IDisposable
#pragma warning restore CA1506
{
	/// <summary>
	/// Allows SSH sessions to keep track of the session number for progress reporting purposes.
	/// </summary>
	private static int sessionCounter = 0;

	private readonly ConcurrentQueue<SshMessage> blockedMessages =
		new ConcurrentQueue<SshMessage>();

#pragma warning disable CA2213 // Disposable fields should be disposed
	private readonly SemaphoreSlim blockedMessagesSemaphore = new SemaphoreSlim(1);
	private readonly SemaphoreSlim sessionRequestSemaphore = new SemaphoreSlim(1);
#pragma warning restore CA2213 // Disposable fields should be disposed

	private readonly ConcurrentDictionary<Type, SshService> services =
		new ConcurrentDictionary<Type, SshService>();
	private KeyExchangeService? kexService;
	private TaskCompletionSource<bool>? connectCompletionSource;
	private readonly CancellationTokenSource disposeCancellationSource =
		new CancellationTokenSource();
	private readonly ConcurrentQueue<IRequestHandler> requestHandlers = new ();
	private readonly TaskChain taskChain;
	private Task? versionExchangeTask;
	private Exception? closedException;
	private int sessionNumber;
	private Timer? keepAliveTimer;
	private bool keepAliveResponseReceived = false;
	private int keepAliveFailureCount;

	/// <summary>
	/// Constructs a new SSH session.
	/// </summary>
	/// <remarks>
	/// This is internal because consumers of the API should be constructing
	/// `SshServerSession`/`SshClientSession` or `MultiChannelStream` instead.
	/// </remarks>
	internal SshSession(
		SshSessionConfiguration config,
		TraceSource trace)
	{
		if (config == null) throw new ArgumentNullException(nameof(config));
		if (trace == null) throw new ArgumentNullException(nameof(trace));

		Config = config;
		Trace = trace;
		this.taskChain = new TaskChain(Trace);
		this.sessionNumber = ++SshSession.sessionCounter;

		if (!Config.KeyExchangeAlgorithms.Any((a) => a != null))
		{
			if (Config.EncryptionAlgorithms.Count > 0 &&
				!Config.EncryptionAlgorithms.Contains(null))
			{
				throw new InvalidOperationException(
					"Encryption requires a key-exchange algorithm to be configured.");
			}
			else if (Config.HmacAlgorithms.Count > 0 && !Config.HmacAlgorithms.Contains(null))
			{
				throw new InvalidOperationException(
					"HMAC requires a key-exchange algorithm to be configured.");
			}
			else if (Config.PublicKeyAlgorithms.Count > 0 &&
				!Config.PublicKeyAlgorithms.Contains(null))
			{
				throw new InvalidOperationException(
					"Host authentication requires a key-exchange algorithm to be configured.");
			}

			// No key exchange, no encryption, no HMAC.
			this.kexService = null;
			ActivateService<ConnectionService>();
		}
		else
		{
			this.kexService = ActivateService<KeyExchangeService>();
		}

		Config.ConfigurationChanged += OnConfigurationChanged;
	}

	public SshSessionConfiguration Config { get; }

	public IEnumerable<SshService> Services => this.services.Values;

	public ICollection<SshChannel> Channels =>
		GetService<ConnectionService>()?.Channels ?? Array.Empty<SshChannel>();

	public bool IsConnected { get; private set; }

	public bool IsClosed { get; private set; }

	public TraceSource Trace { get; }

	/// <summary>
	/// Gets an object that reports current and cumulative measurements about the session.
	/// </summary>
	public SessionMetrics Metrics { get; } = new SessionMetrics();

	public static SshVersionInfo LocalVersion { get; } = SshVersionInfo.GetLocalVersion();

	public SshVersionInfo? RemoteVersion { get; private set; }

#pragma warning disable CA1819 // Properties should not return arrays
	public byte[]? SessionId { get; internal set; }
#pragma warning restore CA1819 // Properties should not return arrays

	/// <summary>
	/// Event that is raised when a client or server is requesting authentication.
	/// </summary>
	/// <remarks>
	/// See <see cref="SshAuthenticationType" /> for a description of the different authentication
	/// methods and how they map to the event-args object.
	///
	/// After validating the credentials, the event handler must set the
	/// <see cref="SshAuthenticatingEventArgs.AuthenticationTask" /> property to a task that
	/// resolves to a principal object to indicate successful authentication. That principal will
	/// then be associated with the session as the <see cref="Principal" /> property.
	/// </remarks>
	public event EventHandler<SshAuthenticatingEventArgs>? Authenticating;

	public event EventHandler<SshRequestEventArgs<SessionRequestMessage>>? Request;

	public event EventHandler<SshChannelOpeningEventArgs>? ChannelOpening;

	public event EventHandler<SshSessionClosedEventArgs>? Closed;

	/// <summary>
	/// Event raised when one of the <see cref="SshService" /> types from
	/// <see cref="SshSessionConfiguration.Services" /> is instantiated.
	/// </summary>
	public event EventHandler<SshService>? ServiceActivated;

	/// <summary>
	/// Event raised to report connection progress.
	/// </summary>
	public event EventHandler<SshReportProgressEventArgs>? ReportProgress;

	/// <summary>
	/// Event raised when a reconnectable session is disconnected but not closed.
	/// </summary>
	/// <remarks>
	/// When reconnect is enabled, a disconnected session does not get automatically closed
	/// (disposed).
	/// This event is NOT raised when a session is permanently closed (either because reconnect
	/// is not enabled or the connection failed too early for reconnection to be set up).
	/// </remarks>
	public event EventHandler<EventArgs>? Disconnected;

	/// <summary>
	/// Event is raised when a keep-alive request is sent but no response is received
	/// </summary>
	public event EventHandler<SshKeepAliveEventArgs>? KeepAliveRequestFailed;

	/// <summary>
	/// Internal event used for testing purposes.
	/// </summary>
	internal event EventHandler<EventArgs>? KeepAliveRequestReceived;

	/// <summary>
	/// Gets the set of protocol extensions (and their values) enabled for the current session.
	/// </summary>
	/// <remarks>
	/// Populated only after an (optional) ExtensionInfoMessage is received from the other side.
	/// </remarks>
	public IReadOnlyDictionary<string, string>? ProtocolExtensions => Protocol?.Extensions;

	/// <summary>
	/// Gets a principal containing claims about the server or client on the
	/// other end of the session, or null if the session is not authenticated.
	/// </summary>
	/// <remarks>
	/// This property is initially null for an unauthenticated session. On
	/// successful authentication, the session Authenticating event handler
	/// provides a Task that returns a principal that is stored here.
	/// </remarks>
	public ClaimsPrincipal? Principal { get; internal set; }

	internal SshProtocol? Protocol { get; set; }

	internal bool Reconnecting { get; set; }

	internal SshSessionAlgorithms? Algorithms => Protocol?.Algorithms;

	private void OnConfigurationChanged(object sender, EventArgs e)
	{
		var protocol = Protocol;
		if (protocol != null)
		{
			protocol.TraceChannelData = Config.TraceChannelData;
		}
	}

	/// <summary>
	/// Gets a session service by type, or null if the service is not configured or activated.
	/// </summary>
	/// <typeparam name="T">A subclass of <see cref="SshService"/>.</typeparam>
	public T? GetService<T>() where T : SshService
	{
		this.services.TryGetValue(typeof(T), out var service);
		return (T?)service;
	}

	/// <summary>
	/// Gets a session service by type, activating it if necessary.
	/// </summary>
	/// <typeparam name="T">A subclass of <see cref="SshService"/>.</typeparam>
	/// <exception cref="KeyNotFoundException">The service type is not configured.</exception>
	public T ActivateService<T>() where T : SshService
	{
		var serviceConfig = Config.Services[typeof(T)];
		return (T)ActivateService(typeof(T), serviceConfig);
	}

	internal SshService? ActivateService(string serviceName)
	{
		if (serviceName == null) throw new ArgumentNullException(nameof(serviceName));
		if (IsClosed) throw new ObjectDisposedException(nameof(SshSession));

		var (serviceType, serviceConfig) = ServiceActivationAttribute.FindService(
			Config.Services, (a) => a.ServiceRequest == serviceName);
		if (serviceType == null)
		{
			return null;
		}

		return ActivateService(serviceType, serviceConfig);
	}

	internal SshService ActivateService(Type serviceType, object? serviceConfig)
	{
		SshService service;
		bool activated = false;

		lock (this.disposeCancellationSource)
		{
			if (IsClosed) throw new ObjectDisposedException(nameof(SshSession));

			service = this.services.GetOrAdd(serviceType, (t) =>
			{
				activated = true;
				return SshService.Activate(this, t, serviceConfig);
			});
		}

		if (activated)
		{
			ServiceActivated?.Invoke(this, service);
		}

		return service;
	}

	internal bool UnregisterService<T>() where T : SshService
	{
		if (this.services.TryRemove(typeof(T), out var service))
		{
			service?.Dispose();
			return true;
		}
		else
		{
			return false;
		}
	}

	/// <summary>
	/// Called immediately after the connection is opened. Sends the local SSH protocol
	/// version, and reads the remote version.
	/// </summary>
	private async Task ExchangeVersionsAsync(CancellationToken cancellation)
	{
		this.OnReportProgress(Progress.StartingProtocolVersionExchange);
		var writeTask = Protocol!.WriteProtocolVersionAsync(LocalVersion.ToString(), cancellation);
		var readTask = Protocol!.ReadProtocolVersionAsync(cancellation);

		// Don't wait for and verify the other side's version info yet.
		// Instead create a task that can be awaited later.
		this.versionExchangeTask = Task.Run(
			async () =>
			{
				var remoteVersion = await readTask.ConfigureAwait(false);

				Trace.TraceEvent(
					TraceEventType.Verbose,
					SshTraceEventIds.ProtocolVersion,
					$"Local version: {LocalVersion}, remote version: {remoteVersion}");

				string errorMessage;
				if (SshVersionInfo.TryParse(remoteVersion, out var remoteVersionInfo))
				{
					RemoteVersion = remoteVersionInfo;
					if (remoteVersionInfo.ProtocolVersion.Major == 2 &&
						remoteVersionInfo.ProtocolVersion.Minor == 0)
					{
						return;
					}

					errorMessage = $"Remote SSH version {remoteVersionInfo.ProtocolVersion} is " +
						"not supported. This library only supports SSH v2.0.";
				}
				else
				{
					errorMessage = $"Could not parse remote SSH version: {remoteVersion}";
				}

				await this.CloseAsync(
					SshDisconnectReason.ProtocolVersionNotSupported,
					new SshConnectionException(
						errorMessage,
						SshDisconnectReason.ProtocolVersionNotSupported)).ConfigureAwait(false);
			},
			this.disposeCancellationSource.Token);

		await writeTask.ConfigureAwait(false);
	}

	/// <summary>
	/// Called immediately after version exchange. Starts the key exchange,
	/// then processes messages until new keys are established. If there's an error
	/// setting up the encryption, it will be thrown as an exception.
	/// </summary>
	private async Task EncryptAsync(CancellationToken cancellation)
	{
		var protocol = Protocol;
		if (protocol == null) throw new ObjectDisposedException(nameof(SshSession));

		await protocol.ConsiderReExchangeAsync(initial: true, cancellation).ConfigureAwait(false);

		// Ensure the protocol version has been received before receiving any messages.
		await this.versionExchangeTask!.WaitAsync(cancellation).ConfigureAwait(false);
		this.OnReportProgress(Progress.CompletedProtocolVersionExchange);
		IsConnected = true;

		this.OnReportProgress(Progress.StartingKeyExchange);
		SshMessage? message = null;
		while (!IsClosed && Protocol?.Algorithms == null && !(message is DisconnectMessage))
		{
			message = await ReceiveAndHandleOneMessageAsync(cancellation)
				.ConfigureAwait(false);
			if (message == null)
			{
				break;
			}
		}

		if (Protocol?.Algorithms == null)
		{
			var connectionException = this.closedException as SshConnectionException;
			throw new SshConnectionException(
				"Session closed while encrypting.",
				connectionException?.DisconnectReason ?? SshDisconnectReason.ConnectionLost,
				this.closedException);
		}
		else if (Protocol.Algorithms.Cipher != null)
		{
			Trace.TraceEvent(
				TraceEventType.Verbose,
				SshTraceEventIds.SessionEncrypted,
				$"{this} encrypted");
		}

		this.OnReportProgress(Progress.CompletedKeyExchange);
	}

	/// <summary>
	/// Limits the amount of time that ConnectAsync() may wait for the initial
	/// session handshake (version exchange).
	/// </summary>
	public TimeSpan? ConnectTimeout { get; set; }

	/// <summary>
	/// Call after constructing an SshSession instance to bind to a stream and exchange
	/// initial messages with the remote peer. Waits for the protocol version exchange and
	/// key exchange; additional message processing is kicked off as a background task chain.
	/// </summary>
	/// <throws>SshConnectionException if the connection failed due to a protocol
	/// error.</throws>
	/// <throws>TimeoutException if the ConnectTimeout property is set and the initial
	/// version exchange could not be completed within the timeout.</throws>
	public async Task ConnectAsync(
		Stream stream,
		CancellationToken cancellation = default)
	{
		if (stream == null) throw new ArgumentNullException(nameof(stream));

		bool startConnecting = false;
		lock (this.disposeCancellationSource)
		{
			if (IsClosed) throw new ObjectDisposedException(nameof(SshSession));

			if (this.connectCompletionSource == null)
			{
				this.connectCompletionSource = new TaskCompletionSource<bool>(
					TaskCreationOptions.RunContinuationsAsynchronously);
				startConnecting = true;
			}
		}

		if (!startConnecting)
		{
			await this.connectCompletionSource.Task.WaitAsync(cancellation)
				.ConfigureAwait(false);
			return;
		}

		Trace.TraceEvent(
			TraceEventType.Verbose,
			SshTraceEventIds.SessionConnecting,
			$"{this} ConnectAsync");

		this.OnReportProgress(Progress.OpeningSshSessionConnection);
		this.closedException = null;
		Protocol = new SshProtocol(stream, Config, Metrics, Trace);
		Protocol.KeyExchangeService = this.kexService;
		Protocol.TraceChannelData = Config.TraceChannelData;

		try
		{
			using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(
				cancellation, this.disposeCancellationSource.Token))
			{
				if (ConnectTimeout.HasValue)
				{
					using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(connectCts.Token))
					{
						timeoutCts.CancelAfter(ConnectTimeout.Value);
						try
						{
							await ExchangeVersionsAsync(timeoutCts.Token).ConfigureAwait(false);
						}
						catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
						{
							throw new TimeoutException();
						}
					}
				}
				else
				{
					await ExchangeVersionsAsync(connectCts.Token).ConfigureAwait(false);
				}

				if (this.kexService != null)
				{
					// Also sends extension info immediately after encrypting.
					await EncryptAsync(connectCts.Token).ConfigureAwait(false);
				}
				else
				{
					// When there's no key-exchange service configured, send a key-exchange init message
					// that specifies "none" for all algorithms.
					await SendMessageAsync(KeyExchangeInitMessage.None, connectCts.Token)
						.ConfigureAwait(false);

					// When encrypting, the key-exchange step will wait on the version-exchange.
					// When not encrypting, it must be directly awaited.
					await this.versionExchangeTask!.WaitAsync(connectCts.Token).ConfigureAwait(false);
					this.OnReportProgress(Progress.CompletedProtocolVersionExchange);
					IsConnected = true;
				}

				// Implement KeepAlive
				StartKeepAliveTimer(this.disposeCancellationSource.Token);
			}

			this.connectCompletionSource.TrySetResult(true);
			this.OnReportProgress(Progress.OpenedSshSessionConnection);
		}
		catch (OperationCanceledException ocex)
		{
			this.connectCompletionSource?.TrySetCanceled(ocex.CancellationToken);
			throw;
		}
		catch (Exception ex)
		{
			this.connectCompletionSource?.TrySetException(ex);
			throw;
		}

		ProcessMessages();

		// Await the completion source in case it got set to an exception by Dispose().
		await this.connectCompletionSource.Task.ConfigureAwait(false);
	}

	internal void StartKeepAliveTimer(CancellationToken cancellation)
	{
		if (Config.KeepAliveTimeoutInSeconds > 0)
		{
			keepAliveTimer = new (
				async (state) =>
				{
					try
					{
						if (this.CanAcceptRequests)
						{
							if (!this.keepAliveResponseReceived)
							{
								Trace.TraceInformation("Keep alive response not received.");
								keepAliveFailureCount++;
								KeepAliveRequestFailed?.Invoke(
									this,
									new SshKeepAliveEventArgs(keepAliveFailureCount));
							}
							else
							{
								keepAliveFailureCount = 0;
							}

							this.keepAliveResponseReceived = false;
							await SendMessageAsync(
									new SessionRequestMessage() { RequestType = ExtensionRequestTypes.KeepAliveRequest, WantReply = true },
									cancellation)
								.ConfigureAwait(true);
						}
					}
					catch (Exception ex)
					{
						Trace.TraceEvent(
							TraceEventType.Error,
							SshTraceEventIds.KeepAliveFailed,
							ex.ToString());
					}
					finally
					{
						keepAliveTimer?.Change(
							TimeSpan.FromSeconds(Config.KeepAliveTimeoutInSeconds),
							Timeout.InfiniteTimeSpan);
					}
				},
				null,
				TimeSpan.FromSeconds(Config.KeepAliveTimeoutInSeconds),
				Timeout.InfiniteTimeSpan);
		}
	}

	/// <summary>
	/// Checks whether the session is in a state that allows requests, such as session requests
	/// and open-channel requests.
	/// </summary>
	/// <remarks>
	/// A session with disabled crypto (no key-exchange service) always allows requests. A
	/// session with enabled crypto does not allow requests until the first key-exchange has
	/// completed (algorithms are negotiated). If the negotiated algorithms enabled encryption,
	/// then the session must be authenticated (have a principal) before allowing requests.
	/// </remarks>
	internal bool CanAcceptRequests =>
		this.kexService == null || (Protocol?.Algorithms != null &&
			(Protocol.Algorithms.Cipher == null || Principal != null));

	/// <summary>
	/// Called after the session encryption and authentication is established.
	/// Processes additional messages on the session until it closes.
	/// </summary>
	internal void ProcessMessages()
	{
		IsConnected = true;

		var processMessagesTask = Task.Run(async () =>
		{
			while (!IsClosed)
			{
				// ReceiveAndHandleOneMessageAsync() should not throw:
				// it catches any exceptions, traces them, and closes the sesssion.
				var message = await ReceiveAndHandleOneMessageAsync(
					this.disposeCancellationSource.Token).ConfigureAwait(false);
				if (message == null)
				{
					break;
				}

				// Reset the keepAlive timer on any message received.
				try
				{
					keepAliveTimer?.Change(
						TimeSpan.FromSeconds(Config.KeepAliveTimeoutInSeconds),
						Timeout.InfiniteTimeSpan);
				}
				catch (ObjectDisposedException)
				{
					// ignore if the timer is disposed
				}

				this.keepAliveResponseReceived = true;
			}

			IsConnected = false;
		});
	}

	protected async Task<SshMessage?> ReceiveAndHandleOneMessageAsync(
		CancellationToken cancellation)
	{
		var protocol = Protocol;
		if (protocol == null)
		{
			return null;
		}

		SshMessage? message;
		try
		{
			message = await protocol.ReceiveMessageAsync(cancellation)
				.ConfigureAwait(false);
			if (message == null)
			{
				await CloseAsync(
					SshDisconnectReason.ConnectionLost, "Connection lost.").ConfigureAwait(false);
				return null;
			}
		}
		catch (SshConnectionException scex)
		{
			if (scex.DisconnectReason != SshDisconnectReason.ConnectionLost)
			{
				Trace.TraceEvent(
					 TraceEventType.Error, SshTraceEventIds.ReceiveMessageFailed, scex.ToString());
			}

			await CloseAsync(scex.DisconnectReason, scex).ConfigureAwait(false);
			return null;
		}
		catch (Exception ex)
		{
			Trace.TraceEvent(
				TraceEventType.Error, SshTraceEventIds.ReceiveMessageFailed, ex.ToString());
			await CloseAsync(SshDisconnectReason.ProtocolError, ex).ConfigureAwait(false);
			return null;
		}

		try
		{
			await HandleMessageAsync(message, cancellation).ConfigureAwait(false);
			return message;
		}
		catch (SshConnectionException scex)
		{
			if (scex.DisconnectReason != SshDisconnectReason.ConnectionLost)
			{
				Trace.TraceEvent(
					 TraceEventType.Error, SshTraceEventIds.HandleMessageFailed, scex.ToString());
			}

			await CloseAsync(scex.DisconnectReason, scex).ConfigureAwait(false);
			return null;
		}
		catch (Exception ex)
		{
			Trace.TraceEvent(
				TraceEventType.Error, SshTraceEventIds.HandleMessageFailed, ex.ToString());
			await CloseAsync(SshDisconnectReason.ProtocolError, ex).ConfigureAwait(false);
			return null;
		}
	}

	/// <summary>
	/// Sends a disconnect message to the other side with the given reason and message,
	/// then closes the session.
	/// </summary>
	public async Task CloseAsync(SshDisconnectReason reason, string? message = null)
	{
		await CloseAsync(reason, message ?? string.Empty, null).ConfigureAwait(false);
	}

	/// <summary>
	/// Sends a disconnect message to the other side with the given reason and
	/// exception message, then closes the session.
	/// </summary>
	public async Task CloseAsync(SshDisconnectReason reason, Exception ex)
	{
		if (ex == null)
		{
			throw new ArgumentNullException(nameof(ex));
		}

		await CloseAsync(reason, ex.Message, ex).ConfigureAwait(false);
	}

	private async Task CloseAsync(SshDisconnectReason reason, string message, Exception? ex)
	{
		lock (this.disposeCancellationSource)
		{
			if (IsClosed || !IsConnected)
			{
				return;
			}

			IsConnected = false;
		}

		Trace.TraceEvent(
			TraceEventType.Verbose,
			SshTraceEventIds.SessionClosing,
			$"{this} Close({reason}, {message})");

		if (reason != SshDisconnectReason.ConnectionLost)
		{
			await TrySendDisconnectMessageAsync(new DisconnectMessage(reason, message))
				.ConfigureAwait(false);
		}
		else if (OnDisconnected())
		{
			// Keep the session in a disconnected (but not closed) state.
			Protocol?.Disconnect();

			this.Trace.TraceEvent(
				TraceEventType.Information,
				SshTraceEventIds.SessionDisconnected,
				$"{this} Disconnected.");
			this.Disconnected?.Invoke(this, EventArgs.Empty);
			return;
		}

		bool closing;
		lock (this.disposeCancellationSource)
		{
			this.closedException = ex;
			closing = !IsClosed;
			IsClosed = true;
		}

		if (closing)
		{
			this.disposeCancellationSource.Cancel();

			ex ??= new SshConnectionException(message, reason);
			this.GetService<ConnectionService>()?.Close(ex);

			Closed?.Invoke(this, new SshSessionClosedEventArgs(reason, message, ex));
		}

		Dispose(true);
	}

	/// <summary>
	/// Invoked when the session is closed because the connection was lost.
	/// (Not invoked when the session is closed for any other reason such as a protocol error
	/// or an intentional close by the application.)
	/// </summary>
	/// <returns>True if the session may remain in a disconnected state, false if
	/// the session should be permanently closed.</returns>
	internal virtual bool OnDisconnected()
	{
		this.connectCompletionSource = null;
		this.kexService?.AbortKeyExchange();

		if (this.ProtocolExtensions?.ContainsKey(SshProtocolExtensionNames.SessionReconnect)
			!= true)
		{
			return false;
		}

		return true;
	}

	/// <summary>
	/// Immediately disposes the SSH session and the underlying transport stream.
	/// </summary>
	/// <remarks>
	/// For graceful shutdown, call `CloseAsync()`, which sends a disconnect message
	/// to the other side before closing.
	/// </remarks>
	public void Dispose()
	{
		Dispose(true);
		GC.SuppressFinalize(this);
	}

	internal void Dispose(Exception ex)
	{
		this.closedException = ex;
		Dispose();
	}

	protected virtual void Dispose(bool disposing)
	{
		var closedEx = this.closedException as SshConnectionException ??
			new SshConnectionException($"{GetType().Name} disposed.", this.closedException);

		if (disposing)
		{
			if (!IsClosed)
			{
				bool closing;
				lock (this.disposeCancellationSource)
				{
					closing = !IsClosed;
					IsConnected = false;
					IsClosed = true;
				}

				if (closing)
				{
					this.disposeCancellationSource.Cancel();

					Trace.TraceEvent(
						TraceEventType.Verbose,
						SshTraceEventIds.SessionClosing,
						$"{this} Close()");
					Closed?.Invoke(this, new SshSessionClosedEventArgs(
						closedEx.DisconnectReason, closedEx.Message, closedEx));
				}
			}

			InvokeRequestHandler(null, null, closedEx);
			this.connectCompletionSource?.TrySetException(closedEx);

			if (this.disposeCancellationSource.IsCancellationRequested)
			{
				this.disposeCancellationSource.Dispose();
			}

			Metrics.Close();

			lock (this.services)
			{
				// Dispose the connection service before other services, to ensure
				// channels are disposed before services that work with them.
				foreach (var service in this.services.Values
					.OrderByDescending((s) => s is ConnectionService))
				{
					service?.Dispose();
				}

				this.services.Clear();
			}

			this.kexService?.Dispose();
			this.keepAliveTimer?.Dispose();

			Protocol?.Dispose();
			Protocol = null;

			// SemaphoreSlim.Dispose() is not thread-safe and may cause WaitAsync(CancellationToken) not being cancelled
			// when SemaphoreSlim.Dispose is invoked immediately after CancellationTokenSource.Cancel.
			// See https://github.com/dotnet/runtime/issues/59639
			// SemaphoreSlim.Dispose() only disposes it's wait handle, which is not initialized unless its AvailableWaitHandle
			// property is read, which we don't use.

			// this.blockedMessagesSemaphore.Dispose();
			// this.sessionRequestSemaphore.Dispose();

			this.taskChain.Dispose();

			Config.ConfigurationChanged -= OnConfigurationChanged;
		}
	}

	/// <summary>
	/// Sends a message.
	/// </summary>
	/// <exception cref="InvalidOperationException">The session was never connected.</exception>
	/// <exception cref="SshConnectionException">The message could not be sent because
	/// the connection was lost.</exception>
	internal async Task SendMessageAsync(
		SshMessage message,
		CancellationToken cancellation)
	{
		if (message == null) throw new ArgumentNullException(nameof(message));
		if (IsClosed) throw new ObjectDisposedException(nameof(SshSession));

		var protocol = Protocol;
		if (protocol == null) throw new InvalidOperationException("Not connected.");

		// Wait for blocked messages to clear before sending.
		await this.blockedMessagesSemaphore.WaitAsync(cancellation).ConfigureAwait(false);

		bool result;
		try
		{
			// Defer sending messages if in the middle of a key (re-)exchange or reconnecting.
			// But do not defer messages that are part of the key exchange or reconnect protocol.
			if ((this.kexService?.Exchanging == true || Reconnecting) &&
				message.MessageType > 4 &&
				(message.MessageType < 20 || message.MessageType > 49) &&
				!(Reconnecting &&
					(message is SessionReconnectRequestMessage ||
					message is SessionReconnectResponseMessage)))
			{
				this.blockedMessages.Enqueue(message);
				this.blockedMessagesSemaphore.TryRelease();
				return;
			}

			result = await protocol.SendMessageAsync(message, cancellation).ConfigureAwait(false);
			this.blockedMessagesSemaphore.TryRelease();
		}
		catch (SshConnectionException ex)
		{
			this.blockedMessagesSemaphore.TryRelease();

			Trace.TraceEvent(
					TraceEventType.Error, SshTraceEventIds.SendMessageFailed, ex.ToString());
			await CloseAsync(ex.DisconnectReason, ex).ConfigureAwait(false);

			if (ex.DisconnectReason == SshDisconnectReason.ConnectionLost &&
				protocol.Extensions?.ContainsKey(SshProtocolExtensionNames.SessionReconnect) == true)
			{
				// Connection-lost exception when reconnect is enabled. Don't throw an exception;
				// the message will remain in the reconnect message cache and will be re-sent
				// upon reconnection.
				return;
			}
			else
			{
				throw;
			}
		}
		catch (Exception ex)
		{
			this.blockedMessagesSemaphore.TryRelease();

			Trace.TraceEvent(
				TraceEventType.Error, SshTraceEventIds.SendMessageFailed, ex.ToString());

			throw;
		}

		if (!result)
		{
			// Sending failed due to a closed stream, but don't throw when reconnect is enabled.
			// In that case the sent message is buffered and will be re-sent after reconnecting.
			if (protocol.Extensions?.ContainsKey(SshProtocolExtensionNames.SessionReconnect) != true)
			{
				throw new SshConnectionException(
					"Session is disconnected.",
					SshDisconnectReason.ConnectionLost);
			}
		}
	}

	private async Task ContinueSendBlockedMessagesAsync(CancellationToken cancellation)
	{
		try
		{
			SshMessage message;
			while (this.blockedMessages.TryDequeue(out message!))
			{
				var protocol = Protocol;
				if (protocol == null) throw new ObjectDisposedException(nameof(SshSession));

				await protocol.SendMessageAsync(message, cancellation).ConfigureAwait(false);
			}
		}
		catch (Exception ex)
		{
			Trace.TraceEvent(
				TraceEventType.Error, SshTraceEventIds.SendMessageFailed, ex.ToString());
			await CloseAsync(SshDisconnectReason.ProtocolError, ex).ConfigureAwait(false);
		}
	}

	internal async Task ContinueSendBlockedMessagesAfterReconnectAsync(
		CancellationToken cancellation)
	{
		await this.blockedMessagesSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			await ContinueSendBlockedMessagesAsync(cancellation).ConfigureAwait(false);

			Reconnecting = false;
		}
		finally
		{
			this.blockedMessagesSemaphore.TryRelease();
		}
	}

	private async Task TrySendDisconnectMessageAsync(DisconnectMessage message)
	{
		if (message == null) throw new ArgumentNullException(nameof(message));

		// Don't wait for too long trying to send the disconnect message.
		var timeout = TimeSpan.FromMilliseconds(100);
		using (var cancellationSource = new CancellationTokenSource(timeout))
		{
			try
			{
				var protocol = Protocol;
				if (protocol != null)
				{
					await protocol.SendMessageAsync(message, cancellationSource.Token)
						.ConfigureAwait(false);
				}
			}
			catch (Exception ex)
			{
				Trace.TraceEvent(
					TraceEventType.Warning, SshTraceEventIds.SendMessageFailed, ex.ToString());
			}
		}
	}

	/// <summary>
	/// Handles an incoming message. Can be overridden by subclasses to handle additional
	/// message types that are registered via <see cref="SshSessionConfiguration.Messages"/>.
	/// </summary>
	protected virtual Task HandleMessageAsync(
		SshMessage message, CancellationToken cancellation)
	{
		return message switch
		{
			SessionRequestMessage m => HandleMessageAsync(m, cancellation),
			SessionRequestSuccessMessage m => HandleMessageAsync(m, cancellation),
			SessionRequestFailureMessage m => HandleMessageAsync(m, cancellation),
			ExtensionInfoMessage m => HandleMessageAsync(m, cancellation),
			DisconnectMessage m => HandleMessageAsync(m, cancellation),
			NewKeysMessage m => HandleMessageAsync(m, cancellation),
			KeyExchangeMessage m => HandleMessageAsync(m, cancellation),
			AuthenticationMessage m => HandleMessageAsync(m, cancellation),
			ConnectionMessage m => HandleMessageAsync(m, cancellation),
			DebugMessage m => HandleMessageAsync(m, cancellation),
			IgnoreMessage m => HandleMessageAsync(m, cancellation),
			UnimplementedMessage m => HandleMessageAsync(m, cancellation),
			_ => throw (message == null
				? new ArgumentNullException(nameof(message))
				: new ArgumentException(
					$"Unhandled message type: {message.GetType().Name}", nameof(message))),
		};
	}

	private async Task HandleMessageAsync(
		DisconnectMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();

		var description = !string.IsNullOrEmpty(message.Description) ? message.Description :
			"Received disconnect message.";
		await CloseAsync(message.ReasonCode, description).ConfigureAwait(false);
	}

	private async Task HandleMessageAsync(
		KeyExchangeMessage message, CancellationToken cancellation)
	{
		if (this.kexService != null)
		{
			await this.kexService.HandleMessageAsync(message, cancellation).ConfigureAwait(false);
		}
		else if (!(message is KeyExchangeInitMessage initMessage && initMessage.AllowsNone))
		{
			// The other side required some security, but it's not configured here.
			await CloseAsync(SshDisconnectReason.KeyExchangeFailed, "Encryption is disabled.")
				.ConfigureAwait(false);
		}
	}

#pragma warning disable CA1801 // Remove unused parameter
	internal async Task HandleMessageAsync(NewKeysMessage message, CancellationToken cancellation)
#pragma warning restore CA1801 // Remove unused parameter
	{
		if (this.kexService == null)
		{
			await CloseAsync(SshDisconnectReason.KeyExchangeFailed).ConfigureAwait(false);
			return;
		}

		await this.blockedMessagesSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			await Protocol!.HandleNewKeysMessageAsync(cancellation).ConfigureAwait(false);

			if (Algorithms!.IsExtensionInfoRequested)
			{
				await SendExtensionInfoAsync(cancellation).ConfigureAwait(false);
			}

			if (!Reconnecting)
			{
				await ContinueSendBlockedMessagesAsync(cancellation).ConfigureAwait(false);
			}
		}
		finally
		{
			this.blockedMessagesSemaphore.TryRelease();
		}

		this.connectCompletionSource?.TrySetResult(true);
	}

	private async Task HandleMessageAsync(
		AuthenticationMessage message, CancellationToken cancellation)
	{
		var service = GetService<AuthenticationService>();
		if (service != null)
		{
			await service.HandleMessageAsync(message, cancellation).ConfigureAwait(false);
		}
	}

	private async Task HandleMessageAsync(
		ConnectionMessage message, CancellationToken cancellation)
	{
		var service = GetService<ConnectionService>();
		if (service != null)
		{
			await service.HandleMessageAsync(message, cancellation).ConfigureAwait(false);
		}
	}

	private async Task HandleMessageAsync(
		UnimplementedMessage message,
		CancellationToken cancellation)
	{
		if (message.UnimplementedMessageType != null)
		{
			// Received a message type that is unimplemented by this side.
			// Send a reply to inform the other side.
			await SendMessageAsync(message, cancellation).ConfigureAwait(false);
		}
		else
		{
			// This is a reply indicating this side previously sent a message type
			// that is not implemented by the other side. It has already been traced.
		}
	}

	private Task HandleMessageAsync(
		DebugMessage message,
#pragma warning disable CA1801 // Review unused parameters
		CancellationToken cancellation)
#pragma warning restore CA1801 // Review unused parameters
	{
		Trace.TraceEvent(
			message.AlwaysDisplay ? TraceEventType.Information : TraceEventType.Verbose,
			SshTraceEventIds.DebugMessage,
			message.Message);
		return Task.CompletedTask;
	}

#pragma warning disable CA1801, CA1822 // Review unused parameters, can be static
	private Task HandleMessageAsync(
		IgnoreMessage message,
		CancellationToken cancellation)
#pragma warning restore CA1801, CA1822 // Review unused parameters, can be static
	{
		return Task.CompletedTask;
	}

	/// <summary>
	/// Raises an Authenticating event and returns the ClaimsPrincipal provided
	/// (asynchronously) by the event-handler, if any.
	/// </summary>
	/// <remarks>Callers should be prepared for exceptions thrown by event handlers.</remarks>
	internal async Task<ClaimsPrincipal?> HandleAuthenticatingAsync(
		SshAuthenticatingEventArgs args, CancellationToken cancellation)
	{
		Trace.TraceEvent(
			TraceEventType.Verbose,
			SshTraceEventIds.SessionAuthenticating,
			$"{this} {nameof(Authenticating)}({args})");

		this.OnReportProgress(Progress.StartingSessionAuthentication);

		Authenticating?.Invoke(this, args);

		if (args.AuthenticationTask == null)
		{
			return null;
		}

		// An event-handler filled in a task on the event. Await the task to get
		// the principal that is the result of authenticating.
		var principal = await args.AuthenticationTask.WaitAsync(cancellation).ConfigureAwait(false);
		this.OnReportProgress(Progress.CompletedSessionAuthentication);
		return principal;
	}

	/// <summary>
	/// Sends a session request and waits for a response.
	/// </summary>
	/// <param name="request">Request details.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The authorization status of the response; if false, the other side denied the
	/// request.</returns>
	/// <remarks>
	/// Note if <see cref="SessionRequestMessage.WantReply" /> is false, this method returns
	/// true immediately after sending the request, without waiting for a response.
	/// </remarks>
	public async Task<bool> RequestAsync(
		SessionRequestMessage request,
		CancellationToken cancellation = default)
	{
		if (request == null) throw new ArgumentNullException(nameof(request));

		if (!request.WantReply)
		{
			await SendMessageAsync(request, cancellation).ConfigureAwait(false);
			return true;
		}

		var response = await RequestAsync<SessionRequestSuccessMessage>(
			request, cancellation).ConfigureAwait(false);
		return response != null;
	}

	/// <summary>
	/// Sends a session request and waits for a specific type of response message.
	/// </summary>
	/// <typeparam name="T">Type of response message expected.</typeparam>
	/// <param name="request">Request details.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The response message, or null if the request failed beause the
	/// other side denied the request.</returns>
	public async Task<T?> RequestAsync<T>(
		SessionRequestMessage request,
		CancellationToken cancellation) where T : SessionRequestSuccessMessage, new()
	{
		var successOrFailure = await RequestAsync<T, SessionRequestFailureMessage>(
			request, cancellation).ConfigureAwait(false);
		return successOrFailure.Success;
	}

	/// <summary>
	/// Sends a session request and waits for a specific type of success or failure message.
	/// </summary>
	/// <typeparam name="TSuccess">Type of successful response message expected.</typeparam>
	/// <typeparam name="TFailure">Type of failure response message expected.</typeparam>
	/// <param name="request">Request details.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>A tuple containing either the success message or failure message returned
	/// by the other side.</returns>
	public async Task<(TSuccess? Success, TFailure? Failure)> RequestAsync<TSuccess, TFailure>(
		SessionRequestMessage request,
		CancellationToken cancellation)
		where TSuccess : SessionRequestSuccessMessage, new()
		where TFailure : SessionRequestFailureMessage, new()
	{
		if (request == null) throw new ArgumentNullException(nameof(request));

		request.WantReply = true;

		var requestHandler = new RequestHandler<TSuccess, TFailure>();
		await sessionRequestSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			this.requestHandlers.Enqueue(requestHandler);
			await SendMessageAsync(request, cancellation).ConfigureAwait(false);
		}
		finally
		{
			sessionRequestSemaphore.TryRelease();
		}

		return await requestHandler.WaitForCompletionAsync(cancellation).ConfigureAwait(false);
	}

	internal Task HandleMessageAsync(
		SessionRequestSuccessMessage message, CancellationToken cancellation)
	{
		cancellation.ThrowIfCancellationRequested();
		InvokeRequestHandler(message, null, null);
		return Task.CompletedTask;
	}

#pragma warning disable CA1801 // Remove unused parameter
	internal Task HandleMessageAsync(
		SessionRequestFailureMessage message, CancellationToken cancellation)
#pragma warning restore CA1801 // Remove unused parameter
	{
		cancellation.ThrowIfCancellationRequested();
		InvokeRequestHandler(null, message, null);
		return Task.CompletedTask;
	}

	/// <summary>
	/// Asynchronously waits for the other side to open a channel.
	/// </summary>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The accepted channel.</returns>
	/// <exception cref="SshConnectionException">The connection was lost while accepting
	/// the channel.</exception>
	public Task<SshChannel> AcceptChannelAsync(CancellationToken cancellation = default)
	{
		return AcceptChannelAsync(null, cancellation);
	}

	/// <summary>
	/// Asynchronously waits for the other side to open a channel.
	/// </summary>
	/// <param name="channelType">Channel type to accept. If null, defaults to the
	/// standard "session" channel type. (Other channel types will not be accepted.)</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The accepted channel.</returns>
	/// <exception cref="SshConnectionException">The connection was lost while accepting
	/// the channel.</exception>
	public async Task<SshChannel> AcceptChannelAsync(
		string? channelType,
		CancellationToken cancellation = default)
	{
		var connectionService = ActivateService<ConnectionService>();

		// Prepare to accept the channel before connecting. This ensures that if the channel
		// open request comes in immediately after connecting then the channel won't be missed
		// in case of a task scheduling delay.
		var acceptTask = connectionService!.AcceptChannelAsync(
			channelType ?? SshChannel.SessionChannelType, cancellation);

		return await acceptTask.ConfigureAwait(false);
	}

	/// <summary>
	/// Opens a channel and asynchronously waits for the other side to accept it.
	/// </summary>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The opened channel.</returns>
	/// <exception cref="SshChannelException">The other side blocked the channel
	/// from opening.</exception>
	/// <exception cref="SshConnectionException">The connection was lost while opening
	/// the channel.</exception>
	public Task<SshChannel> OpenChannelAsync(CancellationToken cancellation = default)
	{
		return OpenChannelAsync(null, cancellation);
	}

	/// <summary>
	/// Opens a channel and asynchronously waits for the other side to accept it.
	/// </summary>
	/// <param name="channelType">Channel type to open. If null, defaults to the
	/// standard "session" channel type.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The opened channel.</returns>
	/// <exception cref="SshChannelException">The other side blocked the channel
	/// from opening.</exception>
	/// <exception cref="SshConnectionException">The connection was lost while opening
	/// the channel.</exception>
	public Task<SshChannel> OpenChannelAsync(
		string? channelType,
		CancellationToken cancellation = default)
	{
		var openMessage = new ChannelOpenMessage
		{
			ChannelType = channelType,
		};
		return OpenChannelAsync(openMessage, null, cancellation);
	}

	/// <summary>
	/// Opens a channel and asynchronously waits for the other side to accept it.
	/// Optionally sends an initial request and also waits for a response to that request.
	/// </summary>
	/// <param name="openMessage">Open message to be sent, including channel type. May be a
	/// subclass of <see cref="ChannelOpenMessage" />.</param>
	/// <param name="initialRequest">Optional initial request sent over the channel, often used
	/// to establish the purpose of the channel.</param>
	/// <param name="cancellation">Optional cancellation token.</param>
	/// <returns>The opened channel.</returns>
	/// <exception cref="SshChannelException">The other side blocked the channel
	/// from opening.</exception>
	/// <exception cref="SshConnectionException">The connection was lost while opening
	/// the channel.</exception>
	/// <remarks>
	/// This uses a private extension to the SSH protocol to avoid an extra round-trip when
	/// opening a channel and sending the first channel request. If the other side doesn't
	/// support the extension, then the standard protocol is used as a fallback.
	/// </remarks>
	public virtual async Task<SshChannel> OpenChannelAsync(
		ChannelOpenMessage openMessage,
		ChannelRequestMessage? initialRequest,
		CancellationToken cancellation = default)
	{
		if (openMessage == null) throw new ArgumentNullException(nameof(openMessage));

		openMessage.ChannelType ??= SshChannel.SessionChannelType;
		await this.taskChain.WaitForAllCurrentTasks(cancellation).ConfigureAwait(false);

		if (initialRequest != null)
		{
			return await OpenChannelWithInitialRequestAsync(
				openMessage, initialRequest, cancellation).ConfigureAwait(false);
		}

		var connectionService = ActivateService<ConnectionService>();
		var completionSource = new TaskCompletionSource<SshChannel>(
			TaskCreationOptions.RunContinuationsAsynchronously);

		uint channelId = await connectionService!.OpenChannelAsync(
			openMessage,
			completionSource,
			cancellation).ConfigureAwait(false);
		return await completionSource.Task.ConfigureAwait(false);
	}

	/// <summary>
	/// Uses a protocol extension (if enabled) to send an initial channel request
	/// at the same time as opening a channel.
	/// </summary>
	private async Task<SshChannel> OpenChannelWithInitialRequestAsync(
		ChannelOpenMessage openMessage,
		ChannelRequestMessage initialRequest,
		CancellationToken cancellation)
	{
		var connectionService = ActivateService<ConnectionService>();
		var completionSource = new TaskCompletionSource<SshChannel>(
			TaskCreationOptions.RunContinuationsAsynchronously);
		uint channelId = await connectionService!.OpenChannelAsync(
			openMessage,
			completionSource,
			cancellation).ConfigureAwait(false);

		SshChannel channel;
		bool requestResult;

		bool? isExtensionSupported =
			Config.ProtocolExtensions.Contains(SshProtocolExtensionNames.OpenChannelRequest) ?
			ProtocolExtensions?.ContainsKey(SshProtocolExtensionNames.OpenChannelRequest) : false;
		if (isExtensionSupported == false)
		{
			// The local or remote side definitely doesn't support this extension. Just send a
			// normal channel request after waiting for the channel open confirmation.
			channel = await completionSource.Task.ConfigureAwait(false);
			requestResult = await channel.RequestAsync(initialRequest, cancellation)
				.ConfigureAwait(false);
		}
		else
		{
			// The remote side does or might support this extension. If uncertain then a reply
			// is required.
			bool wantReply = initialRequest.WantReply || (isExtensionSupported == null);

			// Send the initial channel request message BEFORE waiting for the
			// channel open confirmation.
			var sessionRequest = new SessionChannelRequestMessage
			{
				RequestType = ExtensionRequestTypes.InitialChannelRequest,
				SenderChannelId = channelId,
				Request = initialRequest,
				WantReply = wantReply,
			};
			var requestTask = RequestAsync(sessionRequest, cancellation);

			// Wait for the channel open confirmation.
			channel = await completionSource.Task.ConfigureAwait(false);

			if (!wantReply)
			{
				requestResult = true;
			}
			else
			{
				// Wait for the response to the initial channel request.
				requestResult = await requestTask.ConfigureAwait(false);
				if (!requestResult && (isExtensionSupported == null))
				{
					// The initial request failed. This could be because the other side doesn't
					// support the initial-request extension or because the request was denied.
					// Try sending the request again as a regular channel request.
					requestResult = await channel.RequestAsync(initialRequest, cancellation)
						.ConfigureAwait(false);
				}
			}
		}

		if (!requestResult)
		{
			// The regular request still failed, so close the channel and throw.
			await channel.CloseAsync(cancellation).ConfigureAwait(false);
			throw new SshChannelException(
				"The initial channel request was denied.",
				SshChannelOpenFailureReason.AdministrativelyProhibited);
		}

		return channel;
	}

	internal async Task OnChannelOpeningAsync(
		SshChannelOpeningEventArgs e,
		CancellationToken cancellation,
		bool resolveService = true)
	{
		if (resolveService)
		{
			var (serviceType, serviceConfig) = ServiceActivationAttribute.FindService(
				Config.Services,
				(a) => a.ChannelType == e.Channel.ChannelType && a.ChannelRequest == null);
			if (serviceType != null)
			{
				// A service was configured for activation via this channel type.
				var service = ActivateService(serviceType, serviceConfig);
				await service.OnChannelOpeningAsync(e, cancellation).ConfigureAwait(false);
				return;
			}
		}

		e.Cancellation = cancellation;
		ChannelOpening?.Invoke(this, e);
	}

	/// <summary>
	/// Informs the other side what extensions may be enabled in this session.
	/// </summary>
	internal async Task SendExtensionInfoAsync(CancellationToken cancellation)
	{
		if (Protocol == null)
		{
			return;
		}

		var extensionInfo = new Dictionary<string, string>();

		foreach (var extensionName in Config.ProtocolExtensions)
		{
			if (extensionName == SshProtocolExtensionNames.ServerSignatureAlgorithms)
			{
				// Send the list of enabled host key signature algorithms.
				var publicKeyAlgorithms = SshSessionConfiguration.GetAlgorithmNamesList(
					Config.PublicKeyAlgorithms);
				extensionInfo.Add(
					SshProtocolExtensionNames.ServerSignatureAlgorithms,
					string.Join(",", publicKeyAlgorithms));
			}
			else
			{
				extensionInfo.Add(extensionName, string.Empty);
			}
		}

		await Protocol.SendMessageAsync(
			new ExtensionInfoMessage { ExtensionInfo = extensionInfo }, cancellation)
			.ConfigureAwait(false);
	}

	/// <summary>
	/// Indicates what extensions are enabled by the other side.
	/// </summary>
	internal async Task HandleMessageAsync(
		ExtensionInfoMessage message, CancellationToken cancellation)
	{
		if (Protocol == null)
		{
			return;
		}

		var proposedExtensions = message.ExtensionInfo;
		if (proposedExtensions == null)
		{
			Protocol.Extensions = new Dictionary<string, string>();
			return;
		}

		// Fill the extensions dictionary with only the extensions that are enabled.
		// Assign to the Protocol.Extensions property only after it is filled to avoid a race.
		Dictionary<string, string> extensions = new Dictionary<string, string>();
		foreach (var extensionName in Config.ProtocolExtensions)
		{
			if (proposedExtensions.TryGetValue(extensionName, out var value))
			{
				extensions.Add(extensionName, value);
			}
		}

		Protocol.Extensions = extensions;

		if (extensions.ContainsKey(SshProtocolExtensionNames.SessionReconnect))
		{
			// Reconnect is not enabled until each side sends a special request message.
			await EnableReconnectAsync(cancellation).ConfigureAwait(false);
		}
	}

	/// <summary>
	/// Defines session request types that are used for implementing protocol extensions.
	/// </summary>
	internal static class ExtensionRequestTypes
	{
		public const string InitialChannelRequest = "initial-channel-request@microsoft.com";
		public const string EnableSessionReconnect = "enable-session-reconnect@microsoft.com";
		public const string SessionReconnect = "session-reconnect@microsoft.com";
		public const string KeepAliveRequest = "keepalive@openssh.com";
	}

	/// <summary>
	/// Handle a session request. Some special requests deal with protocol extensions;
	/// any others are delegated to a general request event-handler.
	/// </summary>
	internal virtual async Task HandleMessageAsync(
		SessionRequestMessage message, CancellationToken cancellation)
	{
		TaskCompletionSource<SshMessage> result = new TaskCompletionSource<SshMessage>();
		Func<SshMessage, Task>? continuation = null;
		if (message.RequestType == ExtensionRequestTypes.InitialChannelRequest &&
			this.Config.ProtocolExtensions.Contains(SshProtocolExtensionNames.OpenChannelRequest))
		{
			var sessionChannelRequest = message.ConvertTo<SessionChannelRequestMessage>();
			var remoteChannelId = sessionChannelRequest.SenderChannelId;
			var channel = Channels.FirstOrDefault((c) => c.RemoteChannelId == remoteChannelId);

			if (channel != null && sessionChannelRequest.Request != null)
			{
				sessionChannelRequest.Request.WantReply = false; // Avoid redundant reply.
				if (await channel.HandleRequestAsync(
					sessionChannelRequest.Request, cancellation).ConfigureAwait(false))
				{
					result.SetResult(new SessionRequestSuccessMessage());
				}
				else
				{
					result.SetResult(new SessionRequestFailureMessage());
				}
			}
			else
			{
				result.SetResult(new SessionRequestFailureMessage());
			}
		}
		else if (message.RequestType == ExtensionRequestTypes.EnableSessionReconnect &&
			this.Config.ProtocolExtensions.Contains(SshProtocolExtensionNames.SessionReconnect))
		{
			if (!Protocol!.IncomingMessagesHaveReconnectInfo)
			{
				// Starting immediately after this message, all incoming messages include
				// an extra field or two after the payload.
				Protocol.IncomingMessagesHaveReconnectInfo = true;
				Protocol.IncomingMessagesHaveLatencyInfo =
					Protocol.Extensions!.ContainsKey(SshProtocolExtensionNames.SessionLatency);

				result.SetResult(new SessionRequestSuccessMessage());
			}
			else
			{
				result.SetResult(new SessionRequestFailureMessage());
			}
		}
		else if (message.RequestType == ExtensionRequestTypes.KeepAliveRequest)
		{
			this.KeepAliveRequestReceived?.Invoke(this, EventArgs.Empty);
			result.SetResult(new SessionRequestFailureMessage());
		}
		else if (!CanAcceptRequests)
		{
			Trace.TraceEvent(
				TraceEventType.Warning,
				SshTraceEventIds.SessionRequestFailed,
				"Session request blocked because the session is not yet authenticated.");
			result.SetResult(new SessionRequestFailureMessage());
		}
		else
		{
			var args = new SshRequestEventArgs<SessionRequestMessage>(
				message.RequestType ?? string.Empty, message, Principal, cancellation);

			var (serviceType, serviceConfig) = ServiceActivationAttribute.FindService(
				Config.Services, (a) => a.SessionRequest == message.RequestType);
			if (serviceType != null)
			{
				// A service was configured for activation via this session request type.
				var service = ActivateService(serviceType, serviceConfig);
				await service.OnSessionRequestAsync(args, cancellation).ConfigureAwait(false);
			}
			else
			{
				// Raise a Request event to let an event listener handle this request.
				try
				{
					OnSessionRequest(args);
				}
				catch (Exception ex)
				{
					Trace.TraceEvent(
						TraceEventType.Error,
						SshTraceEventIds.SessionRequestFailed,
						$"OnSessionRequest failed with exception {ex}.");

					// Send failure message in case of exception
					result.SetResult(new SessionRequestFailureMessage());
				}
			}

			if (args.ResponseTask != null && !result.Task.IsCompleted)
			{
				_ = args.ResponseTask.ContinueWith(
				(Func<Task<SshMessage>, Task>)(async (responseTask) =>
				{
					try
					{
						var response = await responseTask.ConfigureAwait(false);
						result.SetResult(result: response);
					}
					catch (Exception ex)
					{
						Trace.TraceEvent(
							TraceEventType.Error,
							SshTraceEventIds.SessionRequestFailed,
							$"Session request response task failed with exception {ex}.");
						result.SetResult(new SessionRequestFailureMessage());
					}
				}),
				cancellation,
				TaskContinuationOptions.None,
				TaskScheduler.Default);
			}
			else if (!result.Task.IsCompleted)
			{
				result.SetResult(args.IsAuthorized ?
					 new SessionRequestSuccessMessage() : new SessionRequestFailureMessage());
			}

			continuation = args.ResponseContinuation;
		}

		await this.taskChain.RunInSequence(
			async () =>
			{
				var response = await result.Task.ConfigureAwait(false);
				if (message.WantReply)
				{
					await SendMessageAsync(response, cancellation).ConfigureAwait(false);
				}

				if (continuation != null)
				{
					await continuation(response).ConfigureAwait(false);
				}
			},
			(ex) =>
			{
				Trace.TraceEvent(
					TraceEventType.Error,
					SshTraceEventIds.SessionRequestFailed,
					$"OnSessionRequest send response failed with exception {ex}.");
			},
			cancellation).ConfigureAwait(false);
	}

	internal void OnSessionRequest(SshRequestEventArgs<SessionRequestMessage> args)
	{
		Request?.Invoke(this, args);
	}

	internal void OnReportProgress(Progress progress)
	{
		var args = new SshReportProgressEventArgs(progress, this.sessionNumber);
		ReportProgress?.Invoke(this, args);
	}

	/// <summary>
	/// Sends a special session request that indicates every following sent message will
	/// include the extended reconnect info.
	/// </summary>
	internal virtual async Task EnableReconnectAsync(CancellationToken cancellation)
	{
		// Ensure no other messages are sent in the middle of turning this on.
		await this.blockedMessagesSemaphore.WaitAsync(cancellation).ConfigureAwait(false);
		try
		{
			// This should not be done during a key-exchange, however that should never
			// be the case since the EnableSessionReconnectRequest is sent in response
			// to an ExtensionInfo message which is sent in response to a NewKeys message.
			// So a key exchange just finished and won't be restarted again soon.
			if (this.kexService?.Exchanging == true)
			{
				Trace.TraceEvent(
					TraceEventType.Warning,
					SshTraceEventIds.SessionReconnectInitFailed,
					"Failed to initialize session reconnect because a key-exchange was in-progress.");
			}
			else
			{
				// Send the message indicating reconnect message tracking is starting.
				await Protocol!.SendMessageAsync(
					new SessionRequestMessage
					{
						RequestType = ExtensionRequestTypes.EnableSessionReconnect,
						WantReply = false,
					},
					cancellation).ConfigureAwait(false);

				// Start using the protocol extensions that include an extra field or two
				// with every sent message.
				Protocol.OutgoingMessagesHaveReconnectInfo = true;
				Protocol.OutgoingMessagesHaveLatencyInfo =
					Protocol.Extensions!.ContainsKey(SshProtocolExtensionNames.SessionLatency);
			}

			this.blockedMessagesSemaphore.TryRelease();
		}
		catch (ObjectDisposedException)
		{
			// The session was just closed.
			this.blockedMessagesSemaphore.TryRelease();
		}
		catch (Exception ex)
		{
			// This is not in a finally block because the semaphore must be released before
			// the call to CloseAsync() which tries to send a message.
			this.blockedMessagesSemaphore.TryRelease();

			Trace.TraceEvent(
				TraceEventType.Error, SshTraceEventIds.SendMessageFailed, ex.ToString());
			await CloseAsync(SshDisconnectReason.ProtocolError, ex).ConfigureAwait(false);
			throw;
		}
	}

	internal Buffer CreateReconnectToken(byte[] previousSessionId, byte[] newSessionId)
	{
		// To generate the reconnect token, combine the old session ID and new (re-negotiated)
		// session ID and sign the result using the new negotiated HMAC algorithm and key. This
		// proves that the old (secret) session ID is known while not disclosing it, and also
		// prevents replay attacks.
		var writer = new SshDataWriter(new Buffer(previousSessionId.Length + newSessionId.Length));
		writer.Write(previousSessionId);
		writer.Write(newSessionId);

		var signer = Algorithms?.Signer;
		if (signer == null)
		{
			throw new SshConnectionException(
				"Connection lost while reconnecting.", SshDisconnectReason.ConnectionLost);
		}

		var reconnectToken = new Buffer(signer.DigestLength);
		signer.Sign(writer.ToBuffer(), reconnectToken);
		return reconnectToken;
	}

	internal bool VerifyReconnectToken(
		byte[] previousSessionId, byte[] newSessionId, Buffer reconnectToken)
	{
		var writer = new SshDataWriter(new Buffer(previousSessionId.Length + newSessionId.Length));
		writer.Write(previousSessionId);
		writer.Write(newSessionId);

		var verifier = Algorithms?.Verifier;
		if (verifier == null)
		{
			throw new InvalidOperationException(
				"HMAC algorithm not available when verifying reconnection. " +
				"The connection may have been lost before the initial key-exchange completed.");
		}

		var result = verifier.Verify(writer.ToBuffer(), reconnectToken);
		return result;
	}

	public override string ToString()
	{
		return $"{GetType().Name}:{GetHashCode()}";
	}

	private interface IRequestHandler
	{
		void HandleRequest(
			SessionRequestSuccessMessage? success,
			SessionRequestFailureMessage? failure,
			Exception? ex);

		public void Cancel();
	}

	private class RequestHandler<TSuccess, TFailure> : IRequestHandler
		where TSuccess : SessionRequestSuccessMessage, new()
		where TFailure : SessionRequestFailureMessage, new()
	{
		public void HandleRequest(
			SessionRequestSuccessMessage? success,
			SessionRequestFailureMessage? failure,
			Exception? ex)
		{
			if (this.IsCancelled)
			{
				// The completion source was already cancelled.
				return;
			}
			else if (ex != null)
			{
				CompletionSource.TrySetException(ex);
			}
			else if (failure != null)
			{
				var result = failure.ConvertTo<TFailure>(copy: true);
				CompletionSource.TrySetResult((null, result));
			}
			else
			{
				// Make a copy of the response message because the continuation may be
				// asynchronous; meanwhile the receive buffer will be re-used.
				var result = success?.ConvertTo<TSuccess>(copy: true);
				CompletionSource.TrySetResult((result, null));
			}
		}

		public void Cancel()
		{
			this.IsCancelled = true;
			CompletionSource.TrySetCanceled();
		}

		public Task<(TSuccess? Success, TFailure? Failure)> WaitForCompletionAsync(CancellationToken cancellation) =>
			CompletionSource.Task.WaitAsync(cancellation);

		private TaskCompletionSource<(TSuccess? Success, TFailure? Failure)> CompletionSource { get; } =
			new TaskCompletionSource<(TSuccess? Success, TFailure? Failure)>(TaskCreationOptions.RunContinuationsAsynchronously);

		private bool IsCancelled { get; set; }
	}

	private void InvokeRequestHandler(
		SessionRequestSuccessMessage? success,
		SessionRequestFailureMessage? failure,
		Exception? ex)
	{
		while (this.requestHandlers.TryDequeue(out var requestHandler))
		{
			requestHandler.HandleRequest(success, failure, ex);

			// An exception is provided if the session is disposing. In that case,
			// all pending requests should fail with that exception.
			if (ex == null)
			{
				break;
			}
		}
	}
}
