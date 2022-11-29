// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.DevTunnels.Ssh.Messages;

namespace Microsoft.DevTunnels.Ssh.Events;

[DebuggerDisplay("{ToString(),nq}")]
[DebuggerStepThrough]
public class SshRequestEventArgs<T> where T : SshMessage
{
	public SshRequestEventArgs(
		string requestType,
		T request,
		ClaimsPrincipal? principal,
		CancellationToken cancellation = default)
	{
		RequestType = requestType;
		Request = request;
		Principal = principal;
		Cancellation = cancellation;
	}

	/// <summary>
	/// Gets the specific type of request.
	/// </summary>
	/// <remarks>
	/// This may be used to convert the request message to a more specific message type.
	/// </remarks>
	public string RequestType { get; }

	public T Request { get; }

	/// <summary>
	/// Gets the principal for the session that made the request, or null if the session
	/// is not authenticated.
	/// </summary>
	/// <remarks>
	/// Claims on the principal may be used to decide whether the request
	/// should be authorized or not.
	/// </remarks>
	public ClaimsPrincipal? Principal { get; }

	/// <summary>
	/// An event handler sets this to true if the request is valid and authorized.
	/// </summary>
	/// <remarks>
	/// Authorization decisions may rely on claims in the authenticated <see cref="Principal" />.
	/// <para/>
	/// For async response handling, use <see cref="ResponseTask" /> instead.
	/// </remarks>
	public bool IsAuthorized { get; set; }

	/// <summary>
	/// Gets or sets a task to be filled in by the event handler for async request processing.
	/// </summary>
	/// <remarks>
	/// An async request handler must set this value to a task that resolves to a
	/// success or failure message.
	/// </remarks>
	public Task<SshMessage>? ResponseTask { get; set; }

	/// <summary>
	/// Gets or sets an action to be invoked AFTER any response message has been sent.
	/// (The continuation will be invoked even if a response was not requested.)
	/// </summary>
	/// <remarks>
	/// This enables a request handler to ensure additional messages are sequenced after the
	/// response message.
	/// </remarks>
	public Func<Task>? ResponseContinuation { get; set; }

	/// <summary>
	/// Gets a token that is cancelled if the session ends before the async response task
	/// completes.
	/// </summary>
	public CancellationToken Cancellation { get; internal set; }

	public override string ToString()
	{
		return $"RequestType: {RequestType}" +
			(Request != null ? $", Request: {Request}" : string.Empty);
	}
}
