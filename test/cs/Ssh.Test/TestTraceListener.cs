using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Microsoft.DevTunnels.Ssh.Test;

internal class TestTraceListener : TraceListener
{
	public ISet<int> EventIds { get; } = new HashSet<int>();

	public List<KeyValuePair<int, string>> Events { get; } = new List<KeyValuePair<int, string>>();

	public override void TraceEvent(TraceEventCache eventCache, string source, TraceEventType eventType, int id, string message)
	{
		if (EventIds.Contains(id))
		{
			message = message.Replace(Environment.NewLine, "\n");
			Events.Add(new KeyValuePair<int, string>(id, message));
		}
	}

	public override void Write(string message) => throw new NotSupportedException();
	public override void WriteLine(string message) => throw new NotSupportedException();
}