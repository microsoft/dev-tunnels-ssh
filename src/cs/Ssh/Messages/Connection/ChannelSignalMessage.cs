// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

public class ChannelSignalMessage : ChannelRequestMessage
{
	private string? signal;
	private string? errorMessage;
	private uint? status;

	public string? Signal
	{
		get => this.signal;
		set
		{
			this.RequestType = ChannelRequestTypes.Signal;
			this.signal = value;
		}
	}

	public string? ExitSignal
	{
		get => this.signal;
		set
		{
			this.RequestType = ChannelRequestTypes.ExitSignal;
			this.signal = value;
		}
	}

	public string? ErrorMessage
	{
		get => this.errorMessage;
		set
		{
			if (RequestType != ChannelRequestTypes.ExitSignal)
			{
				throw new ArgumentException(
					$"Error message property is only valid for {ChannelRequestTypes.ExitSignal} messages.");
			}

			this.errorMessage = value;
		}
	}

	public uint? ExitStatus
	{
		get => this.status;
		set
		{
			this.RequestType = ChannelRequestTypes.ExitStatus;
			this.status = value;
		}
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (string.IsNullOrEmpty(RequestType))
		{
			throw new InvalidOperationException("Signal message request type not set.");
		}

		WantReply = false;

		base.OnWrite(ref writer);

		switch (RequestType)
		{
			case ChannelRequestTypes.ExitStatus:
				if (ExitStatus == null)
				{
					throw new InvalidOperationException("Exit status not set.");
				}

				writer.Write(ExitStatus.Value);
				break;

			case ChannelRequestTypes.Signal:
				if (string.IsNullOrEmpty(Signal))
				{
					throw new InvalidOperationException("Exit status not set.");
				}

				writer.Write(Signal!, Encoding.ASCII);
				break;

			case ChannelRequestTypes.ExitSignal:
				if (string.IsNullOrEmpty(ExitSignal))
				{
					throw new InvalidOperationException("Exit status not set.");
				}

				writer.Write(ExitSignal!, Encoding.ASCII);
				writer.Write(false); // Core dumped
				writer.Write(ErrorMessage ?? string.Empty, Encoding.UTF8);
				writer.Write(string.Empty, Encoding.ASCII); // Language tag
				break;

			default:
				throw new ArgumentException(
					$"Unknown signal message request type: {RequestType}");
		}
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		switch (RequestType)
		{
			case ChannelRequestTypes.ExitStatus:
				ExitStatus = reader.ReadUInt32();
				break;

			case ChannelRequestTypes.Signal:
				Signal = reader.ReadString(Encoding.ASCII);
				break;

			case ChannelRequestTypes.ExitSignal:
				ExitSignal = reader.ReadString(Encoding.ASCII);
				reader.ReadBoolean(); // Core dumped
				ErrorMessage = reader.ReadString(Encoding.UTF8);
				reader.ReadString(Encoding.ASCII); // Language tag
				break;

			default:
				break;
		}
	}
}
