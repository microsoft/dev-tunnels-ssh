// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

public class TerminalRequestMessage : ChannelRequestMessage
{
#pragma warning disable CA1028 // Enum Storage should be Int32
	public enum TerminalOpcode : byte
#pragma warning restore CA1028 // Enum Storage should be Int32
	{
#pragma warning disable CA1707 // Identifiers should not contain underscores
		TTY_OP_END = 0, // TTY_OP_END  Indicates end of options.
		VINTR = 1,     // Interrupt character; 255 if none.
		VQUIT = 2,     // The quit character (sends SIGQUIT signal on POSIX systems).
		VERASE = 3,    // Erase the character to left of the cursor.
		VKILL = 4,     // Kill the current input line.
		VEOF = 5,      // End-of-file character (sends EOF from the terminal).
		VEOL = 6,      // End-of-line character in addition to carriage return and/or linefeed.
		VEOL2 = 7,     // Additional end-of-line character.
		VSTART = 8,    // Continues paused output (normally control-Q).
		VSTOP = 9,     // Pauses output(normally control-S).
		VSUSP = 10,    // Suspends the current program.
		VDSUSP = 11,   // Another suspend character.
		VREPRINT = 12, // Reprints the current input line.
		VWERASE = 13,  // Erases a word left of cursor.
		VLNEXT = 14,   // Enter the next character typed literally, even if a special character.
		VFLUSH = 15,   // Character to flush output.
		VSWTCH = 16,   // Switch to a different shell layer.
		VSTATUS = 17,  // Prints system status line (load, command, pid, etc).
		VDISCARD = 18, // Toggles the flushing of terminal output.
		IGNPAR = 30,   // Ignore parity.
		PARMRK = 31,   // Mark parity and framing errors.
		INPCK = 32,    // Enable checking of parity errors.
		ISTRIP = 33,   // Strip 8th bit off characters.
		INLCR = 34,    // Map NL into CR on input.
		IGNCR = 35,    // Ignore CR on input.
		ICRNL = 36,    // Map CR to NL on input.
		IUCLC = 37,    // Translate uppercase characters to lowercase.
		IXON = 38,     // Enable output flow control.
		IXANY = 39,    // Any char will restart after stop.
		IXOFF = 40,    // Enable input flow control.
		IMAXBEL = 41,  // Ring bell on input queue full.
		ISIG = 50,     // Enable signals INTR, QUIT, [D]SUSP.
		ICANON = 51,   // Canonicalize input lines.
		XCASE = 52,    // Enable I/O of upper chars by preceding lower with "\".
		ECHO = 53,     // Enable echoing.
		ECHOE = 54,    // Visually erase chars.
		ECHOK = 55,    // Kill character discards current line.
		ECHONL = 56,   // Echo NL even if ECHO is off.
		NOFLSH = 57,   // Don't flush after interrupt.
		TOSTOP = 58,   // Stop background jobs from output.
		IEXTEN = 59,   // Enable extensions.
		ECHOCTL = 60,  // Echo control characters as ^(Char).
		ECHOKE = 61,   // Visual erase for line kill.
		PENDIN = 62,   // Retype pending input.
		OPOST = 70,    // Enable output processing.
		OLCUC = 71,    // Convert lowercase to uppercase.
		ONLCR = 72,    // Map NL to CR-NL.
		OCRNL = 73,    // Translate carriage return to newline (output).
		ONOCR = 74,    // Translate newline to carriage return-newline (output).
		ONLRET = 75,   // Newline performs a carriage return (output).
		CS7 = 90,      // 7 bit mode.
		CS8 = 91,      // 8 bit mode.
		PARENB = 92,   // Parity enable.
		PARODD = 93,   // Odd parity, else even.
		TTY_OP_ISPEED = 128, // Specifies the input baud rate in bits per second.
		TTY_OP_OSPEED = 129, // Specifies the output baud rate in bits per second.
#pragma warning restore CA1707 // Identifiers should not contain underscores
	}

#pragma warning disable CA1034 // Nested types should not be visible
	public struct TerminalMode : IEquatable<TerminalMode>
#pragma warning restore CA1034 // Nested types should not be visible
	{
		public TerminalOpcode Opcode { get; set; }
		public uint Argument { get; set; }

		public bool Equals(TerminalMode other)
		{
			return Opcode == other.Opcode && Argument == other.Argument;
		}

		public override bool Equals(object? obj)
		{
			return obj is TerminalMode otherTerminalMode && Equals(otherTerminalMode);
		}

		public static bool operator ==(TerminalMode left, TerminalMode right)
		{
			return left.Equals(right);
		}

		public static bool operator !=(TerminalMode left, TerminalMode right)
		{
			return !(left == right);
		}

		public override int GetHashCode()
		{
			return (Opcode, Argument).GetHashCode();
		}
	}

	public string? Term { get; set; }
	public uint Rows { get; set; }
	public uint Columns { get; set; }
	public uint PixelWidth { get; set; }
	public uint PixelHeight { get; set; }
	public IList<TerminalMode> TerminalModes { get; private set; }

	public TerminalRequestMessage()
	{
		RequestType = ChannelRequestTypes.Terminal;
		TerminalModes = new List<TerminalMode>();
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		Term = reader.ReadString(Encoding.ASCII);
		Columns = reader.ReadUInt32();
		Rows = reader.ReadUInt32();
		PixelWidth = reader.ReadUInt32();
		PixelHeight = reader.ReadUInt32();

		// TODO: Fix terminal modes parsing.
		/*
		TerminalModes.Clear();
		using (SshDataWorker modesReader = new SshDataWorker(reader.ReadBinary()))
		{
			while (modesReader.DataAvailable > 0)
			{
				TerminalOpcode opcode = (TerminalOpcode)reader.ReadByte();
				if (opcode == TerminalOpcode.TTY_OP_END)
				{
					break;
				}

				TerminalModes.Add(new TerminalMode
				{
					Opcode = opcode,
					Argument = reader.ReadUInt32(),
				});
			}
		}
		*/
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		base.OnWrite(ref writer);

		writer.Write(Term ?? string.Empty, Encoding.ASCII);
		writer.Write(Columns);
		writer.Write(Rows);
		writer.Write(PixelWidth);
		writer.Write(PixelHeight);

		var modesWriter = new SshDataWriter();

		foreach (TerminalMode terminalMode in TerminalModes)
		{
			modesWriter.Write((byte)terminalMode.Opcode);
			modesWriter.Write(terminalMode.Argument);
		}

		modesWriter.Write((byte)TerminalOpcode.TTY_OP_END);

		writer.WriteBinary(modesWriter.ToBuffer());
	}

	public override string ToString()
	{
		return $"{base.ToString()}(Term: {Term})";
	}
}
