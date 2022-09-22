// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.Algorithms;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Messages;

public class PublicKeyRequestMessage : AuthenticationRequestMessage
{
	public string? KeyAlgorithmName { get; private set; }
	public Buffer PublicKey { get; private set; }
	public string? ClientHostname { get; private set; }
	public string? ClientUsername { get; private set; }

#pragma warning disable CA2227 // Collection properties should be read only
	public Buffer Signature { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only

	public bool HasSignature => Signature.Count > 0;

	public Buffer PayloadWithoutSignature { get; private set; }

	public PublicKeyRequestMessage()
	{
	}

	public PublicKeyRequestMessage(
		string serviceName,
		string username,
		PublicKeyAlgorithm algorithm,
		IKeyPair key,
		Buffer signature = default,
		string? clientHostname = null,
		string? clientUsername = null)
		: base(
			serviceName,
			clientHostname != null ? AuthenticationMethods.HostBased : AuthenticationMethods.PublicKey,
			username)
	{
		if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
		if (key == null) throw new ArgumentNullException(nameof(key));

		KeyAlgorithmName = algorithm.Name;
		PublicKey = key.GetPublicKeyBytes(algorithm.Name);
		Signature = signature;
		ClientHostname = clientHostname;
		ClientUsername = clientUsername;
	}

	protected override void OnWrite(ref SshDataWriter writer)
	{
		if (KeyAlgorithmName == null)
		{
			throw new InvalidOperationException("Key algorithm name not set.");
		}

		base.OnWrite(ref writer);

		if (MethodName == AuthenticationMethods.HostBased)
		{
			writer.Write(KeyAlgorithmName, Encoding.ASCII);
			writer.WriteBinary(PublicKey);
			writer.Write(ClientHostname!, Encoding.ASCII);
			writer.Write(ClientUsername ?? string.Empty, Encoding.UTF8);

			if (!HasSignature)
			{
				throw new InvalidOperationException(
					"A signature is required for a host-based authentication request.");
			}

			writer.WriteBinary(Signature);
		}
		else
		{
			writer.Write(HasSignature);
			writer.Write(KeyAlgorithmName, Encoding.ASCII);
			writer.WriteBinary(PublicKey);

			if (HasSignature)
			{
				writer.WriteBinary(Signature);
			}
		}
	}

	protected override void OnRead(ref SshDataReader reader)
	{
		base.OnRead(ref reader);

		if (MethodName != AuthenticationMethods.PublicKey)
		{
			throw new ArgumentException($"Method name {MethodName} is not valid.");
		}

		if (MethodName == AuthenticationMethods.HostBased)
		{
			KeyAlgorithmName = reader.ReadString(Encoding.ASCII);
			PublicKey = reader.ReadBinary();
			ClientHostname = reader.ReadString(Encoding.ASCII);
			ClientUsername = reader.ReadString(Encoding.UTF8);
			Signature = reader.ReadBinary();
		}
		else
		{
			bool hasSignature = reader.ReadBoolean();
			KeyAlgorithmName = reader.ReadString(Encoding.ASCII);
			PublicKey = reader.ReadBinary();

			if (hasSignature)
			{
				Signature = reader.ReadBinary();
				PayloadWithoutSignature = RawBytes.Slice(0, reader.Position - Signature.Count - 4);
			}
			else
			{
				Signature = Buffer.Empty;
			}
		}
	}

	public override string ToString()
	{
		return base.ToString() +
			$"(KeyAlgorithmName: {KeyAlgorithmName}, HasSignature: {HasSignature})";
	}
}
