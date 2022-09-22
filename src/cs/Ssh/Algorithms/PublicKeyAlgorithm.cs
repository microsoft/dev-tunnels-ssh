// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Text;
using Microsoft.DevTunnels.Ssh.IO;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public abstract class PublicKeyAlgorithm : SshAlgorithm
{
	protected PublicKeyAlgorithm(
		string name,
		string keyAlgorithmName,
		string hashAlgorithmName)
		: base(name)
	{
		this.KeyAlgorithmName = keyAlgorithmName;
		this.HashAlgorithmName = hashAlgorithmName;
	}

	public string KeyAlgorithmName { get; set; }
	public string HashAlgorithmName { get; }

	public abstract IKeyPair CreateKeyPair();
	public abstract IKeyPair GenerateKeyPair(int? keySizeInBits = null);
	public abstract ISigner CreateSigner(IKeyPair keyPair);
	public abstract IVerifier CreateVerifier(IKeyPair keyPair);

	public Buffer ReadSignatureData(Buffer signatureData)
	{
		var reader = new SshDataReader(signatureData);
		string algorithmName = reader.ReadString(Encoding.ASCII);
		if (algorithmName != Name)
		{
			throw new ArgumentException(
				"Mismatched public key algorithm: " +
				$"got '{algorithmName}', expected '{Name}'.");
		}

		var signature = reader.ReadBinary();
		return signature;
	}

	public Buffer CreateSignatureData(Buffer signature)
	{
		var writer = new SshDataWriter();
		writer.Write(Name, Encoding.ASCII);
		writer.WriteBinary(signature);
		return writer.ToBuffer();
	}
}
