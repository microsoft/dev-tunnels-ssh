// Copyright (c) Microsoft. All rights reserved.

using System;
using Microsoft.DevTunnels.Ssh.Algorithms;

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Interface for a provider of import, export, decryption, and encryption for one of the
/// supported key formats.
/// </summary>
/// <remarks>
/// See <see cref="KeyFormat" /> for a description of the different key formats.
/// </remarks>
public interface IKeyFormatter
{
	/// <summary>
	/// Creates a key pair object by deserializing key data.
	/// </summary>
	/// <param name="keyData">Key data that was decoded from PEM or other encoding and already
	/// decrypted if necessary.</param>
	/// <returns>The created key pair, or null if this formatter does not handle the
	/// format of the supplied key data.</returns>
	/// <exception cref="NotSupportedException">This formatter understands the format of
	/// the supplied key data, but cannot import the key, usually due to unsupported
	/// key pair algorithm.</exception>
	IKeyPair? Import(KeyData keyData);

	/// <summary>
	/// Serializes a key pair object.
	/// </summary>
	/// <param name="keyPair">The public key or public/private key pair to serialize.</param>
	/// <param name="includePrivate">True if the private key should be serialized.</param>
	/// <returns>Formatted (but not yet encrypted or encoded) key data.</returns>
	/// <exception cref="ArgumentException">The private key was requested but the key pair
	/// object does not have the private key.</exception>
	/// <exception cref="NotSupportedException">The private key was requested but the format
	/// does not support serialization of a private key.</exception>
	KeyData Export(IKeyPair keyPair, bool includePrivate);

	/// <summary>
	/// Decrypts key data before it is imported.
	/// </summary>
	/// <param name="keyData">Key data that was decoded from PEM or other encoding.</param>
	/// <param name="passphrase">Decryption passphrase supplied by the caller, or null
	/// if no passphrase was supplied.</param>
	/// <returns>Decrypted key data (still in the same format), or null if this formatter
	/// does not handle the format of the supplied key data.</returns>
	/// <exception cref="NotSupportedException">This formatter understands the format of
	/// the supplied key data, but cannot decrypt the key data, usually due to unsupported
	/// key encryption algorithm.</exception>
	/// <exception cref="UnauthorizedAccessException">The key data could not be decrypted
	/// because the passphrase was incorrect or was not supplied.</exception>
	KeyData? Decrypt(KeyData keyData, string? passphrase);

	/// <summary>
	/// Encrypts key data after it was exported.
	/// </summary>
	/// <param name="keyData">Key data that was exported by the same formatter.</param>
	/// <param name="passphrase">Passphrase from which an encryption key is derived.</param>
	/// <returns>Encrypted key data (still in the same format).</returns>
	/// <exception cref="NotSupportedException">This formatter does not support
	/// encryption.</exception>
	KeyData Encrypt(KeyData keyData, string passphrase);
}
