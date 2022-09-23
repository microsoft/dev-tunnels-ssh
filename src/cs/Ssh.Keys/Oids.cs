// Copyright (c) Microsoft. All rights reserved.

using System.Security.Cryptography;

#pragma warning disable SA1025 // Code should not contain multiple whitespace in a row

namespace Microsoft.DevTunnels.Ssh.Keys;

/// <summary>
/// Defines cryptographic object identifiers (OIDs) used for key import/export.
/// </summary>
internal static class Oids
{
	public static readonly Oid Rsa = new Oid("1.2.840.113549.1.1.1");
	public static readonly Oid EC = new Oid("1.2.840.10045.2.1");
	public static readonly Oid Pkcs5PBKDF2 = new Oid("1.2.840.113549.1.5.12");
	public static readonly Oid Pkcs5PBES2 = new Oid("1.2.840.113549.1.5.13");
	public static readonly Oid HmacWithSHA256 = new Oid("1.2.840.113549.2.9");
	public static readonly Oid DesEde3Cbc = new Oid("1.2.840.113549.3.7");
	public static readonly Oid Aes128Cbc = new Oid("2.16.840.1.101.3.4.1.2");
	public static readonly Oid Aes192Cbc = new Oid("2.16.840.1.101.3.4.1.22");
	public static readonly Oid Aes256Cbc = new Oid("2.16.840.1.101.3.4.1.42");
}
