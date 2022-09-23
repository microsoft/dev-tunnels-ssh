// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

#pragma warning disable CA1060 // Move pinvokes to native methods class
#pragma warning disable SA1307 // Accessible fields should begin with upper-case letter

#if SSH_ENABLE_ECDH
namespace Microsoft.DevTunnels.Ssh.Algorithms;

/// <summary>
/// NCrypt P/Invoke definitions for use with ECDiffieHellmanCng on Windows.
/// </summary>
internal static class NCrypt
{
	public enum BufferType
	{
		KdfHashAlgorithm = 0x00000000,
		KdfSecretPrepend = 0x00000001,
		KdfSecretAppend = 0x00000002,
		KdfHmacKey = 0x00000003,
		KdfTlsLabel = 0x00000004,
		KdfTlsSeed = 0x00000005,
		PkcsAlgOid = 0x00000029,
		PkcsAlgParam = 0x0000002A,
		PkcsSecret = 0x0000002E,
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct Buffer
	{
		public int cbBuffer;
		public BufferType BufferType;
		public IntPtr pvBuffer;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct BuffersDescriptor
	{
		public int ulVersion;
		public int cBuffers;
		public IntPtr pBuffers;
	}

	[Flags]
	public enum SecretAgreementFlags
	{
		None = 0x00000000,
		UseSecretAsHmacKey = 0x00000001,
	}

	[DllImport("ncrypt.dll", EntryPoint = "NCryptDeriveKey", CharSet = CharSet.Unicode)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	public static extern int DeriveKey(
		SafeNCryptSecretHandle hSharedSecret,
		string pwszKDF,
		[In] ref BuffersDescriptor pParameterList,
		[Out, MarshalAs(UnmanagedType.LPArray)] byte[]? pbDerivedKey,
		int cbDerivedKey,
		[Out] out int pcbResult,
		SecretAgreementFlags dwFlags);

	public static class KeyDerivationFunctions
	{
		public const string Hash = "HASH";
		public const string Hmac = "HMAC";
		public const string TlsPrf = "TLS_PRF";
		public const string RawSecret = "TRUNCATE";
	}
}
#endif
