// Copyright (c) Microsoft. All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public abstract class SshAlgorithm
{
	protected SshAlgorithm(string name)
	{
		if (string.IsNullOrEmpty(name))
		{
			throw new ArgumentNullException(nameof(name));
		}

		Name = name;
	}

	/// <summary>
	/// Gets the name that uniquely identifies this algorithm in the context of the SSH protocol,
	/// including the key size and mode or other algorithm parameters.
	/// </summary>
	/// <remarks>
	/// The name is used when negotiating algorithms between client and server.
	/// </remarks>
	public string Name { get; }

	/// <summary>
	/// Gets a value indicating whether the algorithm is available / supported in the current
	/// platform and configuration.
	/// </summary>
	/// <remarks>
	/// Some algorithms may have specific platform or external dependency requirements.
	/// Algorithms that are unavilable due to unmet requirements are excluded from negotiation.
	/// </remarks>
	public virtual bool IsAvailable => true;

	/// <summary>
	/// Gets the System.Security.Cryptography.Cng assembly that is required for certain
	/// crypto implementations on Windows.
	/// </summary>
	internal static Assembly? CngAssembly => lazyCngAssembly.Value;

	private static Lazy<Assembly?> lazyCngAssembly = new Lazy<Assembly?>(
		InitializeCngAssembly, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the System.Security.Cryptography.OpenSsl assembly that is required for certain
	/// crypto implementations on non-Windows platforms. If `libssl` is not installed or
	/// not found in the dynamic-library search path, it might not be available.
	/// </summary>
	internal static Assembly? OpenSslAssembly => lazyOpenSslAssembly.Value;

	private static Lazy<Assembly?> lazyOpenSslAssembly = new Lazy<Assembly?>(
		InitializeOpenSslAssembly, LazyThreadSafetyMode.ExecutionAndPublication);

	private static Assembly? InitializeCngAssembly()
	{
		var ns = typeof(SymmetricAlgorithm).Namespace;
		try
		{
			return Assembly.Load($"{ns}.Cng");
		}
		catch (FileNotFoundException)
		{
			// The System.Security.Cryptography.Cng asembly was not found.
			return null;
		}
	}

#if NET6_0_OR_GREATER
	[UnconditionalSuppressMessage(
		"Trimming",
		"IL2026:RequiresUnreferencedCode",
		Justification = "Crypto types will no be trimmed because they're referenced elsewhere.")]
#endif
	private static Assembly? InitializeOpenSslAssembly()
	{
		var ns = typeof(SymmetricAlgorithm).Namespace;
		Assembly opensslAssembly;
		try
		{
			opensslAssembly = Assembly.Load($"{ns}.OpenSsl");
		}
		catch (FileNotFoundException)
		{
			// The System.Security.Cryptography.OpenSsl asembly was not found.
			return null;
		}

		// Try to P/Invoke into libssl 1.1, just to check whether it can be loaded. Otherwise
		// the .NET OpenSSL initialization may abort the process when it fails to load libssl.
		try
		{
			if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
			{
				// On Mac, .NET prefers v1.1 but also supports v1.0.
				try
				{
					_ = GetOpenSsl11VersionMac();
				}
				catch (DllNotFoundException)
				{
					try
					{
						_ = GetOpenSsl10VersionMac();
					}
					catch (EntryPointNotFoundException)
					{
						// The version_num entrypoint doesn't exist in older versions.
						// That's fine -- this at least confirms the library was loaded.
					}
				}
			}
			else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
			{
				// On Linux, .NET always prefers v1.1, but supports several other versions
				// depending on the distro. Ignore other versions here to keep it simple.
				_ = GetOpenSsl11VersionLinux();
			}
		}
		catch (DllNotFoundException)
		{
			return null;
		}

		// Ensure the crypto interop is initialized. Unfortunately this relies on an
		// internal type, but there's no better way to ensure OpenSSL is actually available
		// before trying to really use it.
		var interopCryptoType = opensslAssembly.GetType("Interop+Crypto");
		if (interopCryptoType == null)
		{
			// The internal interop type was not found. Since it's internal, it could get moved
			// in future versions of .NET. That's not fatal because this library can fallback to
			// other crypto algorithms.
			return null;
		}

		try
		{
			RuntimeHelpers.RunClassConstructor(interopCryptoType.TypeHandle);
		}
		catch (TypeInitializationException)
		{
			// Crypto interop failed to initialize for some other reason.
			return null;
		}

		return opensslAssembly;
	}

	[DllImport("libssl.1.1.dylib", EntryPoint = "OpenSSL_version_num")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
	private static extern int GetOpenSsl11VersionMac();

	[DllImport("libssl.1.0.0.dylib", EntryPoint = "OpenSSL_version_num")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
	private static extern int GetOpenSsl10VersionMac();

	[DllImport("libssl.so.1.1", EntryPoint = "OpenSSL_version_num")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
	private static extern int GetOpenSsl11VersionLinux();
}
