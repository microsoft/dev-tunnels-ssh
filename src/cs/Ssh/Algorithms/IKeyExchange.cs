// Copyright (c) Microsoft. All rights reserved.

namespace Microsoft.DevTunnels.Ssh.Algorithms;

public interface IKeyExchange : ISigner
{
	Buffer StartKeyExchange();
	Buffer DecryptKeyExchange(Buffer exchangeValue);
}
