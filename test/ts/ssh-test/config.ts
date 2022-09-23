//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import { SshSessionConfiguration, SshAlgorithms } from '@microsoft/dev-tunnels-ssh';

export function createConfig(
	kexAlgorithmName: string,
	pkAlgorithmName: string,
	hmacAlgorithmName: string,
): SshSessionConfiguration {
	const kexAlg = Object.values(SshAlgorithms.keyExchange!).find(
		(a) => a?.name === kexAlgorithmName,
	)!;
	const pkAlg = Object.values(SshAlgorithms.publicKey!).find((a) => a?.name === pkAlgorithmName)!;
	const hmacAlg = Object.values(SshAlgorithms.hmac!).find((a) => a?.name === hmacAlgorithmName)!;

	const config = new SshSessionConfiguration();
	config.keyExchangeAlgorithms.splice(0, config.keyExchangeAlgorithms.length, kexAlg);
	config.publicKeyAlgorithms.splice(0, config.publicKeyAlgorithms.length, pkAlg);
	config.hmacAlgorithms.splice(0, config.hmacAlgorithms.length, hmacAlg);
	return config;
}
