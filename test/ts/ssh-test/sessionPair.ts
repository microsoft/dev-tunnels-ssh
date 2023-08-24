//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import {
	KeyPair,
	SshClientSession,
	SshServerSession,
	SshSessionConfiguration,
	SshAlgorithms,
	SshChannel,
} from '@microsoft/dev-tunnels-ssh';
import { DuplexStream } from './duplexStream';
import { MockNetworkStream } from './mockNetworkStream';
import { trace } from './trace';

export async function createSessionPair(
	useServerExtensions: boolean = true,
	useClientExtensions: boolean = true,
	serverConfig?: SshSessionConfiguration,
	clientConfig?: SshSessionConfiguration,
): Promise<[SshClientSession, SshServerSession]> {
	clientConfig = clientConfig ?? serverConfig ?? createSessionConfig(useClientExtensions);
	serverConfig = serverConfig ?? createSessionConfig(useServerExtensions);

	const clientSession = new SshClientSession(clientConfig);
	const serverSession = new SshServerSession(serverConfig);

	clientSession.trace = (level, eventId, msg) => trace(msg);
	serverSession.trace = (level, eventId, msg) => trace(msg);

	return [clientSession, serverSession];
}

export function createSessionConfig(useExtensions: boolean = true): SshSessionConfiguration {
	const config = new SshSessionConfiguration();
	config.enableKeyExchangeGuess = true;

	// Use a faster key-exchange algorithm when testing.
	config.keyExchangeAlgorithms.splice(
		0,
		config.keyExchangeAlgorithms.length,
		SshAlgorithms.keyExchange.dhGroup14Sha256,
	);

	if (!useExtensions) {
		config.protocolExtensions.splice(0, config.protocolExtensions.length);
	}

	return config;
}

export async function connectSessionPair(
	clientSession: SshClientSession,
	serverSession: SshServerSession,
	streamType?: string,
	authenticate: boolean = true,
): Promise<[MockNetworkStream, MockNetworkStream]> {
	const [clientStream, serverStream] = await DuplexStream.createStreams(streamType);
	const clientNetworkStream = new MockNetworkStream(clientStream);
	const serverNetworkStream = new MockNetworkStream(serverStream);

	await Promise.all([
		clientSession.connect(clientNetworkStream),
		serverSession.connect(serverNetworkStream),
	]);

	if (authenticate) {
		serverSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});
		clientSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});
		if (!await clientSession.authenticate({})) {
			throw new Error('Session authentication failed.');
		}
	}

	return [clientNetworkStream, serverNetworkStream];
}

export async function disconnectSessionPair(
	clientStream: MockNetworkStream,
	serverStream: MockNetworkStream,
	disconnectError?: Error,
) {
	if (disconnectError) {
		clientStream.mockDisconnect(disconnectError);
		serverStream.mockDisconnect(disconnectError);
	} else {
		clientStream.close();
		serverStream.close();
	}
}

export function authenticateClient(
	clientSession: SshClientSession,
	serverSession: SshServerSession,
	username?: string,
	passwordOrKey?: string | KeyPair,
	clientPrincipal?: object,
): void {
	if (typeof username === 'undefined') {
		username = 'test';
	}
	if (typeof clientPrincipal === 'undefined') {
		clientPrincipal = {};
	}

	serverSession.onAuthenticating((e) => {
		if (e.username !== username) {
			e.authenticationPromise = Promise.resolve(null);
		} else if (typeof passwordOrKey === 'object') {
			if (!e.publicKey) {
				e.authenticationPromise = Promise.resolve(null);
			} else {
				e.authenticationPromise = new Promise(async (resolve) => {
					const expectedKeyBytes = (await (passwordOrKey as KeyPair).getPublicKeyBytes())!;
					const actualKeyBytes = (await e.publicKey!.getPublicKeyBytes())!;
					resolve(actualKeyBytes.equals(expectedKeyBytes) ? clientPrincipal! : null);
				});
			}
		} else if (typeof passwordOrKey === 'undefined') {
			e.authenticationPromise = Promise.resolve(clientPrincipal as object);
		} else {
			e.authenticationPromise = Promise.resolve(
				e.password === passwordOrKey ? (clientPrincipal as object) : null,
			);
		}
	});
}

export function authenticateServer(
	clientSession: SshClientSession,
	serverSession: SshServerSession,
	serverKey: KeyPair,
	serverPrincipal?: object,
): void {
	if (typeof serverPrincipal === 'undefined') {
		serverPrincipal = {};
	}

	serverSession.credentials.publicKeys.push(serverKey);

	clientSession.onAuthenticating((e) => {
		e.authenticationPromise = new Promise(async (resolve) => {
			const expectedKeyBytes = (await serverKey.getPublicKeyBytes())!;
			const actualKeyBytes = (await e.publicKey!.getPublicKeyBytes())!;
			resolve(actualKeyBytes.equals(expectedKeyBytes) ? serverPrincipal! : null);
		});
	});
}

export async function openChannel(
	clientSession: SshClientSession,
	serverSession: SshServerSession,
	channelType?: string,
): Promise<[SshChannel, SshChannel]> {
	const serverChannelPromise = serverSession.acceptChannel(channelType);
	const clientChannel = await clientSession.openChannel(channelType);
	const serverChannel = await serverChannelPromise;
	return [clientChannel, serverChannel];
}
