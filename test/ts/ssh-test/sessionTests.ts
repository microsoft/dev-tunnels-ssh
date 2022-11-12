//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout, pending, params } from '@testdeck/mocha';

import {
	KeyPair,
	SshAlgorithms,
	SshClientSession,
	SshServerSession,
	SshAuthenticationType,
	ObjectDisposedError,
	formatBuffer,
	SshSessionConfiguration,
	SshSessionClosedEventArgs,
	PromiseCompletionSource,
	SshDisconnectReason,
	SshConnectionError,
} from '@microsoft/dev-tunnels-ssh';
import { DuplexStream, shutdownWebSocketServer } from './duplexStream';
import { createSessionPair, connectSessionPair } from './sessionPair';

@suite
@slow(3000)
@timeout(20000)
export class SessionTests {
	private static readonly testUsername = 'test';
	private static readonly testPassword = 'password';

	private static clientKey: KeyPair;
	private static serverKey: KeyPair;

	private clientClosedCompletion = new PromiseCompletionSource<SshSessionClosedEventArgs>();
	private serverClosedCompletion = new PromiseCompletionSource<SshSessionClosedEventArgs>();

	@slow(10000)
	@timeout(20000)
	public static async before() {
		SessionTests.clientKey = await SshAlgorithms.publicKey.rsaWithSha512!.generateKeyPair();
		SessionTests.serverKey = await SshAlgorithms.publicKey.rsaWithSha512!.generateKeyPair();
	}

	public static async after() {
		shutdownWebSocketServer();
	}

	private async createSessions(): Promise<[SshClientSession, SshServerSession]> {
		const [clientSession, serverSession] = await createSessionPair();
		clientSession.config.encryptionAlgorithms.splice(0, 0, SshAlgorithms.encryption.aes256Gcm);
		serverSession.config.encryptionAlgorithms.splice(0, 0, SshAlgorithms.encryption.aes256Gcm);

		serverSession.credentials.publicKeys = [SessionTests.serverKey];

		clientSession.onClosed((e) => this.clientClosedCompletion.resolve(e));
		serverSession.onClosed((e) => this.serverClosedCompletion.resolve(e));

		return [clientSession, serverSession];
	}

	@test
	public async closeSessionStream() {
		const [clientSession, serverSession] = await this.createSessions();
		const [clientStream, serverStream] = await connectSessionPair(
			clientSession,
			serverSession,
			undefined,
			false,
		);

		serverStream.close();
		clientStream.close();

		const serverClosedEvent = await this.serverClosedCompletion.promise;
		const clientClosedEvent = await this.clientClosedCompletion.promise;

		assert.equal(serverClosedEvent.reason, SshDisconnectReason.connectionLost);
		assert(serverClosedEvent!.error instanceof SshConnectionError);
		assert.equal(
			(<SshConnectionError>serverClosedEvent!.error).reason,
			SshDisconnectReason.connectionLost,
		);

		assert.equal(clientClosedEvent.reason, SshDisconnectReason.connectionLost);
		assert(clientClosedEvent!.error instanceof SshConnectionError);
		assert.equal(
			(<SshConnectionError>clientClosedEvent!.error).reason,
			SshDisconnectReason.connectionLost,
		);
	}

	@test
	public async closeServerSession() {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession, undefined, false);

		const testDisconnectReason = <SshDisconnectReason>9999;
		await serverSession.close(testDisconnectReason);

		const serverClosedEvent = await this.serverClosedCompletion.promise;

		assert.equal(serverClosedEvent.reason, testDisconnectReason);
		assert(serverClosedEvent!.error instanceof SshConnectionError);
		assert.equal((<SshConnectionError>serverClosedEvent!.error).reason, testDisconnectReason);
	}

	@test
	public async closeClientSession() {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession, undefined, false);

		const testDisconnectReason = <SshDisconnectReason>9999;
		await clientSession.close(testDisconnectReason);

		const clientClosedEvent = await this.clientClosedCompletion.promise;

		assert.equal(clientClosedEvent.reason, testDisconnectReason);
		assert(clientClosedEvent!.error instanceof SshConnectionError);
		assert.equal((<SshConnectionError>clientClosedEvent!.error).reason, testDisconnectReason);
	}

	@test
	@params({ clientForce: true })
	@params({ clientForce: false })
	@params.naming((p) => `negotiateNoKeyExchange(clientForce:${p.clientForce})`)
	public async negotiateNoKeyExchange({ clientForce }: { clientForce: boolean }) {
		const clientConfig = new SshSessionConfiguration();
		const serverConfig = new SshSessionConfiguration();

		if (clientForce) {
			// Clear all the client algorithms except for kex:none; support kex:none on the server.
			clientConfig.keyExchangeAlgorithms.splice(0, clientConfig.keyExchangeAlgorithms.length);
			clientConfig.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.none);
			clientConfig.publicKeyAlgorithms.splice(0, clientConfig.publicKeyAlgorithms.length);
			clientConfig.encryptionAlgorithms.splice(0, clientConfig.encryptionAlgorithms.length);
			clientConfig.hmacAlgorithms.splice(0, clientConfig.hmacAlgorithms.length);
			serverConfig.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.none);
		} else {
			// Clear all the server algorithms except for kex:none; support kex:none on the client.
			serverConfig.keyExchangeAlgorithms.splice(0, clientConfig.keyExchangeAlgorithms.length);
			serverConfig.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.none);
			serverConfig.publicKeyAlgorithms.splice(0, clientConfig.publicKeyAlgorithms.length);
			serverConfig.encryptionAlgorithms.splice(0, clientConfig.encryptionAlgorithms.length);
			serverConfig.hmacAlgorithms.splice(0, clientConfig.hmacAlgorithms.length);
			clientConfig.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.none);
		}

		const clientSession = new SshClientSession(serverConfig);
		const serverSession = new SshServerSession(clientConfig);
		await connectSessionPair(clientSession, serverSession, undefined, false);
	}

	@test
	public async authenticateClientWithNoCredentials() {
		const [clientSession, serverSession] = await this.createSessions();

		let authenticationType: SshAuthenticationType | undefined = undefined;
		let authenticatedClientUsername: string | null = null;
		let authenticatedClientPassword: string | null = null;
		let authenticatedClientKey: KeyPair | null = null;
		let clientPrincipal = new Object();

		serverSession.onAuthenticating((e) => {
			authenticationType = e.authenticationType;
			authenticatedClientUsername = e.username;
			authenticatedClientPassword = e.password;
			authenticatedClientKey = e.publicKey;
			e.authenticationPromise = Promise.resolve(clientPrincipal);
		});

		let serverRaisedClientAuthenticated = false;
		serverSession.onClientAuthenticated(() => {
			serverRaisedClientAuthenticated = true;
		});

		let authenticatedServerKey: KeyPair | null = null;
		let serverPrincipal = new Object();

		clientSession.onAuthenticating((e) => {
			authenticatedServerKey = e.publicKey;
			e.authenticationPromise = Promise.resolve(serverPrincipal);
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const authenticated = await clientSession.authenticate({
			username: SessionTests.testUsername,
		});
		assert(authenticated);
		assert(serverRaisedClientAuthenticated);

		assert.equal(authenticationType, SshAuthenticationType.clientNone);
		assert.equal(SessionTests.testUsername, authenticatedClientUsername);
		assert.equal(null, authenticatedClientPassword);
		assert.equal(null, authenticatedClientKey);
		assert(Object.is(clientPrincipal, serverSession.principal));

		assert(authenticatedServerKey);

		const expectedServerKeyBytes = await SessionTests.serverKey.getPublicKeyBytes();
		const actualServerKeyBytes = await authenticatedServerKey!.getPublicKeyBytes();
		assert(actualServerKeyBytes!.equals(expectedServerKeyBytes!));

		assert.equal(
			SessionTests.serverKey.keyAlgorithmName,
			authenticatedServerKey!.keyAlgorithmName,
		);
		assert(Object.is(serverPrincipal, clientSession.principal));
	}

	@test
	@params({ pkAlg: 'ecdsa-sha2-nistp256' })
	@params({ pkAlg: 'ecdsa-sha2-nistp384' })
	@params({ pkAlg: 'rsa-sha2-256', keySize: 2048 })
	@params({ pkAlg: 'rsa-sha2-512', keySize: 4096 })
	@params.naming((p) => `authenticateClientWithPublicKey(${p.pkAlg})`)
	public async authenticateClientWithPublicKey({
		pkAlg,
		keySize,
	}: {
		pkAlg: string;
		keySize?: number;
	}) {
		const alg = Object.values(SshAlgorithms.publicKey).find((a) => a?.name === pkAlg)!;
		const clientKey = await alg.generateKeyPair(keySize);

		const [clientSession, serverSession] = await this.createSessions();

		let authenticationType: SshAuthenticationType | undefined = undefined;
		let authenticatedClientUsername: string | null = null;
		let authenticatedClientPassword: string | null = null;
		let authenticatedClientKey: KeyPair | null = null;
		let clientPrincipal = new Object();

		serverSession.onAuthenticating((e) => {
			authenticationType = e.authenticationType;
			authenticatedClientUsername = e.username;
			authenticatedClientPassword = e.password;
			authenticatedClientKey = e.publicKey;
			e.authenticationPromise = Promise.resolve(clientPrincipal);
		});

		let serverRaisedClientAuthenticated = false;
		serverSession.onClientAuthenticated(() => {
			serverRaisedClientAuthenticated = true;
		});

		let authenticatedServerKey: KeyPair | null = null;
		let serverPrincipal = new Object();

		clientSession.onAuthenticating((e) => {
			authenticatedServerKey = e.publicKey;
			e.authenticationPromise = Promise.resolve(serverPrincipal);
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const authenticated = await clientSession.authenticate({
			username: SessionTests.testUsername,
			publicKeys: [clientKey],
		});
		assert(authenticated);
		assert(serverRaisedClientAuthenticated);

		assert.equal(authenticationType, SshAuthenticationType.clientPublicKey);
		assert.equal(SessionTests.testUsername, authenticatedClientUsername);
		assert.equal(null, authenticatedClientPassword);
		assert(authenticatedClientKey);

		const expectedClientKeyBytes = await clientKey.getPublicKeyBytes();
		const actualClientKeyBytes = await authenticatedClientKey!.getPublicKeyBytes();
		assert(actualClientKeyBytes!.equals(expectedClientKeyBytes!));

		assert.equal(clientKey.keyAlgorithmName, authenticatedClientKey!.keyAlgorithmName);
		assert(Object.is(clientPrincipal, serverSession.principal));

		assert(authenticatedServerKey);

		const expectedServerKeyBytes = await SessionTests.serverKey.getPublicKeyBytes();
		const actualServerKeyBytes = await authenticatedServerKey!.getPublicKeyBytes();
		assert(actualServerKeyBytes!.equals(expectedServerKeyBytes!));

		assert.equal(
			SessionTests.serverKey.keyAlgorithmName,
			authenticatedServerKey!.keyAlgorithmName,
		);
		assert(Object.is(serverPrincipal, clientSession.principal));
	}

	@test
	public async authenticateClientWithPassword() {
		const [clientSession, serverSession] = await this.createSessions();

		let authenticationType: SshAuthenticationType | undefined = undefined;
		let authenticatedClientUsername: string | null = null;
		let authenticatedClientPassword: string | null = null;
		let authenticatedClientKey: KeyPair | null = null;
		let clientPrincipal = new Object();

		serverSession.onAuthenticating((e) => {
			authenticationType = e.authenticationType;
			authenticatedClientUsername = e.username;
			authenticatedClientPassword = e.password;
			authenticatedClientKey = e.publicKey;
			e.authenticationPromise = Promise.resolve(clientPrincipal);
		});

		let serverRaisedClientAuthenticated = false;
		serverSession.onClientAuthenticated(() => {
			serverRaisedClientAuthenticated = true;
		});

		let authenticatedServerKey: KeyPair | null = null;
		let serverPrincipal = new Object();

		clientSession.onAuthenticating((e) => {
			authenticatedServerKey = e.publicKey;
			e.authenticationPromise = Promise.resolve(serverPrincipal);
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const authenticated = await clientSession.authenticate({
			username: SessionTests.testUsername,
			password: SessionTests.testPassword,
		});
		assert(authenticated);
		assert(serverRaisedClientAuthenticated);

		assert.equal(authenticationType, SshAuthenticationType.clientPassword);
		assert.equal(SessionTests.testUsername, authenticatedClientUsername);
		assert.equal(SessionTests.testPassword, authenticatedClientPassword);
		assert.equal(null, authenticatedClientKey);

		assert(Object.is(clientPrincipal, serverSession.principal));

		assert(authenticatedServerKey);

		const expectedServerKeyBytes = await SessionTests.serverKey.getPublicKeyBytes();
		const actualServerKeyBytes = await authenticatedServerKey!.getPublicKeyBytes();
		assert(actualServerKeyBytes!.equals(expectedServerKeyBytes!));

		assert.equal(
			SessionTests.serverKey.keyAlgorithmName,
			authenticatedServerKey!.keyAlgorithmName,
		);
		assert(Object.is(serverPrincipal, clientSession.principal));
	}

	@test
	public async authenticateServerFail() {
		const [clientSession, serverSession] = await this.createSessions();

		serverSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});
		clientSession.onAuthenticating((e) => {
			// Client fails to authenticate the server.
			e.authenticationPromise = Promise.resolve(null);
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const authenticated = await clientSession.authenticate({});
		assert(!authenticated);
	}

	@test
	public async authenticateClientFail() {
		const [clientSession, serverSession] = await this.createSessions();

		let authenticationType: SshAuthenticationType | undefined = undefined;
		serverSession.onAuthenticating((e) => {
			authenticationType = e.authenticationType;
			e.authenticationPromise = Promise.resolve(null);
		});

		let serverRaisedClientAuthenticated = false;
		serverSession.onClientAuthenticated(() => {
			serverRaisedClientAuthenticated = true;
		});

		clientSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const authenticated = await clientSession.authenticate({
			username: SessionTests.testUsername,
			password: SessionTests.testPassword,
		});
		assert(!authenticated);
		assert(!serverRaisedClientAuthenticated);
		assert.equal(authenticationType, SshAuthenticationType.clientPassword);
	}

	@test
	public async authenticateCallbackError() {
		const [clientSession, serverSession] = await this.createSessions();

		let authenticationType: SshAuthenticationType | undefined = undefined;
		serverSession.onAuthenticating((e) => {
			authenticationType = e.authenticationType;
			e.authenticationPromise = Promise.reject(new Error('Test error'));
		});

		clientSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const authenticated = await clientSession.authenticate({
			username: SessionTests.testUsername,
			password: SessionTests.testPassword,
		});
		assert(!authenticated);
		assert.equal(authenticationType, SshAuthenticationType.clientPassword);
	}

	@test
	public async authenticateConnectionError() {
		const [clientSession, serverSession] = await this.createSessions();

		const [clientStream, serverStream] = await connectSessionPair(
			clientSession,
			serverSession,
			undefined,
			false,
		);

		let authenticationType: SshAuthenticationType | undefined = undefined;
		serverSession.onAuthenticating((e) => {
			// Simulate lost connection while authenticating.
			serverStream.close();
		});

		clientSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});

		let error: Error | null = null;
		try {
			await clientSession.authenticate({
				username: SessionTests.testUsername,
			});
		} catch (e) {
			error = e as Error;
		}

		assert(error);
		assert(error instanceof ObjectDisposedError);
	}
}
