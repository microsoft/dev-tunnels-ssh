//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { Buffer } from 'buffer';
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
	SessionRequestSuccessMessage,
	SessionRequestFailureMessage,
	SshMessage,
	SessionRequestMessage,
	AuthenticationInfoRequestMessage,
	AuthenticationInfoResponseMessage,
	SshAuthenticatingEventArgs,
	PublicKeyRequestMessage,
	ServiceRequestMessage,
	SshTraceEventIds,
	SshDataWriter,
	AuthenticationMethod,
	PublicKeyAlgorithm,
} from '@microsoft/dev-tunnels-ssh';
import { DuplexStream, shutdownWebSocketServer } from './duplexStream';
import { createSessionPair, connectSessionPair } from './sessionPair';
import { withTimeout } from './promiseUtils';

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

		let authenticatedServerKey: KeyPair = null!;
		let serverPrincipal = new Object();

		clientSession.onAuthenticating((e) => {
			authenticatedServerKey = e.publicKey!;
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
	@params({ result: true })
	@params({ result: false })
	@params.naming((p) => `authenticateClientPublicKeyQuery(${p.result})`)
	public async authenticateClientPublicKeyQuery({ result }: { result: boolean }) {
		const [clientSession, serverSession] = await this.createSessions();

		const queryEventCompletion = new PromiseCompletionSource<SshAuthenticatingEventArgs>();
		serverSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve(result ? {} : null);
			queryEventCompletion.resolve(e);
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const keyAlgorithm = SshAlgorithms.publicKey.ecdsaSha2Nistp384!;
		const keyPair = await keyAlgorithm.generateKeyPair();
		const publicKeyQueryMessage = new PublicKeyRequestMessage();
		publicKeyQueryMessage.serviceName = 'ssh-connection';
		publicKeyQueryMessage.username = 'test';
		publicKeyQueryMessage.keyAlgorithmName = keyAlgorithm.name;
		publicKeyQueryMessage.publicKey = (await keyPair.getPublicKeyBytes())!;

		const serviceRequestMessage = new ServiceRequestMessage();
		serviceRequestMessage.serviceName = 'ssh-userauth';
		await clientSession.sendMessage(serviceRequestMessage);
		await clientSession.sendMessage(publicKeyQueryMessage);

		const args = await withTimeout(queryEventCompletion.promise, 5000);
		assert.strictEqual(args.username, 'test');
		assert(args.publicKey);
		assert(!args.publicKey.hasPrivateKey);
		const argsPublicKeyBytes = (await args.publicKey.getPublicKeyBytes())!;
		assert(argsPublicKeyBytes.equals((await keyPair.getPublicKeyBytes())!));

		// A public-key query message should not have set a principal.
		assert(!serverSession.principal);

		// The session should not be disconnected after a (successful or failed) PK query.
		assert(serverSession.isConnected);
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
		let authenticatedClientKey: KeyPair = null!;
		let clientPrincipal = new Object();

		serverSession.onAuthenticating((e) => {
			authenticationType = e.authenticationType;
			authenticatedClientUsername = e.username;
			authenticatedClientPassword = e.password;
			authenticatedClientKey = e.publicKey!;
			e.authenticationPromise = Promise.resolve(clientPrincipal);
		});

		let serverRaisedClientAuthenticated = false;
		serverSession.onClientAuthenticated(() => {
			serverRaisedClientAuthenticated = true;
		});

		let authenticatedServerKey: KeyPair = null!;
		let serverPrincipal = new Object();

		clientSession.onAuthenticating((e) => {
			authenticatedServerKey = e.publicKey!;
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

		let authenticatedServerKey: KeyPair = null!;
		let serverPrincipal = new Object();

		clientSession.onAuthenticating((e) => {
			authenticatedServerKey = e.publicKey!;
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

	/**
	 * Verifies that a public-key authentication request with a signature that does not match
	 * the presented public key never reaches the application's `Authenticating` event handler,
	 * and never results in an authenticated session.
	 */
	@test
	@params({ pkAlg: 'ecdsa-sha2-nistp256' })
	@params({ pkAlg: 'ecdsa-sha2-nistp384' })
	@params({ pkAlg: 'rsa-sha2-256', keySize: 2048 })
	@params({ pkAlg: 'rsa-sha2-512', keySize: 2048 })
	@params.naming((p) => `authenticateClientWithPublicKeyInvalidSignature(${p.pkAlg})`)
	public async authenticateClientWithPublicKeyInvalidSignature({
		pkAlg,
		keySize,
	}: {
		pkAlg: string;
		keySize?: number;
	}) {
		const alg = Object.values(SshAlgorithms.publicKey).find((a) => a?.name === pkAlg)!;
		const presentedKey = await alg.generateKeyPair(keySize);
		const signingKey = await alg.generateKeyPair(keySize);

		const [clientSession, serverSession] = await this.createSessions();

		const authenticationTypes: SshAuthenticationType[] = [];
		serverSession.onAuthenticating((e) => {
			authenticationTypes.push(e.authenticationType);

			// Approve anything that reaches the application callback, so that the assertions
			// below fail if the callback is reached for a request with an invalid signature.
			e.authenticationPromise = Promise.resolve({});
		});

		let serverRaisedClientAuthenticated = false;
		serverSession.onClientAuthenticated(() => {
			serverRaisedClientAuthenticated = true;
		});

		clientSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const presentedPublicKey = (await presentedKey.getPublicKeyBytes(alg.name))!;

		// The request presents one public key, but the signature over the transcript that the
		// server verifies is produced with a different key.
		const request = new PublicKeyRequestMessage();
		request.serviceName = 'ssh-connection';
		request.username = SessionTests.testUsername;
		request.keyAlgorithmName = alg.name;
		request.publicKey = presentedPublicKey;
		request.signature = await SessionTests.createMismatchedSignature(
			alg,
			signingKey,
			clientSession.sessionId!,
			SessionTests.testUsername,
			presentedPublicKey,
		);

		const serviceRequestMessage = new ServiceRequestMessage();
		serviceRequestMessage.serviceName = 'ssh-userauth';
		await clientSession.sendMessage(serviceRequestMessage);
		await clientSession.sendMessage(request);

		// Allow ample time for the server to process the request before asserting that it
		// did not authenticate the session.
		for (let i = 0; i < 100 && !serverSession.principal; i++) {
			await new Promise((resolve) => setTimeout(resolve, 20));
		}

		assert(!serverSession.principal, 'Server must not assign a principal.');
		assert(!serverRaisedClientAuthenticated, 'Server must not raise ClientAuthenticated.');
		assert(
			!authenticationTypes.includes(SshAuthenticationType.clientPublicKey),
			'Server must not raise the clientPublicKey authentication event.',
		);
		assert.strictEqual(authenticationTypes.length, 0);
	}

	/**
	 * Verifies that a host-based authentication request with a signature that does not match
	 * the presented host public key never reaches the application's `Authenticating` event
	 * handler, and never results in an authenticated session. (RFC 4252 Section 9)
	 */
	@test
	public async authenticateClientHostBasedInvalidSignature() {
		const alg = SshAlgorithms.publicKey.ecdsaSha2Nistp384!;
		const presentedHostKey = await alg.generateKeyPair();
		const signingKey = await alg.generateKeyPair();

		const [clientSession, serverSession] = await this.createSessions();

		// Host-based authentication is opt-in; enable it on the server for this test.
		serverSession.config.authenticationMethods.push(AuthenticationMethod.hostBased);

		const authenticationTypes: SshAuthenticationType[] = [];
		serverSession.onAuthenticating((e) => {
			authenticationTypes.push(e.authenticationType);
			e.authenticationPromise = Promise.resolve({});
		});

		let serverRaisedClientAuthenticated = false;
		serverSession.onClientAuthenticated(() => {
			serverRaisedClientAuthenticated = true;
		});

		clientSession.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const presentedPublicKey = (await presentedHostKey.getPublicKeyBytes(alg.name))!;
		const clientHostname = 'client-host.example.com';
		const clientUsername = SessionTests.testUsername;

		const sessionId = clientSession.sessionId!;
		const writer = new SshDataWriter(
			Buffer.alloc(sessionId.length + presentedPublicKey.length + 256),
		);
		writer.writeBinary(sessionId);
		writer.writeByte(50); // SSH_MSG_USERAUTH_REQUEST
		writer.writeString(clientUsername, 'utf8');
		writer.writeString('ssh-connection', 'ascii');
		writer.writeString(AuthenticationMethod.hostBased, 'ascii');
		writer.writeString(alg.name, 'ascii');
		writer.writeBinary(presentedPublicKey);
		writer.writeString(clientHostname, 'ascii');
		writer.writeString(clientUsername, 'ascii');

		// Sign the transcript with a key that does not match the presented host public key.
		const signer = alg.createSigner(signingKey);
		const rawSignature = await signer.sign(writer.toBuffer());

		const request = new PublicKeyRequestMessage();
		request.serviceName = 'ssh-connection';
		request.username = clientUsername;
		request.methodName = AuthenticationMethod.hostBased;
		request.keyAlgorithmName = alg.name;
		request.publicKey = presentedPublicKey;
		request.clientHostname = clientHostname;
		request.clientUsername = clientUsername;
		request.signature = alg.createSignatureData(rawSignature);

		const serviceRequestMessage = new ServiceRequestMessage();
		serviceRequestMessage.serviceName = 'ssh-userauth';
		await clientSession.sendMessage(serviceRequestMessage);
		await clientSession.sendMessage(request);

		for (let i = 0; i < 100 && !serverSession.principal; i++) {
			await new Promise((resolve) => setTimeout(resolve, 20));
		}

		assert(!serverSession.principal, 'Server must not assign a principal.');
		assert(!serverRaisedClientAuthenticated, 'Server must not raise ClientAuthenticated.');
		assert(
			!authenticationTypes.includes(SshAuthenticationType.clientHostBased),
			'Server must not raise the clientHostBased authentication event.',
		);
		assert.strictEqual(authenticationTypes.length, 0);
	}

	/**
	 * Signs the public-key authentication transcript
	 * (sessionId || type || username || service || method || true || algorithm || publicKey)
	 * using a key that does NOT match the public key included in the transcript.
	 */
	private static async createMismatchedSignature(
		alg: PublicKeyAlgorithm,
		signingKey: KeyPair,
		sessionId: Buffer,
		username: string,
		claimedPublicKey: Buffer,
	): Promise<Buffer> {
		const writer = new SshDataWriter(Buffer.alloc(sessionId.length + claimedPublicKey.length + 128));
		writer.writeBinary(sessionId);
		writer.writeByte(50); // SSH_MSG_USERAUTH_REQUEST
		writer.writeString(username, 'utf8');
		writer.writeString('ssh-connection', 'ascii');
		writer.writeString(AuthenticationMethod.publicKey, 'ascii');
		writer.writeBoolean(true);
		writer.writeString(alg.name, 'ascii');
		writer.writeBinary(claimedPublicKey);

		const signer = alg.createSigner(signingKey);
		const signature = await signer.sign(writer.toBuffer());
		return alg.createSignatureData(signature);
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

	@test
	public async authenticateInteractive() {
		const [clientSession, serverSession] = await this.createSessions();

		serverSession.onAuthenticating((e) => {
			if (e.authenticationType !== SshAuthenticationType.clientInteractive) {
				e.authenticationPromise = Promise.resolve(null);
				return;
			} else if (!e.infoResponse) {
				e.infoRequest = new AuthenticationInfoRequestMessage();
				e.infoRequest.prompts = [
					{ prompt: 'One', echo: true },
					{ prompt: 'Two', echo: false },
				];
				e.authenticationPromise = Promise.resolve(null);
			} else {
				assert(e.infoResponse.responses);
				assert.equal(e.infoResponse.responses.length, 2);
				assert.strictEqual(e.infoResponse.responses[0], '1');
				assert.strictEqual(e.infoResponse.responses[1], '2');
				e.authenticationPromise = Promise.resolve({});
			}
		});
		clientSession.onAuthenticating((e) => {
			if (e.authenticationType === SshAuthenticationType.serverPublicKey) {
				e.authenticationPromise = Promise.resolve({});
			} else if (e.authenticationType === SshAuthenticationType.clientInteractive) {
				assert(e.infoRequest);
				assert.equal(e.infoRequest.prompts?.length, 2);
				assert.strictEqual(e.infoRequest.prompts![0].prompt, 'One');
				assert(e.infoRequest.prompts![0].echo);
				assert.strictEqual(e.infoRequest.prompts![1].prompt, 'Two');
				assert(!e.infoRequest.prompts![1].echo);
				e.infoResponse = new AuthenticationInfoResponseMessage();
				e.infoResponse.responses = ['1', '2'];
			}
		});

		await connectSessionPair(clientSession, serverSession, undefined, false);

		const authenticated = await clientSession.authenticate(
			{ username: SessionTests.testUsername });
		assert(authenticated);
	}

	@test
	public async overlappingSessionRequests() {
		const [clientSession, serverSession] = await this.createSessions();
		await connectSessionPair(clientSession, serverSession, undefined, true);

		const asyncResponse = async (delay: number, success: boolean): Promise<SshMessage> => {
			await new Promise((resolve) => setTimeout(resolve, delay));
			return success ? new SessionRequestSuccessMessage() : new SessionRequestFailureMessage();
		};

		serverSession.onRequest((e) => {
			// Use a longer delay for the first message, so it completes after the second one.
			var delay = 2 - parseInt(e.requestType);
			e.responsePromise = asyncResponse(delay, e.requestType !== '1');
		});

		const testRequest1 = new SessionRequestMessage('1', true);
		const testRequest2 = new SessionRequestMessage('2', true);
		const request1Promise = withTimeout(clientSession.request(testRequest1), 5000);
		const request2Promise = withTimeout(clientSession.request(testRequest2), 5000);

		assert(!(await request1Promise));
		assert(await request2Promise);
	}

	@test
	public async testKeepAliveOneMessage() {
		const [clientSession, serverSession] = await this.createSessions();

		try {
			// Configure keep-alive timeout on client
			clientSession.config.keepAliveTimeoutInSeconds = 1;

			// Track keep-alive success events
			let keepAliveCount = 0;
			clientSession.onKeepAliveSucceeded((count) => {
				keepAliveCount = count;
			});

			await connectSessionPair(clientSession, serverSession, undefined, true);

			// Wait for keep-alive to be sent
			await new Promise((resolve) => setTimeout(resolve, 1500));

			// Check that keep-alive success was triggered on client
			assert.strictEqual(keepAliveCount, 1, 'Should have one keep-alive success event');
		} finally {
			await clientSession.close(SshDisconnectReason.none);
			await serverSession.close(SshDisconnectReason.none);
		}
	}

	@test
	public async testNoKeepAliveWhenActive() {
		const [clientSession, serverSession] = await this.createSessions();

		try {
			// Configure keep-alive timeout on client
			clientSession.config.keepAliveTimeoutInSeconds = 1;

			// Track keep-alive failures (not requests)
			let keepAliveFailureCount = 0;
			clientSession.onKeepAliveFailed(() => {
				keepAliveFailureCount++;
			});

			await connectSessionPair(clientSession, serverSession, undefined, true);

			// Send NO-REPLY messages from SERVER to CLIENT frequently to keep client's timer reset
			// Since any received message resets keepAliveResponseReceived = true
			for (let i = 0; i < 3; i++) {
				const testRequest = new SessionRequestMessage();
				testRequest.requestType = 'test';
				testRequest.wantReply = false; // No reply needed, just incoming traffic to client

				await serverSession.request(testRequest); // Server sends to client
				await new Promise((resolve) => setTimeout(resolve, 900)); // Send every 900ms (less than 1s timeout)
			}

			// Wait for one more keep-alive cycle to complete
			await new Promise((resolve) => setTimeout(resolve, 1100));

			// With constant activity, keep-alives may still be sent but should not fail
			assert.strictEqual(
				keepAliveFailureCount,
				0,
				'Should not have any keep-alive failures when session is active',
			);
		} finally {
			await clientSession.close(SshDisconnectReason.none);
			await serverSession.close(SshDisconnectReason.none);
		}
	}

	@test
	public async testKeepAliveFailureEvent() {
		const [clientSession, serverSession] = await this.createSessions();

		try {
			// Configure keep-alive timeout on client
			clientSession.config.keepAliveTimeoutInSeconds = 1;

			// Track keep-alive failure events
			let keepAliveFailedCount = 0;
			clientSession.onKeepAliveFailed((count) => {
				keepAliveFailedCount = count;
			});

			await connectSessionPair(clientSession, serverSession, undefined, true);

			// Set up server to delay response to first request (simulating network delay/timeout)
			let isFirstRequest = true;
			serverSession.onRequest((e) => {
				if (e.requestType === 'first' && isFirstRequest) {
					isFirstRequest = false;
					// Delay response by 3.5 seconds to trigger multiple keep-alive failures
					e.responsePromise = new Promise((resolve) => {
						setTimeout(() => {
							resolve(new SessionRequestSuccessMessage());
						}, 3500);
					});
				} else {
					// Handle other requests normally (including keep-alive requests)
					e.responsePromise = Promise.resolve(new SessionRequestSuccessMessage());
				}
			});

			// Send the first request that will be delayed
			const firstRequest = new SessionRequestMessage();
			firstRequest.requestType = 'first';
			firstRequest.wantReply = true;

			await clientSession.request(firstRequest);

			// We should have at least 2 keep-alive failures (3.5s delay with 1s timeout)
			assert.ok(keepAliveFailedCount >= 2, `Expected at least 2 failures, got ${keepAliveFailedCount}`);
		} finally {
			await clientSession.close(SshDisconnectReason.none);
			await serverSession.close(SshDisconnectReason.none);
		}
	}
}
