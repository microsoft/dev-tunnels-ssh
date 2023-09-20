//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import * as childProcess from 'child_process';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import * as util from 'util';
import { suite, test, params, pending, slow, timeout } from '@testdeck/mocha';

import {
	SshAuthenticatingEventArgs,
	SshAlgorithms,
	KeyPair,
	PromiseCompletionSource,
	ChannelRequestType,
	CommandRequestMessage,
	SshAuthenticationType,
	SshClientSession,
} from '@microsoft/dev-tunnels-ssh';
import { PortForwardingService, SshClient, SshServer } from '@microsoft/dev-tunnels-ssh-tcp';
import {
	KeyFormat,
	exportPublicKeyFile,
	exportPrivateKeyFile,
} from '@microsoft/dev-tunnels-ssh-keys';

import { trace } from './trace';
import { createConfig } from './config';
import {
	acceptSocketConnection,
	connectSocket,
	getAvailablePort,
	listenOnLocalPort,
	readSocket,
	writeSocket,
} from './tcpUtils';
import { until, withTimeout } from './promiseUtils';

const asyncFs = {
	writeFile: util.promisify(fs.writeFile),
	unlink: util.promisify(fs.unlink),
};

@suite
export class InteropTests {
	private static readonly sshExe = InteropTests.findSshExePath('ssh');
	private static readonly sshdExe = InteropTests.findSshExePath('sshd');

	private static readonly rsa = SshAlgorithms.publicKey.rsaWithSha512!;
	private static serverRsaKey: KeyPair;
	private static clientRsaKey: KeyPair;

	private static readonly testUsername = 'testuser';
	private static readonly testCommand = 'testcommand';

	@slow(5000)
	@timeout(10000)
	public static async before() {
		InteropTests.serverRsaKey = await InteropTests.rsa.generateKeyPair();
		InteropTests.clientRsaKey = await InteropTests.rsa.generateKeyPair();
	}

	/**
	 * Starts an ssh server using the library, then launches an external ssh client
	 * and validates that the client can connect, encrypt and authenticate the session,
	 * and send a command.
	 *
	 * This test case will be skipped on Windows if ssh.exe is not found.
	 */
	@test(slow(3000), timeout(10000))
	@params({
		kexAlg: 'diffie-hellman-group14-sha256',
		pkAlg: 'rsa-sha2-512',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'diffie-hellman-group16-sha512',
		pkAlg: 'rsa-sha2-512',
		hmacAlg: 'hmac-sha2-512-etm@openssh.com',
	})
	@params({
		kexAlg: 'diffie-hellman-group14-sha256',
		pkAlg: 'ecdsa-sha2-nistp384',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'diffie-hellman-group14-sha256',
		pkAlg: 'ecdsa-sha2-nistp521',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'ecdh-sha2-nistp384',
		pkAlg: 'ecdsa-sha2-nistp384',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'ecdh-sha2-nistp521',
		pkAlg: 'ecdsa-sha2-nistp521',
		hmacAlg: 'hmac-sha2-512-etm@openssh.com',
	})
	@params.naming((p) => `interopWithSshClient(${p.kexAlg},${p.pkAlg},${p.hmacAlg})`)
	@pending(!InteropTests.sshExe)
	public async interopWithSshClient({
		kexAlg,
		pkAlg,
		hmacAlg,
	}: {
		kexAlg: string;
		pkAlg: string;
		hmacAlg: string;
	}) {
		const config = createConfig(kexAlg, pkAlg, hmacAlg);
		var server = new SshServer(config);

		var clientKey = pkAlg.startsWith('rsa-')
			? InteropTests.clientRsaKey
			: await config.publicKeyAlgorithms
					.find((a) => a?.keyAlgorithmName === pkAlg)!
					.generateKeyPair();
		var serverKey = pkAlg.startsWith('rsa-')
			? InteropTests.serverRsaKey
			: await config.publicKeyAlgorithms
					.find((a) => a?.keyAlgorithmName === pkAlg)!
					.generateKeyPair();
		server.credentials.publicKeys = [serverKey];

		let serverError: Error | undefined;
		server.onError((err) => {
			serverError = err;
		});
		const testPort = await getAvailablePort();
		const serverPromise = server.acceptSessions(testPort);

		const clientKeyFile = await InteropTests.createTempFile();
		const knownHostsFile = await InteropTests.createTempFile();

		let clientProcess: childProcess.ChildProcess | undefined = undefined;
		let processOutput = '';
		try {
			const authenticateCompletion = new PromiseCompletionSource<boolean>();
			const requestCompletion = new PromiseCompletionSource<CommandRequestMessage>();
			server.onSessionOpened((session) => {
				session.onAuthenticating((e) => {
					if (e.authenticationType !== SshAuthenticationType.clientPublicKey) {
						return;
					}

					e.authenticationPromise = new Promise(async (resolve, reject) => {
						try {
							const clientPublicKey = e.publicKey && (await e.publicKey.getPublicKeyBytes());
							const knownPublicKeyBytes = (await clientKey.getPublicKeyBytes())!;
							if (clientPublicKey?.equals(knownPublicKeyBytes)) {
								authenticateCompletion.resolve(true);
								resolve({});
							} else {
								authenticateCompletion.resolve(false);
								resolve(null);
							}
						} catch (e) {
							if (!(e instanceof Error)) throw e;
							authenticateCompletion.reject(e);
							reject(e);
						}
					});
				});

				session.onChannelOpening((ce) => {
					ce.channel.onRequest((e) => {
						if (e.requestType == ChannelRequestType.command) {
							const request = e.request.convertTo(new CommandRequestMessage());
							requestCompletion.resolve(request);
							e.isAuthorized = true;
						}
					});
				});

				session.onClosed((e) => {
					authenticateCompletion.reject(e.error ?? new Error('Session closed.'));
					requestCompletion.reject(e.error ?? new Error('Session closed.'));
				});
			});

			await exportPrivateKeyFile(
				clientKey,
				null,
				clientKeyFile,
				pkAlg.startsWith('rsa-') ? KeyFormat.Pkcs1 : KeyFormat.Sec1,
			);

			const keyAlg = serverKey.keyAlgorithmName;
			const serverPublicKey = (await serverKey.getPublicKeyBytes())!;
			await asyncFs.writeFile(
				knownHostsFile,
				`[localhost]:${testPort} ${keyAlg} ${serverPublicKey.toString('base64')}\n`,
			);

			const args = [
				'-v',
				'-o',
				'IdentityFile=' + clientKeyFile,
				'-o',
				'UserKnownHostsFile=' + knownHostsFile,
				'-c',
				'aes256-ctr',
				'-p',
				testPort.toString(),
				'-l',
				InteropTests.testUsername,
				'localhost',
				InteropTests.testCommand,
			];
			trace(`${InteropTests.sshExe} ${args.join(' ')}`);

			clientProcess = childProcess.spawn(InteropTests.sshExe!, args);
			clientProcess.on('error', (e) => {
				processOutput += `Failed to start process: ${e.message}`;
			});
			clientProcess.on('exit', (code: number | null, signal: string | null) => {
				trace(`ssh process exited with ${signal ? 'signal ' + signal : 'code ' + code}`);
			});

			const dataReceivedHandler = (data: any) => {
				trace(data.toString().replace(/\r?\n$/, ''));
				processOutput += data.toString();
			};
			clientProcess.stdout!.on('data', dataReceivedHandler);
			clientProcess.stderr!.on('data', dataReceivedHandler);

			const authenticated = await authenticateCompletion.promise;
			assert(authenticated);

			const commandRequest = await requestCompletion.promise;
			assert(commandRequest);
			assert.equal(InteropTests.testCommand, commandRequest.command);
			assert(!serverError);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			throw new Error(e.message + `\nssh process output follows:\n${processOutput}`);
		} finally {
			if (clientProcess) {
				clientProcess.kill();
			}

			await InteropTests.deleteTempFile(clientKeyFile);
			await InteropTests.deleteTempFile(knownHostsFile);

			server.dispose();
			await serverPromise;
		}
	}

	/**
	 * Launches an external sshd server, then connects to it using the library and
	 * and validates that the client can connect, encrypt and authenticate the session.
	 *
	 * This test case will be skipped on Windows if sshd.exe is not found.
	 */
	@test(slow(3000), timeout(10000))
	@params({
		kexAlg: 'diffie-hellman-group14-sha256',
		pkAlg: 'rsa-sha2-512',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'diffie-hellman-group16-sha512',
		pkAlg: 'rsa-sha2-512',
		hmacAlg: 'hmac-sha2-512-etm@openssh.com',
	})
	@params({
		kexAlg: 'diffie-hellman-group14-sha256',
		pkAlg: 'ecdsa-sha2-nistp384',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'diffie-hellman-group14-sha256',
		pkAlg: 'ecdsa-sha2-nistp521',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'ecdh-sha2-nistp384',
		pkAlg: 'ecdsa-sha2-nistp384',
		hmacAlg: 'hmac-sha2-512',
	})
	@params({
		kexAlg: 'ecdh-sha2-nistp521',
		pkAlg: 'ecdsa-sha2-nistp521',
		hmacAlg: 'hmac-sha2-512-etm@openssh.com',
	})
	@params.naming((p) => `interopWithSshServer(${p.kexAlg},${p.pkAlg},${p.hmacAlg})`)
	@pending(!InteropTests.sshdExe)
	public async interopWithSshServer({
		kexAlg,
		pkAlg,
		hmacAlg,
	}: {
		kexAlg: string;
		pkAlg: string;
		hmacAlg: string;
	}) {
		const config = createConfig(kexAlg, pkAlg, hmacAlg);

		// Force an AES-GCM interop test, even if OpenSSH does not prefer that cipher.
		config.encryptionAlgorithms.splice(0, config.encryptionAlgorithms.length);
		config.encryptionAlgorithms.push(SshAlgorithms.encryption.aes256Gcm);

		config.addService(PortForwardingService);

		const client = new SshClient(config);

		var clientKey = pkAlg.startsWith('rsa-')
			? InteropTests.clientRsaKey
			: await config.publicKeyAlgorithms
					.find((a) => a?.keyAlgorithmName === pkAlg)!
					.generateKeyPair();
		var serverKey = pkAlg.startsWith('rsa-')
			? InteropTests.serverRsaKey
			: await config.publicKeyAlgorithms
					.find((a) => a?.keyAlgorithmName === pkAlg)!
					.generateKeyPair();

		const configFile = await InteropTests.createTempFile();
		const hostKeyFile = await InteropTests.createTempFile();
		const hostPublicKeyFile = hostKeyFile + '.pub';
		const pidFile = await InteropTests.createTempFile();
		const authorizedKeysFile = await InteropTests.createTempFile();

		await InteropTests.deleteTempFile(pidFile, 'pidFile');

		let serverProcess: childProcess.ChildProcess | undefined = undefined;
		let processOutput = '';
		try {
			await exportPublicKeyFile(serverKey, hostPublicKeyFile);
			await exportPrivateKeyFile(serverKey, null, hostKeyFile);
			await exportPublicKeyFile(clientKey, authorizedKeysFile);

			const testPort = await getAvailablePort();

			const args = [
				'-D', // Do not detach
				'-e', // Log to stderr
				'-o',
				'LogLevel=VERBOSE',
				'-p',
				testPort.toString(),
				'-f',
				configFile,
				'-o',
				'AuthorizedKeysFile=' + authorizedKeysFile,
				'-o',
				'StrictModes=no', // Do not check permissions on key file/dir
				'-o',
				'PidFile=' + pidFile,
				'-o',
				'HostKey=' + hostKeyFile,
			];
			trace(`${InteropTests.sshdExe} ${args.join(' ')}`);
			processOutput += `${InteropTests.sshdExe} ${args.join(' ')}\n`;

			const serverListeningCompletion = new PromiseCompletionSource<void>();
			serverProcess = childProcess.spawn(InteropTests.sshdExe!, args);
			serverProcess.on('error', (e) => {
				processOutput += `Failed to start process: ${e.message}`;
				serverListeningCompletion.reject(new Error('Server process failed to start.'));
			});
			serverProcess.on('exit', (code: number | null, signal: string | null) => {
				const status = signal ? 'signal ' + signal : 'code ' + code;
				trace(`sshd process exited with ${status}.`);
				serverListeningCompletion.reject(new Error(`Server process exited with ${status}.`));
			});

			const dataReceivedHandler = (data: any) => {
				trace(data.toString().replace(/\r?\n$/, ''));
				processOutput += data.toString();

				if (/Server listening/.test(data)) {
					serverListeningCompletion.resolve();
				}
			};
			serverProcess.stdout!.on('data', dataReceivedHandler);
			serverProcess.stderr!.on('data', dataReceivedHandler);

			// Wait until sshd is actually listening on the port.
			await withTimeout(serverListeningCompletion.promise, 2000);

			const session = await client.openSession('localhost', testPort);

			session.onAuthenticating((e: SshAuthenticatingEventArgs) => {
				if (e.authenticationType !== SshAuthenticationType.serverPublicKey) {
					return;
				}

				e.authenticationPromise = (async (): Promise<object | null> => {
					const authKeyBytes = e.publicKey && (await e.publicKey.getPublicKeyBytes());
					const serverKeyBytes = await serverKey.getPublicKeyBytes();

					if (authKeyBytes && serverKeyBytes && authKeyBytes.equals(serverKeyBytes)) {
						return {};
					} else {
						return null;
					}
				})();
			});

			const serverAuthenticated = await session.authenticateServer();
			assert(serverAuthenticated);
			const clientAuthenticated = await session.authenticateClient({
				username: os.userInfo().username,
				publicKeys: [clientKey],
			});
			assert(clientAuthenticated);

			await this.forwardPortToServer(session);
			await this.forwardPortFromServer(session);
		} catch (e) {
			if (!(e instanceof Error)) throw e;
			e.message += `\nsshd process output follows:\n${processOutput}`;
			throw e;
		} finally {
			if (serverProcess) {
				serverProcess.kill();
				try {
					const pid = fs.readFileSync(pidFile);
					require('process').kill(pid);
				} catch (e) {}
			}

			client.dispose();

			await InteropTests.deleteTempFile(configFile);
			await InteropTests.deleteTempFile(hostKeyFile);
			await InteropTests.deleteTempFile(hostPublicKeyFile);
			await InteropTests.deleteTempFile(pidFile);
		}
	}

	private async forwardPortToServer(session: SshClientSession): Promise<void> {
		const serverListener = await listenOnLocalPort(0);
		let serverConnection: net.Socket | undefined;
		let clientConnection: net.Socket | undefined;
		try {
			const serverPort = (<net.AddressInfo>serverListener.address()).port;

			const pfs = session.activateService(PortForwardingService);
			const forwarder = await pfs.forwardToRemotePort('127.0.0.1', 0, '127.0.0.1', serverPort);

			const acceptPromise = acceptSocketConnection(serverListener);
			clientConnection = await connectSocket(forwarder.localIPAddress, forwarder.localPort);
			serverConnection = await withTimeout(acceptPromise, 5000);

			const writeBuffer = Buffer.from('hello', 'utf8');
			await writeSocket(serverConnection, writeBuffer);
			await writeSocket(clientConnection, writeBuffer);

			const readBuffer1 = await readSocket(clientConnection);
			const readBuffer2 = await readSocket(serverConnection);

			assert(readBuffer1.equals(writeBuffer));
			assert(readBuffer2.equals(writeBuffer));
		} finally {
			clientConnection?.destroy();
			serverConnection?.destroy();
			serverListener.close();
		}
	}

	private async forwardPortFromServer(session: SshClientSession): Promise<void> {
		const clientListener = await listenOnLocalPort(0);
		let serverConnection: net.Socket | undefined;
		let clientConnection: net.Socket | undefined;
		try {
			const clientPort = (<net.AddressInfo>clientListener.address()).port;

			const pfs = session.activateService(PortForwardingService);
			const forwarder = await pfs.forwardFromRemotePort('127.0.0.1', 0, '127.0.0.1', clientPort);
			assert(forwarder);

			const acceptPromise = acceptSocketConnection(clientListener);

			await until(async () => {
				try {
					serverConnection = await connectSocket(
						forwarder!.remoteIPAddress,
						forwarder!.remotePort,
					);
					return true;
				} catch (e) {
					return false;
				}
			}, 5000);
			clientConnection = await withTimeout(acceptPromise, 5000);

			const writeBuffer = Buffer.from('hello', 'utf8');
			await writeSocket(serverConnection!, writeBuffer);
			await writeSocket(clientConnection, writeBuffer);

			const readBuffer1 = await readSocket(clientConnection);
			const readBuffer2 = await readSocket(serverConnection!);
			assert(readBuffer1.equals(writeBuffer));
			assert(readBuffer2.equals(writeBuffer));
		} finally {
			clientConnection?.destroy();
			serverConnection?.destroy();
			clientListener.close();
		}
	}

	private static async createTempFile(): Promise<string> {
		const tmp = await import('tmp');
		return await new Promise<string>((resolve, reject) => {
			tmp.file({ discardDescriptor: true }, (err, filePath) =>
				err ? reject(err) : resolve(filePath),
			);
		});
	}

	private static async deleteTempFile(filePath: string, name?: string): Promise<void> {
		try {
			await asyncFs.unlink(filePath);
		} catch (e) {
			if (name) {
				throw new Error(`Failed to delete '${name}' temp file at ${filePath}`);
			}
		}
	}

	private static findSshExePath(name: string): string | null {
		if (!process.platform) {
			// Browser environment.
			return null;
		} else if (
			process.platform === 'darwin' &&
			os.userInfo().username === 'buildagent' &&
			name === 'sshd'
		) {
			// On Mac build agents, sshd has an interaction with the keychain
			// that causes a keychain popup and brings the build agent offline.
			console.warn('    Skipping SSH server test on Mac build agent.');
			return null;
		} else if (process.platform !== 'win32') {
			const pathEnv = process.env.PATH ?? '';
			for (let dir of pathEnv.split(':').filter((d) => d)) {
				const dirAndName = path.join(dir, name);
				if (fs.existsSync(dirAndName)) {
					return dirAndName;
				}
			}

			console.warn(`    SSH executable not found: '${name}'`);
			return null;
		} else {
			// OpenSSH tools are not typically in %PATH% on Windows.
			// Look for them in common installation locations.
			const relativePath = `OpenSSH\\${name}.exe`;

			for (let searchDir of [
				`${process.env.WINDIR}\\SYSTEM32`,
				process.env.ProgramFiles,
				process.env['ProgramFiles(x86)'],
			]) {
				const sshPath = path.join(searchDir || '', relativePath);
				if (fs.existsSync(sshPath)) {
					return sshPath;
				}
			}

			console.warn(
				`    SSH executable not found: '${name}.exe'\n` +
					'    To run this test, install the OpenSSH optional Windows feature.',
			);
			return null;
		}
	}
}
