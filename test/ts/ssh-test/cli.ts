//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

// Minimal command-line interface for the TS SSH library, for testing purposes.
// Compatible with some basic CLI options for `ssh` and `sshd`.

import * as fs from 'fs';
import * as os from 'os';
import * as http from 'http';
import * as yargs from 'yargs';
import { server as WebSocketServer, connection as WebSocket } from 'websocket';

import {
	SshAlgorithms,
	SshClientCredentials,
	SshSessionConfiguration,
	SshProtocolExtensionNames,
	CommandRequestMessage,
	PromiseCompletionSource,
	SshDisconnectReason,
	KeyPair,
	BaseStream,
	SshServerSession,
	CancellationToken,
	ObjectDisposedError,
	SshAuthenticationType,
	Trace,
	TraceLevel,
} from '@microsoft/dev-tunnels-ssh';
import {
	PortForwardingService,
	PortForwardRequestMessage,
	SshClient,
	SshServer,
} from '@microsoft/dev-tunnels-ssh-tcp';
import { importKey, importKeyFile, KeyEncoding, KeyFormat } from '@microsoft/dev-tunnels-ssh-keys';
import 'source-map-support/register';

let trace: Trace = (level, eventId, msg) => {};

main()
	.then((exitCode) => process.exit(exitCode))
	.catch((e) => {
		console.error(e);
		process.exit(1);
	});

function usage(errorMessage?: string) {
	if (errorMessage) {
		console.error(errorMessage);
		console.error('');
	}
	console.error(
		'Usage: ssh -p <port> ' +
			'-l <username> ' +
			'[-o IdentityFile=<keyFile>] ' +
			'[-o UserKnownHostsFile=<hostsFile>] ' +
			'<host> [command]',
	);
	console.error('Usage: sshd -p <port> [-w] [-o HostKey=<keyFile>]');
	return 2;
}

async function main() {
	const argv = await yargs.argv;
	const port = ((argv.p || argv.port) as number) || 0;

	let optionsArray = ((argv.o || argv.option) as string | string[]) || [];
	if (!Array.isArray(optionsArray)) {
		optionsArray = [optionsArray];
	}

	const options: { [name: string]: string } = {};
	for (let i = optionsArray.length - 1; i >= 0; i--) {
		const nameAndValue = optionsArray[i].split('=');
		if (nameAndValue.length === 2) {
			options[nameAndValue[0]] = nameAndValue[1];
		}
	}

	if (argv.v || (options['LogLevel'] ?? '').toUpperCase() == 'VERBOSE') {
		trace = (level, eventId, msg) => {
			if (level === TraceLevel.Error) console.error(msg);
			else if (level === TraceLevel.Warning) console.warn(msg);
			else console.log(msg);
		};
	}

	const tool = argv._[0] as string;
	const host = argv._[1] as string;
	const command = (argv._[2] as string) || null;
	const username = (argv.l || argv.login || argv.username) as string;
	const sshOverWebsocket = !!argv.w;

	if (tool === 'ssh') return ssh(host, port, username, options, command);
	else if (tool === 'sshd') return sshd(port, options, sshOverWebsocket);
	else return usage();
}

async function ssh(
	host: string,
	port: number,
	username: string,
	options: { [name: string]: string },
	command: string | null,
) {
	if (!host) return usage('Specify a host.');
	if (!port) return usage('Specify a port.');
	if (!username) return usage('Specify a username.');

	const reconnect =
		options['Reconnect'] === '1' || (options['Reconnect'] || '').toLowerCase() === 'true';

	let identityString: string;
	const identityFile = options['IdentityFile'];
	if (identityFile) {
		identityString = fs.readFileSync(identityFile).toString();
	} else {
		identityString = (await import('./testKeys'))['private-rsa2048-pkcs1'].toString('utf8');
	}

	const identityKey = await importKey(identityString);

	let hostLines: string[];
	const hostsFile = options['UserKnownHostsFile'];
	if (hostsFile) {
		hostLines = fs
			.readFileSync(hostsFile)
			.toString()
			.split('\n');
	} else {
		const k = await identityKey.getPublicKeyBytes();
		hostLines = [`[${host}]:${port} ${identityKey.keyAlgorithmName} ${k!.toString('base64')}`];
	}
	if (!hostsFile) return usage('Specify a UserKnownHostsFile.');

	const hostMatch = hostLines.find((l) => l.startsWith(`[${host}]:${port} `));
	if (!hostMatch) {
		console.error(`${host}:${port} entry not found in UserKnownHostsFile.`);
		return;
	}

	const hostKeyParts = hostMatch.split(' ');
	const knownHostKey = hostKeyParts[2];

	const config = new SshSessionConfiguration();
	config.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.ecdhNistp521Sha512);
	config.publicKeyAlgorithms.push(SshAlgorithms.publicKey.ecdsaSha2Nistp521);
	config.encryptionAlgorithms.push(SshAlgorithms.encryption.aes256Gcm);
	if (reconnect) {
		config.protocolExtensions.push(SshProtocolExtensionNames.sessionReconnect);
		config.protocolExtensions.push(SshProtocolExtensionNames.sessionLatency);
	}

	const client = new SshClient(config);
	client.trace = trace;

	const session = await client.openSession(host, port);

	session.onAuthenticating((e) => {
		if (e.publicKey) {
			e.authenticationPromise = authenticateServer(e.publicKey, knownHostKey);
		}
	});

	const credentials: SshClientCredentials = { username, publicKeys: [identityKey] };
	const authenticated = await session.authenticate(credentials);
	if (!authenticated) {
		console.error('Authentication failed.');
		return;
	}

	const reconnectCompletion = new PromiseCompletionSource<void>();
	if (reconnect) {
		session.onDisconnected(() => {
			console.log('Disconnected. Attempting to reconnect...');
			client
				.reconnectSession(session, host, port)
				.then(() => {
					reconnectCompletion.resolve();
				})
				.catch((e: Error) => {
					console.error('Failed to reconnect: ' + e.message);
					reconnectCompletion.reject(e);
				});
		});
	}

	const channel = await session.openChannel();

	if (command) {
		const request = new CommandRequestMessage();
		request.command = command;
		request.wantReply = true;
		await channel.request(request);
	}

	if (reconnect) {
		console.log('Testing reconnection...');
		await session.close(SshDisconnectReason.connectionLost, 'Test disconnection.');
		await reconnectCompletion.promise;
		console.log('Reconnection succeeded.');
	}

	console.log('Done!');
	await new Promise((c) => setTimeout(c, 5000));
}

async function authenticateServer(
	serverPublicKey: KeyPair,
	knownHostKey: string,
): Promise<object | null> {
	const serverKeyBytes = await serverPublicKey.getPublicKeyBytes()!;
	const pkAlg = Object.values(SshAlgorithms.publicKey!).find(
		(a) => a?.keyAlgorithmName === serverPublicKey?.keyAlgorithmName,
	);
	if (!pkAlg) return null;
	const hostKey = pkAlg.createKeyPair();
	await hostKey.setPublicKeyBytes(Buffer.from(knownHostKey, 'base64'));
	const hostKeyBytes = await hostKey.getPublicKeyBytes();
	const result = serverKeyBytes!.equals(hostKeyBytes!) ? {} : null;
	console.log('Server authentication ' + (result ? 'succeeded.' : 'failed.'));
	return result;
}

async function sshd(port: number, options: { [name: string]: string }, sshOverWebsocket: boolean) {
	if (!port) return usage('Specify a port.');

	let hostKeys: KeyPair[] = [];
	const hostKeyFile = options['HostKey'];
	if (hostKeyFile) {
		const keyPair = await importKeyFile(hostKeyFile);
		hostKeys.push(keyPair);
	} else {
		const testKeys = await import('./testKeys');
		const hostKeyNames: (keyof typeof testKeys)[] = [
			'private-rsa2048-pkcs8',
			'private-ecdsa384-pkcs8',
			'private-ecdsa521-pkcs8',
		];
		for (let keyFile of hostKeyNames) {
			const keyPair = await importKey(testKeys[keyFile]?.toString('utf8'));
			hostKeys.push(keyPair);
		}
	}

	const authorizedKeys: KeyPair[] = [];
	const authorizedKeysFile = options['AuthorizedKeysFile'];
	if (authorizedKeysFile) {
		let authorizedKeysLines: string[] = fs
			.readFileSync(authorizedKeysFile)
			.toString()
			.split(/\r?\n/)
			.filter((line) => !!line);
		for (let line of authorizedKeysLines) {
			const publicKey = await importKey(line);
			authorizedKeys.push(publicKey);
		}
	}

	const config = new SshSessionConfiguration();
	config.keyExchangeAlgorithms.push(SshAlgorithms.keyExchange.ecdhNistp521Sha512);
	config.publicKeyAlgorithms.push(SshAlgorithms.publicKey.ecdsaSha2Nistp521);
	config.encryptionAlgorithms.splice(0, 0, SshAlgorithms.encryption.aes256Gcm);
	config.protocolExtensions.push(SshProtocolExtensionNames.sessionReconnect);
	config.protocolExtensions.push(SshProtocolExtensionNames.sessionLatency);
	config.addService(PortForwardingService);

	if (sshOverWebsocket) {
		await sshWebsocketServer(port, config, hostKeys);
		return 0;
	}

	const server = new SshServer(config);
	server.trace = trace;

	server.credentials.publicKeys = hostKeys;
	server.onSessionOpened((session) => {
		session.onAuthenticating((e) => {
			if (e.authenticationType === SshAuthenticationType.clientPublicKey && e.publicKey) {
				e.authenticationPromise = authenticateClient(e.username!, e.publicKey, authorizedKeys);
			}
		});
		session.onRequest((e) => {
			// Always approve port-forward requests.
			if (e.request instanceof PortForwardRequestMessage) {
				e.isAuthorized = !!e.principal;
			}
		});
	});

	await server.acceptSessions(port);
	console.log(`Listening on port ${port}`);
	await new Promise((c) => setTimeout(c, 999999999));
	return 0;
}

async function authenticateClient(
	clientUsername: string,
	clientPublicKey: KeyPair,
	authorizedKeys: KeyPair[],
): Promise<object | null> {
	const clientKeyBytes = await clientPublicKey.getPublicKeyBytes()!;
	let result = null;
	if (clientUsername === os.userInfo().username) {
		for (let authorizedKey of authorizedKeys) {
			const authorizedKeyBytes = await authorizedKey.getPublicKeyBytes();
			if (clientKeyBytes!.equals(authorizedKeyBytes!)) {
				result = {};
				break;
			}
		}
	}
	console.log('Client authentication ' + (result ? 'succeeded.' : 'failed.'));
	return result;
}

async function sshWebsocketServer(
	port: number,
	config: SshSessionConfiguration,
	hostKeys: KeyPair[],
) {
	const server = http.createServer((request, response) => {
		response.writeHead(404);
		response.end();
	});
	server.listen(port, () => {
		console.log(`WebSocket server listening on port ${port}`);
	});

	const wsServer = new WebSocketServer({
		httpServer: server,
		autoAcceptConnections: false,
	});

	const reconnectableSessions: SshServerSession[] = [];

	wsServer.on('request', (request) => {
		var webSocket: WebSocket = request.accept('ssh');
		console.log('Accepted WebSocket connection.');
		const stream = new WebSocketServerStream(webSocket);
		const session = new SshServerSession(config, reconnectableSessions);
		session.credentials.publicKeys = hostKeys;
		session.onAuthenticating((e) => {
			e.authenticationPromise = Promise.resolve({});
		});
		session.onRequest((e) => {
			// Always approve port-forward requests.
			if (e.request instanceof PortForwardRequestMessage) {
				e.isAuthorized = !!e.principal;
			}
		});
		session
			.connect(stream)
			.then(() => console.log('Connected SSH session.'))
			.catch((e) => console.log('Failed to connect SSH session: ' + e.message));
	});
	await new Promise((c) => setTimeout(c, 999999999));
}

class WebSocketServerStream extends BaseStream {
	public constructor(private readonly websocket: WebSocket) {
		super();
		if (!websocket) throw new TypeError('WebSocket is required.');

		if (
			typeof (websocket as any).binaryType === 'string' &&
			(websocket as any).binaryType !== 'arraybuffer'
		) {
			throw new Error('WebSocket must use arraybuffer binary type.');
		}

		websocket.on('message', (data) => {
			if (data.type === 'binary') {
				this.onData(data.binaryData);
			}
		});
		websocket.on('close', (code?: number, reason?: string) => {
			if (typeof code === undefined || !code) {
				this.onEnd();
			} else {
				const error = new Error(reason);
				(<any>error).code = code;
				this.onError(error);
			}
		});
	}

	public async write(data: Buffer, cancellation?: CancellationToken): Promise<void> {
		if (!data) throw new TypeError('Data is required.');
		if (this.disposed) throw new ObjectDisposedError(this);

		this.websocket.send(data);
	}

	public async close(error?: Error, cancellation?: CancellationToken): Promise<void> {
		if (this.disposed) throw new ObjectDisposedError(this);

		if (!error) {
			this.websocket.close();
		} else {
			const code = typeof (<any>error).code === 'number' ? (<any>error).code : undefined;
			this.websocket.drop(code, error.message);
		}
		this.disposed = true;
		this.closedEmitter.fire({ error });
		this.onError(error || new Error('Stream closed.'));
	}

	public dispose(): void {
		if (!this.disposed) {
			this.websocket.close();
		}

		super.dispose();
	}
}
