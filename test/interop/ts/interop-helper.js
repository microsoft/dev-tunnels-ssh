// Copyright (c) Microsoft Corporation. All rights reserved.
// Minimal SSH server/client helper for Go interop testing.
// Usage: node interop-helper.js <server|client> <port> <kex> <pk> <enc> <hmac>
//
// Requires: NODE_PATH set to <repo>/out/lib/node_modules
// Prerequisite: run "node build.js build-ts" from the repo root first.
//
// Protocol:
//   Server prints "LISTENING" when ready, "ECHOED <n>" when echoing data.
//   Client prints "AUTHENTICATED", "CHANNEL_OPEN", "ECHO_OK", "DONE".

'use strict';

const {
	SshSessionConfiguration,
	SshAlgorithms,
	SshAuthenticationType,
} = require('@microsoft/dev-tunnels-ssh');
const { SshClient, SshServer } = require('@microsoft/dev-tunnels-ssh-tcp');

const args = process.argv.slice(2);
if (args.length < 6) {
	console.error('Usage: interop-helper.js <server|client> <port> <kex> <pk> <enc> <hmac>');
	process.exit(1);
}

const [mode, portStr, kexName, pkName, encName, hmacName] = args;
const port = parseInt(portStr, 10);

function findAlgorithm(collection, name) {
	for (const alg of Object.values(collection)) {
		if (alg && alg.name === name) return alg;
	}
	throw new Error(`Algorithm '${name}' not found`);
}

function createConfig(kex, pk, enc, hmac) {
	const config = new SshSessionConfiguration();

	const kexAlg = findAlgorithm(SshAlgorithms.keyExchange, kex);
	const pkAlg = findAlgorithm(SshAlgorithms.publicKey, pk);
	const encAlg = findAlgorithm(SshAlgorithms.encryption, enc);
	const hmacAlg = findAlgorithm(SshAlgorithms.hmac, hmac);

	config.keyExchangeAlgorithms.splice(0, config.keyExchangeAlgorithms.length, kexAlg);
	config.publicKeyAlgorithms.splice(0, config.publicKeyAlgorithms.length, pkAlg);
	config.encryptionAlgorithms.splice(0, config.encryptionAlgorithms.length, encAlg);
	config.hmacAlgorithms.splice(0, config.hmacAlgorithms.length, hmacAlg);

	return config;
}

async function runServer(config, port) {
	const pkAlg = config.publicKeyAlgorithms[0];
	const hostKey = await pkAlg.generateKeyPair();

	const server = new SshServer(config);
	server.credentials.publicKeys = [hostKey];

	server.onSessionOpened((session) => {
		session.onAuthenticating((e) => {
			// Accept all authentication.
			e.authenticationPromise = Promise.resolve({});
		});

		session.onChannelOpening((e) => {
			const channel = e.channel;
			channel.onDataReceived((data) => {
				// Echo data back.
				channel.send(Buffer.from(data)).catch((err) => {
					console.error('Echo error:', err.message);
				});
				channel.adjustWindow(data.length);
				console.log('ECHOED ' + data.length);
			});
		});
	});

	await server.acceptSessions(port, '127.0.0.1');
	console.log('LISTENING');

	// Stay alive until killed.
	await new Promise((resolve) => {
		setTimeout(resolve, 30000);
	});
}

async function runClient(config, port) {
	const client = new SshClient(config);
	const session = await client.openSession('127.0.0.1', port);

	session.onAuthenticating((e) => {
		// Auto-approve server host key.
		e.authenticationPromise = Promise.resolve({});
	});

	const authenticated = await session.authenticate({ username: 'testuser' });
	if (!authenticated) {
		console.error('Authentication failed');
		process.exit(1);
	}

	console.log('AUTHENTICATED');

	const channel = await session.openChannel();
	console.log('CHANNEL_OPEN');

	// Send test data.
	const testData = Buffer.from('INTEROP_TEST_DATA');
	const echoPromise = new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error('Echo timeout')), 10000);
		channel.onDataReceived((data) => {
			clearTimeout(timer);
			channel.adjustWindow(data.length);
			resolve(Buffer.from(data));
		});
	});

	await channel.send(testData);

	// Wait for echo.
	const echoed = await echoPromise;
	if (echoed.toString() === 'INTEROP_TEST_DATA') {
		console.log('ECHO_OK');
	} else {
		console.error('Echo mismatch');
		process.exit(1);
	}

	await channel.close();
	session.dispose();
	console.log('DONE');
	process.exit(0);
}

async function main() {
	try {
		const config = createConfig(kexName, pkName, encName, hmacName);
		if (mode === 'server') {
			await runServer(config, port);
		} else if (mode === 'client') {
			await runClient(config, port);
		} else {
			console.error('Unknown mode:', mode);
			process.exit(1);
		}
	} catch (err) {
		console.error('ERROR:', err.message || err);
		process.exit(1);
	}
}

main();
