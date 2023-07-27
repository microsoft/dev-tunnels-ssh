//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as net from 'net';
import { PromiseCompletionSource } from '@microsoft/dev-tunnels-ssh';

export async function getAvailablePort(): Promise<number> {
	const listener = await listenOnLocalPort(0);
	const localPort = (<net.AddressInfo>listener.address()).port;
	listener.close();
	return localPort;
}

export function listenOnLocalPort(port: number, localIPAddress?: string): Promise<net.Server> {
	const listener = net.createServer();
	const listenCompletion = new PromiseCompletionSource<net.Server>();
	listener.once('listening', () => {
		listenCompletion.resolve(listener);
	});
	listener.once('error', (e) => {
		listenCompletion.reject(e);
	});
	listener.listen({
		host: localIPAddress ?? '127.0.0.1',
		port,
		ipv6Only: localIPAddress?.startsWith('::'),
	});
	return listenCompletion.promise;
}

export function acceptSocketConnection(listener: net.Server): Promise<net.Socket> {
	const connectCompletion = new PromiseCompletionSource<net.Socket>();
	listener.once('connection', (socket) => {
		connectCompletion.resolve(socket);
	});
	listener.once('error', (e) => {
		connectCompletion.reject(e);
	});
	listener.once('close', () => {
		connectCompletion.reject(new Error('Listener closed.'));
	});
	return connectCompletion.promise;
}

export function connectSocket(host: string, port: number): Promise<net.Socket> {
	const connectCompletion = new PromiseCompletionSource<net.Socket>();
	const socket = net.createConnection({ host, port });
	socket.once('connect', () => {
		connectCompletion.resolve(socket);
	});
	socket.once('error', (e: Error) => {
		connectCompletion.reject(e);
	});
	return connectCompletion.promise;
}

export function readSocket(socket: net.Socket): Promise<Buffer> {
	const readCompletion = new PromiseCompletionSource<Buffer>();
	if (socket.destroyed) {
		const error = new Error('Socket closed before write.');
		(<any>error).code = 'ERR_SOCKET_CLOSED';
		readCompletion.reject(error);
	}
	socket.once('data', (data: Buffer) => {
		readCompletion.resolve(data);
	});
	socket.once('error', (e) => {
		readCompletion.reject(e);
	});
	socket.once('close', (hadError: boolean) => {
		if (hadError) {
			readCompletion.reject(new Error('Socket closed with error.'));
		} else {
			readCompletion.resolve(Buffer.alloc(0));
		}
	});
	return readCompletion.promise;
}

export function writeSocket(socket: net.Socket, data: Buffer): Promise<void> {
	const writeCompletion = new PromiseCompletionSource<void>();
	if (socket.destroyed) {
		const error = new Error('Socket closed before write.');
		(<any>error).code = 'ERR_SOCKET_CLOSED';
		writeCompletion.reject(error);
	}
	socket.write(data, (e?: Error) => {
		if (e) {
			writeCompletion.reject(e);
		} else {
			writeCompletion.resolve();
		}
	});
	return writeCompletion.promise;
}

export function endSocket(socket: net.Socket): Promise<void> {
	const endCompletion = new PromiseCompletionSource<void>();
	socket.end(() => endCompletion.resolve());
	return endCompletion.promise;
}
