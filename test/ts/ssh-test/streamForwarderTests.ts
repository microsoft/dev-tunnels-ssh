//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout } from '@testdeck/mocha';
import { Duplex } from 'stream';

import { Trace } from '@microsoft/dev-tunnels-ssh';
import { StreamForwarder } from '@microsoft/dev-tunnels-ssh-tcp';

const timeoutMs = 3000;

/**
 * A minimal Duplex stream that captures written data and allows pushing readable data.
 * Does not echo writes back to the readable side (unlike PassThrough), making it safe
 * for use in bidirectional pipe scenarios without creating infinite loops.
 */
class MockDuplex extends Duplex {
	public readonly written: Buffer[] = [];

	constructor() {
		super();
	}

	_write(chunk: Buffer, _encoding: string, callback: (error?: Error | null) => void): void {
		this.written.push(Buffer.from(chunk));
		callback();
	}

	_read(_size: number): void {
		// No-op; data is pushed externally via this.push()
	}

	pushData(data: Buffer): void {
		this.push(data);
	}
}

/**
 * A Duplex that emits 'error' on nextTick after pipe() is called,
 * simulating the synchronous-dispose race in StreamForwarder construction.
 */
class ErrorOnPipeDuplex extends MockDuplex {
	private readonly pipeError: Error;

	constructor(error: Error) {
		super();
		this.pipeError = error;
	}

	pipe<T extends NodeJS.WritableStream>(destination: T): T {
		const result = super.pipe(destination);
		process.nextTick(() => this.emit('error', this.pipeError));
		return result;
	}
}

function createTrace(): Trace {
	return () => {};
}

@suite
@slow(2000)
@timeout(timeoutMs * 2)
export class StreamForwarderTests {
	@test
	public async forwardDataLocalToRemote() {
		const local = new MockDuplex();
		const remote = new MockDuplex();
		const forwarder = new StreamForwarder(local, remote, createTrace());

		// Push data into local's readable side; it should be piped to remote's writable side.
		local.pushData(Buffer.from('hello'));

		await new Promise((r) => setImmediate(r));
		assert.strictEqual(Buffer.concat(remote.written).toString(), 'hello');

		forwarder.dispose();
		local.destroy();
		remote.destroy();
	}

	@test
	public async forwardDataRemoteToLocal() {
		const local = new MockDuplex();
		const remote = new MockDuplex();
		const forwarder = new StreamForwarder(local, remote, createTrace());

		// Push data into remote's readable side; it should be piped to local's writable side.
		remote.pushData(Buffer.from('world'));

		await new Promise((r) => setImmediate(r));
		assert.strictEqual(Buffer.concat(local.written).toString(), 'world');

		forwarder.dispose();
		local.destroy();
		remote.destroy();
	}

	@test
	public async localStreamErrorDisposesForwarder() {
		const local = new MockDuplex();
		const remote = new MockDuplex();
		let disposedCalled = false;
		const forwarder = new StreamForwarder(local, remote, createTrace(), () => {
			disposedCalled = true;
		});

		local.emit('error', new Error('connection reset'));

		await new Promise((r) => setImmediate(r));
		assert.strictEqual(forwarder.isDisposed, true);
		assert.strictEqual(disposedCalled, true);
		local.destroy();
		remote.destroy();
	}

	@test
	public async remoteStreamErrorDisposesForwarder() {
		const local = new MockDuplex();
		const remote = new MockDuplex();
		let disposedCalled = false;
		const forwarder = new StreamForwarder(local, remote, createTrace(), () => {
			disposedCalled = true;
		});

		remote.emit('error', new Error('channel closed'));

		await new Promise((r) => setImmediate(r));
		assert.strictEqual(forwarder.isDisposed, true);
		assert.strictEqual(disposedCalled, true);
		local.destroy();
		remote.destroy();
	}

	@test
	public async onDisposedCallbackInvokedOnDispose() {
		const local = new MockDuplex();
		const remote = new MockDuplex();
		let callbackForwarder: StreamForwarder | null = null;
		const forwarder = new StreamForwarder(local, remote, createTrace(), (f: StreamForwarder) => {
			callbackForwarder = f;
		});

		forwarder.dispose();
		assert.strictEqual(callbackForwarder, forwarder);
		local.destroy();
		remote.destroy();
	}

	@test
	public async disposeIsIdempotent() {
		const local = new MockDuplex();
		const remote = new MockDuplex();
		let disposeCount = 0;
		const forwarder = new StreamForwarder(local, remote, createTrace(), () => {
			disposeCount++;
		});

		forwarder.dispose();
		forwarder.dispose();
		forwarder.dispose();
		assert.strictEqual(disposeCount, 1);
		local.destroy();
		remote.destroy();
	}

	@test
	public async synchronousErrorDuringPipeMarksDisposed() {
		const errorStream = new ErrorOnPipeDuplex(new Error('immediate failure'));
		const remote = new MockDuplex();
		const forwarder = new StreamForwarder(errorStream, remote, createTrace());

		// The error fires on nextTick, so wait a tick.
		await new Promise((r) => setImmediate(r));
		assert.strictEqual(forwarder.isDisposed, true);
		errorStream.destroy();
		remote.destroy();
	}

	@test
	public async forwarderRemovedFromSetOnDispose() {
		const local = new MockDuplex();
		const remote = new MockDuplex();
		const set = new Set<StreamForwarder>();
		const forwarder = new StreamForwarder(local, remote, createTrace(), (f: StreamForwarder) => {
			set.delete(f);
		});
		set.add(forwarder);

		forwarder.dispose();
		assert.strictEqual(set.size, 0);
		local.destroy();
		remote.destroy();
	}

	@test
	public async synchronousDisposeRaceDoesNotLeaveStaleEntry() {
		const errorStream = new ErrorOnPipeDuplex(new Error('race error'));
		const remote = new MockDuplex();
		const set = new Set<StreamForwarder>();
		const forwarder = new StreamForwarder(errorStream, remote, createTrace(), (f: StreamForwarder) => {
			set.delete(f);
		});

		// Caller adds after construction (the real code pattern).
		if (!forwarder.isDisposed) {
			set.add(forwarder);
		}

		// Wait for the error to fire and dispose to run.
		await new Promise((r) => setImmediate(r));
		assert.strictEqual(set.size, 0);
		assert.strictEqual(forwarder.isDisposed, true);
		errorStream.destroy();
		remote.destroy();
	}

	@test
	public async onDisposedCallbackErrorIsSwallowed() {
		const local = new MockDuplex();
		const remote = new MockDuplex();
		const forwarder = new StreamForwarder(local, remote, createTrace(), () => {
			throw new Error('callback error');
		});

		// Should not throw — the error is traced and swallowed.
		forwarder.dispose();
		assert.strictEqual(forwarder.isDisposed, true);
		local.destroy();
		remote.destroy();
	}
}
