//
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

import * as assert from 'assert';
import { suite, test, slow, timeout, pending } from '@testdeck/mocha';
import { DuplexStream } from './duplexStream';

import {
	PromiseCompletionSource,
	MultiChannelStream,
	SshChannelOpeningEventArgs,
	SshChannel,
} from '@microsoft/dev-tunnels-ssh';

@suite
@slow(3000)
@timeout(20000)
export class MultiChannelStreamTests {
	@test
	public async singleChannelConnect() {
		const [serverStream, clientStream] = await DuplexStream.createStreams();

		var server = new MultiChannelStream(serverStream);
		var client = new MultiChannelStream(clientStream);

		var serverChannelPromise = server.acceptChannel();
		var clientChannel = await client.openChannel();
		var serverChannel = await serverChannelPromise;
		assert(serverChannel);
		assert(clientChannel);

		clientChannel.close();
		serverChannel.close();
	}

	@test
	public async singleChannelReadWrite() {
		const [serverStream, clientStream] = await DuplexStream.createStreams();

		var server = new MultiChannelStream(serverStream);
		var client = new MultiChannelStream(clientStream);

		var serverChannelPromise = server.acceptChannel();
		var clientChannel = await client.openChannel();
		var serverChannel = await serverChannelPromise;

		await this.sendDataOverChannel(serverChannel, clientChannel);

		clientChannel.close();
		serverChannel.close();
	}

	private async sendDataOverChannel(serverChannel: SshChannel, clientChannel: SshChannel) {
		assert(serverChannel);
		assert(clientChannel);

		const payloadString = 'Hello!';
		const payload = Buffer.from(payloadString, 'utf-8');
		const eom = new PromiseCompletionSource<Buffer>();
		serverChannel.onDataReceived((data) => {
			eom.resolve(data);
		});
		await clientChannel.send(payload);
		const receivedPayloadString = (await eom.promise).toString('utf-8');

		assert.equal(payloadString, receivedPayloadString);
	}

	@test
	public async disposeClosesTransportStream() {
		const [serverStream] = await DuplexStream.createStreams();
		const multiChannelStream = new MultiChannelStream(serverStream);
		assert(!multiChannelStream.isClosed);
		var closedEventFired = false;
		multiChannelStream.onClosed((e) => (closedEventFired = true));
		multiChannelStream.dispose();
		assert(serverStream.isDisposed);
		assert(multiChannelStream.isClosed);
		assert(closedEventFired);
	}

	@test
	public async closeClosesTransportStream() {
		const [serverStream] = await DuplexStream.createStreams();
		const multiChannelStream = new MultiChannelStream(serverStream);
		assert(!multiChannelStream.isClosed);
		var closedEventFired = false;
		multiChannelStream.onClosed((e) => (closedEventFired = true));
		await multiChannelStream.close();
		assert(serverStream.isDisposed);
		assert(multiChannelStream.isClosed);
		assert(closedEventFired);
	}

	@test
	public async openChannelEventFiresWhenChannelOpens() {
		const channelType = 'MyChannelType';

		var serverChannelOpeningEventFired = false;
		var serverChannelPromise: Promise<SshChannel> | undefined = undefined;
		var clientChannelOpeningEventFired = false;

		const [serverStream, clientStream] = await DuplexStream.createStreams();

		var server = new MultiChannelStream(serverStream);
		var client = new MultiChannelStream(clientStream);

		server.onChannelOpening(serverChannelOpening);
		client.onChannelOpening(clientChannelOpening);

		const serverPromise = server.connectAndRunUntilClosed();
		const clientPromise = client.connectAndRunUntilClosed();

		const clientChannel = await client.openChannel(channelType);
		assert(serverChannelPromise);
		assert(clientChannelOpeningEventFired);
		assert(serverChannelOpeningEventFired);

		const serverChannel = await serverChannelPromise!;
		await this.sendDataOverChannel(serverChannel, clientChannel);

		clientChannel.close();
		serverChannel.close();

		await client.close();
		await server.close();

		await Promise.all([clientPromise, serverPromise]);

		function serverChannelOpening(e: SshChannelOpeningEventArgs) {
			serverChannelOpeningEventFired = true;
			assert(e.isRemoteRequest);
			assert.equal(channelType, e.channel?.channelType);
			serverChannelPromise = server.acceptChannel(channelType);
		}

		function clientChannelOpening(e: SshChannelOpeningEventArgs) {
			clientChannelOpeningEventFired = true;
			assert(!e.isRemoteRequest);
			assert.equal(channelType, e.channel?.channelType);
		}
	}
}
